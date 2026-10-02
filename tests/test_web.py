"""Web API tests against an in-process fake API (no network)."""
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apitest.web import app as web

SPEC = {
    "openapi": "3.0.1", "info": {"title": "Fake", "version": "1"},
    "servers": [{"url": "http://fake.test"}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/a": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/b": {"get": {"security": [{"b": []}], "responses": {"200": {"description": "ok"}}}},
        "/slow": {"get": {"responses": {"200": {"description": "ok"}}}},
    },
}


def fake_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/openapi.json":
        return httpx.Response(200, json=SPEC)
    if request.url.path.startswith("/slow"):
        time.sleep(0.3)
    return httpx.Response(200, json={}, headers={"x-content-type-options": "nosniff"})


@pytest.fixture
def client(tmp_path, monkeypatch):
    real = httpx.Client
    def fake_client(*a, **kw):
        kw["transport"] = httpx.MockTransport(fake_handler)
        return real(*a, **kw)
    monkeypatch.setattr(httpx, "Client", fake_client)
    web.configure(tmp_path)
    web._runs.clear(); web._cancels.clear(); web._secrets.clear()
    return TestClient(web.app)


def _create(client, **extra):
    body = {"name": "Fake API", "spec": "http://fake.test/openapi.json", "stages": ["authz"],
            "headers": "Authorization: Bearer literal-secret\nX-Env: ${APITEST_TEST_VAR}"} | extra
    r = client.post("/api/projects", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _wait(client, rid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/runs/{rid}").json()
        if r["status"] not in ("running", "stopping"):
            return r
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_discover_finds_spec_from_root(client):
    res = client.post("/api/discover", json={"url": "http://fake.test"}).json()
    assert [s["url"] for s in res["specs"]] == ["http://fake.test/openapi.json"]
    assert {o["label"] for o in res["specs"][0]["ops"]} == {"GET /a", "GET /b", "GET /slow"}


def test_project_crud_and_secret_handling(client, tmp_path, monkeypatch):
    monkeypatch.setenv("APITEST_TEST_VAR", "from-env")
    pid = _create(client)
    saved = (tmp_path / "projects" / f"{pid}.json").read_text()
    assert "literal-secret" not in saved and "${APITEST_TEST_VAR}" in saved  # literal token never on disk
    p = client.get(f"/api/projects/{pid}").json()
    assert "literal-secret" in p["headers"] and len(p["operations"]) == 3
    assert [x["id"] for x in client.get("/api/projects").json()] == [pid]
    yaml_text = client.get(f"/api/projects/{pid}/yaml").text
    assert "<set me>" in yaml_text and "literal-secret" not in yaml_text
    assert client.delete(f"/api/projects/{pid}").status_code == 200
    assert client.get("/api/projects").json() == []


def test_run_selected_operations_and_per_api_status(client, monkeypatch):
    monkeypatch.setenv("APITEST_TEST_VAR", "x")
    pid = _create(client)
    rid = client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /b"]}).json()["id"]
    run = _wait(client, rid)
    assert run["status"] == "done" and run["tested"] == ["GET /b"]
    crit = [f for s in run["report"]["stages"] for f in s["findings"] if f["severity"] == "critical"]
    assert crit and all(f["operation"] == "GET /b" for f in crit)  # /b is "secured" but serves anyone
    st = client.get(f"/api/projects/{pid}").json()["op_status"]
    assert st["GET /b"]["max"] == "critical" and "GET /a" not in st
    assert client.post(f"/api/projects/{pid}/runs", json={"operations": ["GET /nope"]}).status_code == 400


def test_missing_env_var_is_a_clear_error(client, monkeypatch):
    monkeypatch.setenv("APITEST_TEST_VAR", "x")
    pid = _create(client)
    monkeypatch.delenv("APITEST_TEST_VAR")
    r = client.post(f"/api/projects/{pid}/runs", json={})
    assert r.status_code == 400 and "APITEST_TEST_VAR" in r.text


def test_stop_cancels_run(client, monkeypatch):
    monkeypatch.setenv("APITEST_TEST_VAR", "x")
    # many slow operations so the run is still going when we stop it
    SPEC["paths"].update({f"/slow{i}": {"get": {"responses": {"200": {"description": "ok"}}}} for i in range(40)})
    try:
        pid = _create(client, stages=["authz", "types"])
        rid = client.post(f"/api/projects/{pid}/runs", json={}).json()["id"]
        assert client.post(f"/api/projects/{pid}/runs", json={}).status_code == 409  # one at a time
        time.sleep(0.5)
        assert client.post(f"/api/runs/{rid}/cancel").status_code == 200
        run = _wait(client, rid)
        assert run["status"] == "cancelled"
        assert run["stages"]["authz"]["status"] == "cancelled"
        assert run["stages"]["types"]["status"] == "cancelled"
        assert client.post(f"/api/runs/{rid}/cancel").status_code == 409
    finally:
        for i in range(40):
            SPEC["paths"].pop(f"/slow{i}", None)
