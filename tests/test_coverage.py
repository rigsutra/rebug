import json

from apitest import coverage
from apitest.spec import Operation
from apitest.testlog import TestLog


def _ops():
    return [
        Operation("get", "/sites", True, False, query_params={}, params=[{"name": "siteId", "in": "query"}]),
        Operation("post", "/ingress", True, True, op={"requestBody": {}}),
        Operation("get", "/health", False, False),
        Operation("post", "/recalc", True, True),
    ]


def _log(tmp_path, entries):
    tl = TestLog(tmp_path / "test-log.ndjson")
    for stage, op, scen, verdict, status in entries:
        tl.add(stage, scen, operation=op, verdict=verdict, explanation=f"{scen} -> {status}",
               request={"method": op.split()[0], "url": "http://x" + op.split()[1]}, response={"status": status})
    return tmp_path / "test-log.ndjson"


def test_no_token_is_called_out_per_api_and_for_the_run(tmp_path):
    log = _log(tmp_path, [("conformance", "GET /sites", "Edge cases: x", "pass", 401)] * 20 +
                         [("types", "POST /ingress", "Valid request first (every field the correct type)", "error", 401)])
    cov = coverage.build(_ops(), {"stages": ["conformance", "types", "authz"], "headers": {}, "headers_b": {},
                                  "bola": [], "exclude_paths": ["^/recalc$"]},
                         {"conformance": {"status": "ok"}, "types": {"status": "ok"}, "authz": {"status": "ok"}}, log)
    apis = {a["operation"]: a for a in cov["apis"]}
    sites = {t["test"]: t for t in apis["GET /sites"]["tests"]}
    assert sites["Behaviour vs Swagger"]["status"] == "partial"
    assert "no token was set" in sites["Behaviour vs Swagger"]["reason"]
    assert sites["Cross-user (BOLA)"]["status"] == "not_tested"  # takes siteId but no scenario
    assert sites["Wrong data types"]["status"] == "not_applicable"
    ingress = {t["test"]: t for t in apis["POST /ingress"]["tests"]}
    assert ingress["Wrong data types"]["status"] == "not_tested"
    assert apis["POST /recalc"]["verdict"] == "excluded"
    assert all(t["status"] == "not_tested" and "Excluded" in t["reason"] for t in apis["POST /recalc"]["tests"])
    assert apis["GET /sites"]["verdict"] == "incomplete"
    assert cov["warnings"][0].startswith("No token was set for user A")
    assert any("No second user" in w for w in cov["warnings"])
    coverage.write(cov, tmp_path)
    assert "partial" in (tmp_path / "coverage.csv").read_text(encoding="utf-8-sig")
    assert json.loads((tmp_path / "coverage.json").read_text())["apis"]


def test_successful_writes_are_warned_about(tmp_path):
    log = _log(tmp_path, [("conformance", "POST /ingress", "Random data: valid request", "pass", 201)])
    cov = coverage.build(_ops(), {"stages": ["conformance"], "headers": {"Authorization": "***"}},
                         {"conformance": {"status": "ok"}}, log)
    assert any("write request(s)" in w for w in cov["warnings"])
