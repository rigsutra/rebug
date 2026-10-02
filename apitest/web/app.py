"""Web UI backend: projects, API discovery, runs (start / stop / results).

Storage (under --data-dir, default ./reports):
  projects/<id>.json   project settings + cached list of operations
  runs/<run id>/       run.json (status, masked headers), report.json/html, raw tool output

Secrets: header lines that reference an environment variable (Authorization: Bearer ${ORDERS_TOKEN})
are saved with the project and resolved when a run starts. Any other header line is treated as a
literal secret and kept in this process's memory only, so it is gone after a restart.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from ..config import ALL_STAGES, ENV_REF, Config, expand_env, parse_header
from ..discover import discover
from ..models import sev_rank
from ..runner import run_pipeline
from ..spec import load_spec

STATIC = Path(__file__).parent / "static"
DATA = Path("reports").resolve()

app = FastAPI(title="apitest", docs_url=None, redoc_url=None)
_runs: dict[str, dict] = {}            # live state of runs started by this process
_cancels: dict[str, threading.Event] = {}
_secrets: dict[str, dict[str, str]] = {}  # project id -> {"headers": text, "headers_b": text}
_lock = threading.RLock()


def configure(data_dir: str | Path) -> None:
    global DATA
    DATA = Path(data_dir).resolve()


def projects_dir() -> Path:
    return DATA / "projects"


def runs_dir() -> Path:
    return DATA / "runs"


# ---------------- models ----------------

class BolaIn(BaseModel):
    method: str = "GET"
    path: str
    params: dict[str, str] = Field(default_factory=dict)


class ProjectIn(BaseModel):
    name: str
    description: str = ""
    spec: str
    base_url: str = ""
    headers: str = ""     # "Name: value" per line (user A)
    headers_b: str = ""   # user B, for BOLA
    stages: list[str] = Field(default_factory=lambda: list(ALL_STAGES))
    max_examples: int = 50
    fail_on: str = "high"
    no_mutating_authz: bool = False
    exclude_paths: list[str] = Field(default_factory=list)
    bola: list[BolaIn] = Field(default_factory=list)


class DiscoverIn(BaseModel):
    url: str
    headers: str = ""


class RunIn(BaseModel):
    operations: list[str] = Field(default_factory=list)  # empty = whole project


# ---------------- helpers ----------------

def _parse_headers(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line.strip():
            k, v = parse_header(line)
            out[k] = v
    return out


def _split_secret(text: str) -> tuple[str, str]:
    """Return (lines safe to save: ${ENV} references, literal-secret lines kept in memory)."""
    saved, secret = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        parse_header(line)  # validate
        (saved if ENV_REF.search(line) else secret).append(line.strip())
    return "\n".join(saved), "\n".join(secret)


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "project"
    if (projects_dir() / f"{s}.json").exists():
        s = f"{s}-{uuid.uuid4().hex[:4]}"
    return s


def _ops_summary(spec) -> list[dict]:
    out = []
    for o in spec.operations:
        out.append({"method": o.method, "path": o.path, "label": o.label, "secured": o.secured,
                    "has_body": o.has_body, "path_params": list(o.path_params),
                    "summary": o.op.get("summary") or "", "tags": o.op.get("tags") or [],
                    "operation_id": o.op.get("operationId") or "", "deprecated": bool(o.op.get("deprecated"))})
    return out


def _load_spec_info(spec_url: str, headers_text: str) -> dict:
    try:
        headers = {k: expand_env(v) for k, v in _parse_headers(headers_text).items()}
    except ValueError:
        headers = {}  # env var missing: try without auth, specs are usually public
    try:
        spec = load_spec(spec_url.strip(), headers)
    except Exception as e:
        raise HTTPException(400, f"Could not load spec: {e}")
    info = spec.raw.get("info", {})
    return {"spec_info": {"title": info.get("title", ""), "api_version": info.get("version", ""),
                          "version": spec.version, "base_url": spec.base_url, "from_page": spec.from_page},
            "operations": _ops_summary(spec), "refreshed": time.time()}


def _project_file(pid: str) -> Path:
    if not re.fullmatch(r"[a-z0-9-]+", pid):
        raise HTTPException(404)
    return projects_dir() / f"{pid}.json"


def _read_project(pid: str) -> dict:
    f = _project_file(pid)
    if not f.is_file():
        raise HTTPException(404, "Project not found")
    return json.loads(f.read_text(encoding="utf-8"))


def _write_project(p: dict) -> None:
    projects_dir().mkdir(parents=True, exist_ok=True)
    _project_file(p["id"]).write_text(json.dumps(p, indent=2), encoding="utf-8")


def _apply(p: dict, body: ProjectIn) -> None:
    if any(s not in ALL_STAGES for s in body.stages):
        raise HTTPException(400, "Unknown stage")
    try:
        saved_a, secret_a = _split_secret(body.headers)
        saved_b, secret_b = _split_secret(body.headers_b)
    except ValueError as e:
        raise HTTPException(400, str(e))
    data = body.model_dump()
    data["headers"], data["headers_b"] = saved_a, saved_b
    data["bola"] = [b for b in data["bola"] if b["path"]]
    data["exclude_paths"] = [x for x in data["exclude_paths"] if x.strip()]
    p.update(data)
    _secrets[p["id"]] = {"headers": secret_a, "headers_b": secret_b}


def _merged_headers(p: dict, key: str) -> str:
    secret = _secrets.get(p["id"], {}).get(key, "")
    return "\n".join(x for x in (p.get(key, ""), secret) if x)


def _mask(h: dict[str, str]) -> dict[str, str]:
    return {k: "***" for k in h}


# ---------------- runs: storage ----------------

def _meta_public(state: dict) -> dict:
    return {k: v for k, v in state.items() if k != "events"}


def _save_meta(state: dict) -> None:
    d = runs_dir() / state["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "run.json").write_text(json.dumps(_meta_public(state), indent=2), encoding="utf-8")


def _load_meta(run_id: str) -> dict | None:
    if run_id in _runs:
        return _runs[run_id]
    if not re.fullmatch(r"[\w-]+", run_id):
        return None
    f = runs_dir() / run_id / "run.json"
    if not f.is_file():
        return None
    meta = json.loads(f.read_text(encoding="utf-8"))
    if meta.get("status") in ("running", "stopping"):  # server restarted mid-run
        meta["status"] = "interrupted"
    return meta


def _report(run_id: str) -> dict | None:
    f = runs_dir() / run_id / "report.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else None


def _counts(report: dict | None) -> dict | None:
    if not report:
        return None
    c: dict[str, int] = {}
    for st in report["stages"]:
        for fd in st["findings"]:
            c[fd["severity"]] = c.get(fd["severity"], 0) + 1
    return c


def _project_runs(pid: str, limit: int = 50) -> list[dict]:
    out = []
    if not runs_dir().is_dir():
        return out
    for d in sorted(runs_dir().iterdir(), reverse=True):
        if len(out) >= limit:
            break
        meta = _load_meta(d.name)
        if meta and meta.get("project_id") == pid:
            out.append(meta)
    return out


def _running_run(pid: str) -> str | None:
    for rid, st in _runs.items():
        if st.get("project_id") == pid and st["status"] in ("running", "stopping"):
            return rid
    return None


# ---------------- runs: execution ----------------

def _worker(run_id: str, cfg: Config) -> None:
    state = _runs[run_id]

    def emit(e: dict) -> None:
        with _lock:
            t = e["type"]
            if t == "stage_start":
                state["stages"][e["stage"]] = {"status": "running", "started": time.time()}
            elif t == "stage_end":
                state["stages"][e["stage"]] = {k: e[k] for k in ("status", "findings", "note", "duration")}
            elif t == "spec":
                state["spec_info"] = {k: e[k] for k in ("version", "operations", "base_url")}
                state["tested"] = e["labels"]
            elif t == "cancelled":
                state["status"] = "cancelled"

    try:
        run_pipeline(cfg, emit)
        if state["status"] != "cancelled":
            state["status"] = "cancelled" if cfg.cancel.is_set() else "done"
    except Exception as e:
        state["status"] = "cancelled" if cfg.cancel.is_set() else "error"
        state["error"] = f"{type(e).__name__}: {e}"
    state["finished"] = time.time()
    _save_meta(state)
    _cancels.pop(run_id, None)


def _start(p: dict, operations: list[str]) -> str:
    running = _running_run(p["id"])
    if running:
        raise HTTPException(409, f"A run is already in progress for this project ({running}). Stop it first.")
    try:
        headers = {k: expand_env(v) for k, v in _parse_headers(_merged_headers(p, "headers")).items()}
        headers_b = {k: expand_env(v) for k, v in _parse_headers(_merged_headers(p, "headers_b")).items()}
    except ValueError as e:
        raise HTTPException(400, f"{e} (set it in the environment of the apitest server)")
    if operations:
        known = {o["label"] for o in p.get("operations", [])}
        unknown = [o for o in operations if o not in known]
        if unknown:
            raise HTTPException(400, f"Not in this project's spec: {unknown}. Refresh the API list.")
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    cancel = threading.Event()
    cfg = Config(
        spec=p["spec"], base_url=p.get("base_url", ""), headers=headers, headers_b=headers_b,
        stages=p.get("stages") or list(ALL_STAGES), max_examples=p.get("max_examples", 50),
        fail_on=p.get("fail_on", "high"), out_dir=str(runs_dir() / run_id),
        no_mutating_authz=p.get("no_mutating_authz", False), exclude_paths=p.get("exclude_paths", []),
        bola=p.get("bola", []), operations=operations, cancel=cancel,
    )
    if operations:  # only run BOLA scenarios that belong to the selected operations
        sel = set(operations)
        cfg.bola = [b for b in cfg.bola if f"{b['method'].upper()} {b['path'].split('?')[0]}" in sel]
    state = {
        "id": run_id, "project_id": p["id"], "project_name": p["name"], "status": "running",
        "started": time.time(), "finished": None, "error": None, "spec": cfg.spec, "base_url": cfg.base_url,
        "operations": operations, "tested": None, "stages_requested": cfg.stages,
        "stages": {s: {"status": "pending"} for s in cfg.stages}, "fail_on": cfg.fail_on,
        "headers": _mask(headers), "headers_b": _mask(headers_b), "spec_info": None,
    }
    _runs[run_id] = state
    _cancels[run_id] = cancel
    _save_meta(state)
    threading.Thread(target=_worker, args=(run_id, cfg), daemon=True).start()
    return run_id


# ---------------- routes: static / env ----------------

@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/static/{name}")
def static(name: str):
    f = (STATIC / name).resolve()
    if f.parent != STATIC.resolve() or not f.is_file():
        raise HTTPException(404)
    return FileResponse(f, headers={"Cache-Control": "no-cache"})


@app.get("/api/env")
def env():
    npx = bool(shutil.which("npx"))
    docker = bool(shutil.which("docker")) and \
        subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    return {"stages": ALL_STAGES,
            "available": {"lint": npx, "zap": docker},
            "reasons": {"lint": "" if npx else "Node.js (npx) not found",
                        "zap": "" if docker else "Docker is not running"}}


# ---------------- routes: discovery ----------------

@app.post("/api/discover")
def api_discover(body: DiscoverIn):
    try:
        headers = {k: expand_env(v) for k, v in _parse_headers(body.headers).items()}
    except ValueError as e:
        raise HTTPException(400, str(e))
    res = discover(body.url, headers)
    for s in res["specs"]:  # include the API list of each document found
        try:
            spec = load_spec(s["url"], headers)
            s["base_url"] = spec.base_url
            s["ops"] = _ops_summary(spec)
        except Exception as e:
            s["ops"], s["error"] = [], str(e)
    return res


# ---------------- routes: projects ----------------

@app.get("/api/projects")
def list_projects():
    out = []
    if projects_dir().is_dir():
        for f in sorted(projects_dir().glob("*.json")):
            p = json.loads(f.read_text(encoding="utf-8"))
            runs = _project_runs(p["id"], limit=1)
            last = runs[0] if runs else None
            out.append({
                "id": p["id"], "name": p["name"], "description": p.get("description", ""), "spec": p["spec"],
                "spec_info": p.get("spec_info"), "operations": len(p.get("operations", [])),
                "running": _running_run(p["id"]),
                "last_run": last and {"id": last["id"], "status": last["status"], "started": last["started"],
                                      "counts": _counts(_report(last["id"])),
                                      "partial": bool(last.get("operations"))},
            })
    return out


@app.post("/api/projects")
def create_project(body: ProjectIn):
    if not body.name.strip():
        raise HTTPException(400, "Name is required")
    p = {"id": _slug(body.name), "created": time.time()}
    _apply(p, body)
    p.update(_load_spec_info(body.spec, _merged_headers(p, "headers")))
    p["updated"] = time.time()
    _write_project(p)
    return {"id": p["id"]}


@app.get("/api/projects/{pid}")
def get_project(pid: str):
    p = _read_project(pid)
    p["headers"] = _merged_headers(p, "headers")
    p["headers_b"] = _merged_headers(p, "headers_b")
    p["running"] = _running_run(pid)
    # latest result per operation, from the newest runs that tested it
    op_status: dict[str, dict] = {}
    labels = {o["label"] for o in p.get("operations", [])}
    for meta in _project_runs(pid, limit=30):
        if meta["status"] not in ("done", "cancelled"):
            continue
        tested = meta.get("tested") or []
        pending = [l for l in tested if l in labels and l not in op_status]
        if not pending:
            continue
        rep = _report(meta["id"])
        if not rep:
            continue
        finished_stages = {s["name"] for s in rep["stages"] if s["status"] not in ("cancelled",)}
        for l in pending:
            op_status[l] = {"run_id": meta["id"], "started": meta["started"], "counts": {}, "max": None,
                            "partial": meta["status"] == "cancelled"}
        for st in rep["stages"]:
            if st["name"] not in finished_stages:
                continue
            for fd in st["findings"]:
                s = op_status.get(fd.get("operation"))
                if s and s["run_id"] == meta["id"]:
                    s["counts"][fd["severity"]] = s["counts"].get(fd["severity"], 0) + 1
                    if s["max"] is None or sev_rank(fd["severity"]) > sev_rank(s["max"]):
                        s["max"] = fd["severity"]
        if len(op_status) == len(labels):
            break
    p["op_status"] = op_status
    return p


@app.put("/api/projects/{pid}")
def update_project(pid: str, body: ProjectIn):
    p = _read_project(pid)
    spec_changed = body.spec.strip() != p["spec"]
    _apply(p, body)
    if spec_changed or not p.get("operations"):
        p.update(_load_spec_info(body.spec, _merged_headers(p, "headers")))
    p["updated"] = time.time()
    _write_project(p)
    return {"ok": True}


@app.post("/api/projects/{pid}/refresh")
def refresh_project(pid: str):
    p = _read_project(pid)
    p.update(_load_spec_info(p["spec"], _merged_headers(p, "headers")))
    _write_project(p)
    return {"operations": len(p["operations"])}


@app.delete("/api/projects/{pid}")
def delete_project(pid: str):
    _read_project(pid)
    if _running_run(pid):
        raise HTTPException(409, "Stop the running test first")
    removed = 0
    for meta in _project_runs(pid, limit=100000):
        shutil.rmtree(runs_dir() / meta["id"], ignore_errors=True)
        _runs.pop(meta["id"], None)
        removed += 1
    _project_file(pid).unlink()
    _secrets.pop(pid, None)
    return {"deleted_runs": removed}


@app.get("/api/projects/{pid}/runs")
def project_runs(pid: str):
    _read_project(pid)
    return [{k: m.get(k) for k in ("id", "status", "started", "finished", "operations", "error")}
            | {"counts": _counts(_report(m["id"]))} for m in _project_runs(pid)]


@app.post("/api/projects/{pid}/runs")
def start_project_run(pid: str, body: RunIn):
    return {"id": _start(_read_project(pid), body.operations)}


@app.get("/api/projects/{pid}/yaml", response_class=PlainTextResponse)
def project_yaml(pid: str):
    """CLI config for this project. ${ENV} references are kept; literal tokens become placeholders."""
    p = _read_project(pid)
    def hdrs(key):
        out = {}
        for k, v in _parse_headers(p.get(key, "")).items():
            out[k] = v
        for k in _parse_headers(_secrets.get(pid, {}).get(key, "")):
            out[k] = "<set me>"
        return out
    cfg = Config(spec=p["spec"], base_url=p.get("base_url", ""), headers=hdrs("headers"),
                 headers_b=hdrs("headers_b"), stages=p.get("stages", ALL_STAGES),
                 max_examples=p.get("max_examples", 50), fail_on=p.get("fail_on", "high"),
                 out_dir=f"reports/{pid}", no_mutating_authz=p.get("no_mutating_authz", False),
                 exclude_paths=p.get("exclude_paths", []), bola=p.get("bola", []))
    data = asdict(cfg)
    for k in ("timeout", "zap_image", "types_max_fields", "operations", "cancel"):
        data.pop(k, None)
    return f"# apitest config for project '{p['name']}'\n" + yaml.safe_dump(data, sort_keys=False)


# ---------------- routes: runs ----------------

@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    meta = _load_meta(run_id)
    if not meta:
        raise HTTPException(404)
    with _lock:
        data = json.loads(json.dumps(_meta_public(meta)))
    data["report"] = _report(run_id)
    d = runs_dir() / run_id
    data["files"] = sorted(x.name for x in d.iterdir() if x.is_file() and x.name != "run.json"
                           and not x.name.startswith(".")) if d.is_dir() else []
    return data


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: str):
    ev = _cancels.get(run_id)
    st = _runs.get(run_id)
    if not ev or not st or st["status"] not in ("running", "stopping"):
        raise HTTPException(409, "This run is not running")
    ev.set()
    st["status"] = "stopping"
    return {"ok": True}


@app.get("/api/runs/{run_id}/files/{name}")
def run_file(run_id: str, name: str):
    run_dir = (runs_dir() / run_id).resolve()
    f = (run_dir / name).resolve()
    if f.parent != run_dir or not f.is_file() or not run_dir.is_relative_to(runs_dir().resolve()):
        raise HTTPException(404)
    if f.suffix in (".log", ".xml", ".txt"):
        return PlainTextResponse(f.read_text(encoding="utf-8", errors="replace"))
    return FileResponse(f)


def serve(host: str, port: int, data_dir: str = "reports") -> None:
    import uvicorn
    configure(data_dir)
    print(f"Data directory: {DATA}")
    if host not in ("127.0.0.1", "localhost"):
        print(f"WARNING: binding to {host}. Anyone who can reach this port can make the server send "
              "requests to arbitrary URLs. Put authentication in front of it.")
    print(f"apitest UI: http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
