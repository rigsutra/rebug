"""Web UI backend: projects, API discovery, runs (start / stop / results).

Storage (under --data-dir, default ./reports):
  projects/<id>.json   project settings + cached list of operations
  runs/<run id>/       run.json (status, masked headers), report.json/html, raw tool output

Secrets: header lines that reference an environment variable (Authorization: Bearer ${ORDERS_TOKEN})
are saved with the project and resolved when a run starts. Any other header line is treated as a
literal secret and kept in this process's memory only, so it is gone after a restart.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import zipfile
import subprocess
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from ..config import ALL_STAGES, ENV_REF, Config, expand_env, parse_header
from ..discover import discover
from ..models import sev_rank
from ..runner import run_pipeline
from ..spec import load_spec
from types import SimpleNamespace

from .. import coverage as coverage_mod
from .. import htmlreport
from ..stages.conformance import log_scenarios
from ..testlog import TestLog, iter_entries, write_csv

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
    force: bool = False  # start even though no token is set for APIs that need login


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


def _excluded(p: dict) -> set[str]:
    pats = []
    for x in p.get("exclude_paths", []):
        try:
            pats.append(re.compile(x))
        except re.error:
            pass
    return {o["label"] for o in p.get("operations", []) if any(r.search(o["path"]) for r in pats)}


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

FEED_MAX = 400  # live activity entries kept per run


def _worker(run_id: str, cfg: Config) -> None:
    state = _runs[run_id]

    def on_progress(p: dict) -> None:
        p["t"] = time.time()
        with _lock:
            state["activity"] = p
            # per-field chatter from `types` only updates "Now"; it doesn't flood the feed
            if not (p["stage"] == "types" and p["msg"].startswith("Field ")):
                state["feed"].append(p)
                del state["feed"][:-FEED_MAX]

    cfg.on_progress = on_progress

    def emit(e: dict) -> None:
        with _lock:
            t = e["type"]
            if t == "stage_start":
                state["stages"][e["stage"]] = {"status": "running", "started": time.time()}
                state["activity"] = {"stage": e["stage"], "msg": "Starting", "op": "", "done": None,
                                     "total": None, "level": "info", "t": time.time()}
            elif t == "stage_end":
                state["stages"][e["stage"]] = {k: e[k] for k in ("status", "findings", "note", "duration")}
                state["feed"].append({"stage": e["stage"], "op": "", "done": None, "total": None, "t": time.time(),
                                      "level": "bad" if e["status"] == "error" else "ok" if e["status"] == "ok" else "warn",
                                      "msg": f"Finished: {e['status']}, {e['findings']} finding(s)"})
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


def _start(p: dict, operations: list[str], force: bool = False) -> str:
    running = _running_run(p["id"])
    if running:
        raise HTTPException(409, f"A run is already in progress for this project ({running}). Stop it first.")
    try:
        headers = {k: expand_env(v) for k, v in _parse_headers(_merged_headers(p, "headers")).items()}
        headers_b = {k: expand_env(v) for k, v in _parse_headers(_merged_headers(p, "headers_b")).items()}
    except ValueError as e:
        raise HTTPException(400, f"{e} (set it in the environment of the apitest server)")
    scope = [o for o in p.get("operations", []) if (not operations or o["label"] in operations)
             and o["label"] not in _excluded(p)]
    secured = [o for o in scope if o.get("secured")]
    if secured and not headers and not force:
        raise HTTPException(428, json.dumps({
            "code": "NO_TOKEN",
            "message": f"No token is set for user A, but {len(secured)} of the {len(scope)} APIs in this run need login. "
                       "Without one, every request to them is refused with 401 and their real behaviour isn't tested. "
                       "Tokens typed directly into Settings are forgotten when the apitest server restarts."}))
    excluded = _excluded(p)
    if operations:
        known = {o["label"] for o in p.get("operations", [])}
        unknown = [o for o in operations if o not in known]
        if unknown:
            raise HTTPException(400, f"Not in this project's spec: {unknown}. Refresh the API list.")
        operations = [o for o in operations if o not in excluded]
        if not operations:
            raise HTTPException(400, "All selected APIs are excluded in Settings → Exclude paths.")
    elif excluded and len(excluded) == len(p.get("operations", [])):
        raise HTTPException(400, "Every API is excluded in Settings → Exclude paths; nothing to test.")
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    cancel = threading.Event()
    cfg = Config(
        spec=p["spec"], base_url=p.get("base_url", ""), headers=headers, headers_b=headers_b,
        stages=p.get("stages") or list(ALL_STAGES), max_examples=p.get("max_examples", 50),
        fail_on=p.get("fail_on", "high"), out_dir=str(runs_dir() / run_id),
        no_mutating_authz=p.get("no_mutating_authz", False), exclude_paths=p.get("exclude_paths", []),
        bola=p.get("bola", []), operations=operations, cancel=cancel, title=p["name"],
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
        "activity": None, "feed": [], "exclude_paths": cfg.exclude_paths, "bola": cfg.bola,
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


@app.get("/favicon.ico", include_in_schema=False)
def favicon():  # browsers ask for this path directly; an SVG is accepted by all current ones
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")


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
                "excluded": len(_excluded(p)),
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
    excluded = _excluded(p)
    for o in p.get("operations", []):
        o["excluded"] = o["label"] in excluded
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
    return {"id": _start(_read_project(pid), body.operations, body.force)}


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
    for k in ("timeout", "zap_image", "types_max_fields", "operations", "cancel", "on_progress", "testlog", "title"):
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
    data["feed"] = (data.get("feed") or [])[-150:]
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


def _run_dir(run_id: str) -> Path:
    if not re.fullmatch(r"[\w-]+", run_id) or not (runs_dir() / run_id).is_dir():
        raise HTTPException(404)
    return runs_dir() / run_id


def _summary(e: dict) -> dict:
    """Test-log entry without bodies/headers, for the list view."""
    rq, rs = e.get("request") or {}, e.get("response") or {}
    d = e.get("details") or {}
    return {"seq": e["seq"], "ts": e["ts"], "stage": e["stage"], "operation": e["operation"],
            "scenario": e["scenario"], "expected": e["expected"], "verdict": e["verdict"],
            "explanation": (e.get("explanation") or "")[:300],
            "method": rq.get("method", ""), "url": rq.get("url", ""), "status": rs.get("status"),
            "elapsed_ms": rs.get("elapsed_ms"),
            "problem": (d.get("failures") or [""])[0][:200] if d.get("failures") else
                       d.get("problem") or "; ".join(d.get("passive_issues") or []) or d.get("error", "")}


@app.get("/api/runs/{run_id}/log")
def run_log(run_id: str, stage: str = "", op: str = "", verdict: str = "", q: str = "",
            offset: int = 0, limit: int = 100):
    """Filtered, paginated test log. Counts are over the filtered set (except `stages`, which
    ignores the stage filter so the stage tabs keep their numbers)."""
    f = _run_dir(run_id) / "test-log.ndjson"
    q = q.lower()
    items, total, verdicts, stages, ops = [], 0, {}, {}, set()
    for e in iter_entries(f):
        if op and e["operation"] != op and not (op == "-" and not e["operation"]):
            continue
        if verdict and e["verdict"] != verdict:
            continue
        if q and q not in json.dumps(e, ensure_ascii=False).lower():
            continue
        stages[e["stage"]] = stages.get(e["stage"], 0) + 1
        if stage and e["stage"] != stage:
            continue
        ops.add(e["operation"])
        verdicts[e["verdict"]] = verdicts.get(e["verdict"], 0) + 1
        if offset <= total < offset + limit:
            items.append(_summary(e))
        total += 1
    return {"total": total, "items": items, "verdicts": verdicts, "stages": stages,
            "operations": sorted(o for o in ops if o), "available": f.is_file()}


@app.get("/api/runs/{run_id}/log/{seq}")
def run_log_entry(run_id: str, seq: int):
    for e in iter_entries(_run_dir(run_id) / "test-log.ndjson"):
        if e["seq"] == seq:
            return e
    raise HTTPException(404)


@app.get("/api/runs/{run_id}/download/{kind}")
def run_download(run_id: str, kind: str):
    d = _run_dir(run_id)
    meta = _load_meta(run_id) or {}
    slug = re.sub(r"[^a-z0-9]+", "-", (meta.get("project_name") or "run").lower()).strip("-") or "run"
    base = f"apitest-{slug}-{run_id}"
    if kind in ("html", "zip", "csv", "ndjson") and meta.get("status") not in ("running", "stopping"):
        _ensure_artifacts(d, meta)  # older runs: rebuild what can be recovered
    if kind in ("html", "view"):
        f = d / "test-report.html"
        if not f.is_file():
            raise HTTPException(404, "The HTML report is written when the run finishes")
        if kind == "view":  # open in the browser instead of downloading
            return FileResponse(f, media_type="text/html")
        return FileResponse(f, media_type="text/html", filename=f"{base}-report.html")
    if kind in ("csv", "ndjson") and not (d / "test-log.ndjson").is_file():
        raise HTTPException(404, "This run has no test log (it was made by an older apitest version)")
    if kind == "csv":
        csv_path = d / "test-log.csv"
        if not csv_path.is_file() or (d / "test-log.ndjson").stat().st_mtime > csv_path.stat().st_mtime:
            write_csv(d / "test-log.ndjson", csv_path)  # live run, or CSV older than the log
        return FileResponse(csv_path, media_type="text/csv", filename=f"{base}-test-log.csv")
    if kind == "ndjson":
        return FileResponse(d / "test-log.ndjson", media_type="application/x-ndjson", filename=f"{base}-test-log.ndjson")
    if kind == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    z.write(p, f"{base}/{p.relative_to(d).as_posix()}")
            z.writestr(f"{base}/README.txt", ZIP_README)
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{base}.zip"'})
    raise HTTPException(404)


def _ensure_artifacts(d: Path, meta: dict) -> None:
    """Runs made before the test log / HTML report existed: rebuild them from what the run saved
    (Schemathesis' event stream holds every request it sent)."""
    if (d / "test-report.html").is_file():
        return
    legacy = not (d / "test-log.ndjson").is_file()
    if legacy:
        tl = TestLog(d / "test-log.ndjson")
        if (d / "schemathesis-events.ndjson").is_file():
            log_scenarios(SimpleNamespace(testlog=tl), d / "schemathesis-events.ndjson")
        write_csv(d / "test-log.ndjson", d / "test-log.csv")
    spec_file = next((f for f in (d / "spec-full.json", d / "spec.json") if f.is_file()), None)
    if not spec_file:
        return
    ops = load_spec(str(spec_file)).operations
    if meta.get("operations"):
        ops = [o for o in ops if o.label in set(meta["operations"])]
    proj = {}
    if meta.get("project_id"):
        try:
            proj = _read_project(meta["project_id"])
        except HTTPException:
            pass
    report = json.loads((d / "report.json").read_text(encoding="utf-8")) if (d / "report.json").is_file() else {"stages": []}
    settings = {"stages": meta.get("stages_requested") or [], "headers": meta.get("headers") or {},
                "headers_b": meta.get("headers_b") or {},
                "bola": meta.get("bola", proj.get("bola", [])),
                "exclude_paths": meta.get("exclude_paths", proj.get("exclude_paths", [])),
                "operations": meta.get("operations") or [],
                "unrecorded_stages": [s for s in (meta.get("stages_requested") or []) if s != "conformance"]
                if legacy else []}
    cov = coverage_mod.build(ops, settings, {s["name"]: {"status": s["status"], "note": s.get("note", "")}
                                             for s in report["stages"]}, d / "test-log.ndjson")
    if legacy:
        cov["warnings"].insert(0, "This run was made by an older apitest version that didn't record every request. "
                                  "Only the behaviour tests (Schemathesis) could be recovered; the other tests' "
                                  "individual requests weren't saved, so they may show as not tested.")
    coverage_mod.write(cov, d)
    htmlreport.build(d, meta, cov)


ZIP_README = """apitest run export

test-report.html  Start here: per API, what was tested and what wasn't (and why), the problems found,
                  and every test with its input, output and result. Open it in any browser.
coverage.csv      Per API and test: tested / partly tested / not tested / not applicable, and why.
test-log.ndjson   Every test: one JSON object per line with stage, operation, scenario, expected,
                  verdict (pass/fail/info/error), the full request and response, and details
                  (checks run, failure messages, ZAP attack/evidence). Tokens are masked.
test-log.csv      The same, one row per test without bodies, for Excel.
report.html       Findings report.        report.json   Findings as JSON.
run.json          Run settings and status (header values masked).
spec.json / spec-full.json   The OpenAPI document that was tested.
schemathesis-*    Raw Schemathesis output (JUnit XML, event stream, console log).
zap.html / zap.json / zap.log   Raw OWASP ZAP output.
types.log         One line per wrong-type request.
"""


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
