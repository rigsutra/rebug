"""DAST via the OWASP ZAP API scan, run in Docker."""
from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from ..models import Finding, StageResult
from ..proc import run_cmd

RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _for_container(url: str) -> str:
    u = urlparse(url)
    if u.hostname in ("localhost", "127.0.0.1"):
        netloc = "host.docker.internal" + (f":{u.port}" if u.port else "")
        return urlunparse(u._replace(netloc=netloc))
    return url


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("zap")
    if not _docker_ok():
        res.status, res.note = "skipped", "Docker not available or daemon not running"
        return res
    base = cfg.base_url or spec.base_url
    (out / "spec.json").write_text(spec.text, encoding="utf-8")
    zap_opts = []
    for i, (k, v) in enumerate(cfg.headers.items()):
        zap_opts += [f"-config replacer.full_list({i}).description=h{i}",
                     f"-config replacer.full_list({i}).enabled=true",
                     f"-config replacer.full_list({i}).matchtype=REQ_HEADER",
                     f"-config replacer.full_list({i}).matchstr={k}",
                     f"-config replacer.full_list({i}).regex=false",
                     f"-config replacer.full_list({i}).replacement={v}"]
    name = f"apitest-zap-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "run", "--rm", "--name", name, "--add-host", "host.docker.internal:host-gateway",
           "-v", f"{out.resolve()}:/zap/wrk:rw", cfg.zap_image, "zap-api-scan.py",
           "-t", "spec.json", "-f", "openapi", "-O", _for_container(base),
           "-J", "zap.json", "-r", "zap.html", "-I"]
    if zap_opts:
        cmd += ["-z", " ".join(zap_opts)]
    # Killing the docker client doesn't stop the container, so remove it by name on cancel
    p = run_cmd(cmd, cancel=cfg.cancel, timeout=3600,
                on_cancel=lambda: subprocess.run(["docker", "rm", "-f", name], capture_output=True))
    (out / "zap.log").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
    zf = out / "zap.json"
    if not zf.exists():
        res.status, res.note = "error", (p.stderr or p.stdout)[-600:]
        return res
    for site in json.loads(zf.read_text(encoding="utf-8")).get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [])
            where = f"{inst[0].get('method', '')} {inst[0].get('uri', '')}" if inst else ""
            res.findings.append(Finding("zap", RISK.get(str(a.get("riskcode")), "info"),
                                        a.get("name", "ZAP alert"), where,
                                        f"{len(inst)} instance(s). {a.get('desc', '')[:300]}"))
    return res
