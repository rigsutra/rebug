"""DAST via the OWASP ZAP API scan, run in Docker."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from ..models import Finding, StageResult
from ..proc import progress, run_cmd
from ..testlog import OpMatcher, log_of

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


# Lines from zap-api-scan.py's debug log (-d, written to stderr), in the order they appear
PROGRESS_LINES = [
    (re.compile(r"\bStarting ZAP\b"), lambda m: ("ZAP is starting up (usually 1–3 minutes)", None)),
    (re.compile(r"Set max pscan alerts"), lambda m: ("ZAP is up; importing the API definition", None)),
    (re.compile(r"Number of Imported URLs: (\d+)"), lambda m: (f"Imported {m[1]} URLs from the spec", None)),
    (re.compile(r"Spider progress %: (\d+)"), lambda m: ("Crawling", int(m[1]))),
    (re.compile(r"Active Scan progress %: (\d+)"), lambda m: ("Active scan: attacking the APIs", int(m[1]))),
    (re.compile(r"Active Scan complete"), lambda m: ("Active scan complete", 100)),
    (re.compile(r"Records to scan"), lambda m: ("Passive scan: analysing responses", None)),
    (re.compile(r"Passive scanning complete"), lambda m: ("Passive scan complete; writing the report", None)),
    (re.compile(r"Total of (\d+) URLs"), lambda m: (f"Finished: {m[1]} URLs checked", None)),
]


def _live(cfg, lines: list[str]) -> None:
    for line in lines:
        for rx, fmt in PROGRESS_LINES:
            m = rx.search(line)
            if m:
                msg, pct = fmt(m)
                progress(cfg, "zap", msg + (f" {pct}%" if pct is not None else ""), done=pct,
                         total=100 if pct is not None else None)
                break


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
           "-J", "zap.json", "-r", "zap.html", "-I", "-d"]  # -d: debug output includes scan progress %
    if zap_opts:
        cmd += ["-z", " ".join(zap_opts)]
    progress(cfg, "zap", "Starting the OWASP ZAP container")
    # Killing the docker client doesn't stop the container, so remove it by name on cancel
    p = run_cmd(cmd, cancel=cfg.cancel, timeout=3600,
                on_cancel=lambda: subprocess.run(["docker", "rm", "-f", name], capture_output=True),
                on_tick=lambda lines: _live(cfg, lines))
    (out / "zap.log").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
    zf = out / "zap.json"
    if not zf.exists():
        res.status, res.note = "error", (p.stderr or p.stdout)[-600:]
        return res
    tl = log_of(cfg)
    match = OpMatcher(spec.operations, _for_container(base))
    for site in json.loads(zf.read_text(encoding="utf-8")).get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [])
            where = f"{inst[0].get('method', '')} {inst[0].get('uri', '')}" if inst else ""
            sev = RISK.get(str(a.get("riskcode")), "info")
            res.findings.append(Finding("zap", sev, a.get("name", "ZAP alert"), where,
                                        f"{len(inst)} instance(s). {a.get('desc', '')[:300]}"))
            if not tl:
                continue
            for i in inst:
                method, uri = i.get("method", ""), i.get("uri", "")
                tl.add("zap", f"Security check: {a.get('name', 'alert')}", operation=match(method, uri),
                       expected=_strip_html(a.get("solution", ""))[:400] or "No issue",
                       verdict="info" if sev == "info" else "fail",
                       explanation=f"ZAP rated this {sev} risk. {_strip_html(a.get('desc', ''))[:300]}"
                                   + (f" Parameter: {i.get('param')}." if i.get("param") else "")
                                   + (f" Attack sent: {i.get('attack')}." if i.get("attack") else ""),
                       request={"method": method, "url": uri},
                       details={"risk": sev, "confidence": a.get("confidence"), "param": i.get("param"),
                                "attack": i.get("attack"), "evidence": i.get("evidence"),
                                "otherinfo": i.get("otherinfo"), "cwe": a.get("cweid"), "wasc": a.get("wascid"),
                                "description": _strip_html(a.get("desc", ""))[:1500],
                                "reference": _strip_html(a.get("reference", ""))[:600]})
    if tl:
        imported = re.search(r"Total of (\d+) URLs", p.stdout + p.stderr)
        tl.add("zap", "ZAP scan summary", verdict="info",
               details={"message": f"ZAP checked {imported[1] if imported else 'an unknown number of'} URLs. "
                                   "Only requests that raised an alert are listed individually; ZAP's API scan "
                                   "doesn't export every request it sends. Its full HTML report is zap.html."})
    return res


def _strip_html(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()
