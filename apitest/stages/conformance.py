"""Type safety / conformance + fuzzing via Schemathesis."""
from __future__ import annotations

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Finding, StageResult
from ..proc import run_cmd


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("conformance")
    base = cfg.base_url or spec.base_url
    if not base:
        res.status, res.note = "error", "No base URL (pass --base-url)"
        return res
    junit = out / "schemathesis-junit.xml"
    if cfg.spec.startswith("http") and not spec.from_page and not spec.filtered:
        schema_arg = cfg.spec
    else:  # local file, spec embedded in a Swagger UI page, or reduced to selected operations
        schema_arg = str(out / "spec.json")
        (out / "spec.json").write_text(spec.text, encoding="utf-8")
    cmd = [sys.executable, "-m", "schemathesis.cli", "run", schema_arg, "--url", base,
           "--checks", "all", "--max-examples", str(cfg.max_examples),
           "--continue-on-failure", "--no-color",
           "--report", "junit", "--report-junit-path", str(junit)]
    for k, v in cfg.headers.items():
        cmd += ["-H", f"{k}: {v}"]
    for pat in cfg.exclude_paths:
        cmd += ["--exclude-path-regex", pat]
    # Schemathesis chokes on PYTHONIOENCODING values like "utf-8:surrogateescape" (Windows)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    junit.unlink(missing_ok=True)
    p = run_cmd(cmd, cancel=cfg.cancel, timeout=1800, env=env)
    (out / "schemathesis.log").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
    root = ET.parse(junit).getroot() if junit.exists() else None
    if root is None or not list(root.iter("testcase")):
        # No test cases means Schemathesis itself failed; never report that as a clean pass
        res.status = "error"
        res.note = "Schemathesis ran no tests: " + (p.stderr or p.stdout).strip()[-600:]
        return res
    res.note = f"{len(list(root.iter('testcase')))} operation(s) tested"
    for case in root.iter("testcase"):
        name = case.get("name", "")
        for el in case.findall("failure") + case.findall("error"):
            res.findings += _split_checks(name, (el.text or el.get("message") or "").strip())
    return res


# Schemathesis check titles -> severity. Anything unlisted is "medium".
SEVERITY_BY_CHECK = [
    ("server error", "high"),
    ("without authentication", "high"),
    ("missing header not rejected", "high"),
    ("ignored auth", "high"),
    ("response violates schema", "medium"),
    ("schema-violating request", "medium"),
    ("undocumented content type", "low"),
    ("undocumented http status", "low"),
    ("unsupported method", "low"),
]


def _split_checks(endpoint: str, text: str) -> list[Finding]:
    """One <failure> holds several numbered test cases, each listing checks as
    '- <title>' lines. Emit one finding per distinct check title."""
    blocks = re.split(r"(?m)^\d+\. Test Case ID: \S+\s*$", text)
    found: dict[str, list[str]] = {}
    for block in blocks:
        for title in re.findall(r"(?m)^- (.+)$", block):
            found.setdefault(title.strip(), []).append(block.strip())
    if not found and text:
        found["Check failed"] = [text]
    out = []
    for title, examples in found.items():
        sev = next((s for k, s in SEVERITY_BY_CHECK if k in title.lower()), "medium")
        detail = f"{len(examples)} failing case(s). First:\n\n{examples[0][:1500]}"
        out.append(Finding("conformance", sev, title, endpoint, detail))
    return out
