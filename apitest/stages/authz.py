"""Custom authorization checks that generic scanners miss.

1. No credentials on an endpoint the spec marks as secured -> must not return 2xx.
2. Garbage credentials on a secured endpoint -> must not return 2xx.
3. BOLA: resources owned by user A requested with user B's credentials.
4. Passive response checks: security headers, stack-trace leaks, wildcard CORS with credentials.
"""
from __future__ import annotations

import re
from pathlib import Path

import httpx

from ..models import Finding, StageResult
from ..proc import check

SAFE = {"get", "head", "options"}
LEAK = re.compile(r"(Traceback \(most recent|at [\w.$]+\([\w.]+:\d+\)|System\.\w+Exception|"
                  r"Stack trace|SQLSTATE|ORA-\d{4,}|SequelizeDatabaseError|\bat Object\.<anonymous>)")
HEADERS_EXPECTED = {"x-content-type-options": "nosniff"}


def _url(base: str, path: str, params: dict[str, str]) -> str:
    for k, v in params.items():
        path = path.replace("{" + k + "}", v)
    return base.rstrip("/") + path


def _send(client, op, base, headers):
    kw = {"headers": headers, "params": op.query_params}
    if op.has_body:
        kw["json"] = {}
    return client.request(op.method.upper(), _url(base, op.path, op.path_params), **kw)


def run(spec, cfg, out: Path) -> StageResult:
    res = StageResult("authz")
    base = cfg.base_url or spec.base_url
    if not base:
        res.status, res.note = "error", "No base URL (pass --base-url)"
        return res
    ops = [o for o in spec.operations if not any(re.search(p, o.path) for p in cfg.exclude_paths)]
    if cfg.no_mutating_authz:
        ops = [o for o in ops if o.method in SAFE]
    checked = 0
    seen: set[str] = set()
    with httpx.Client(timeout=cfg.timeout, follow_redirects=False) as c:
        for op in ops:
            check(cfg)
            try:
                if op.secured:
                    for label, hdrs in (("no credentials", {}),
                                        ("invalid credentials", {"Authorization": "Bearer invalid.token.value"})):
                        r = _send(c, op, base, hdrs)
                        checked += 1
                        if 200 <= r.status_code < 300:
                            res.findings.append(Finding(
                                "authz", "critical",
                                f"Secured endpoint accepted {label} (HTTP {r.status_code})",
                                op.label, "The spec declares security on this operation but it was served anyway."))
                        _passive(res, op, r, seen)
                elif op.method in SAFE:
                    r = _send(c, op, base, cfg.headers)
                    checked += 1
                    _passive(res, op, r, seen)
            except httpx.HTTPError as e:
                res.findings.append(Finding("authz", "info", "Request failed", op.label, str(e)))
        res.findings += _bola(c, cfg, base)
    res.note = f"{checked} requests sent; {len(cfg.bola)} BOLA scenario(s) configured"
    if not cfg.bola:
        res.note += " (add `bola:` entries to the config to test cross-user access)"
    return res


def _passive(res, op, r, seen):
    if "leak" not in seen and r.status_code >= 400 and LEAK.search(r.text[:5000]):
        seen.add("leak")
        res.findings.append(Finding("authz", "medium", "Error response leaks stack trace / internals",
                                    op.label, r.text[:400]))
    for h in HEADERS_EXPECTED:
        if h not in seen and h not in r.headers:
            seen.add(h)
            res.findings.append(Finding("authz", "low", f"Missing security header: {h}", op.label,
                                        "Seen on the first checked response; likely applies API-wide."))
    acao = r.headers.get("access-control-allow-origin")
    acac = r.headers.get("access-control-allow-credentials")
    if "cors" not in seen and acao == "*" and acac == "true":
        seen.add("cors")
        res.findings.append(Finding("authz", "high", "CORS allows any origin with credentials", op.label))


def _bola(c, cfg, base) -> list[Finding]:
    out: list[Finding] = []
    if not cfg.bola:
        return out
    if not cfg.headers_b:
        return [Finding("authz", "info", "BOLA scenarios skipped", "",
                        "Pass --header-b with user B's credentials.")]
    for sc in cfg.bola:
        check(cfg)
        method = sc.get("method", "GET").upper()
        path = sc["path"]
        params = {k: str(v) for k, v in sc.get("params", {}).items()}
        label = f"{method} {path} {params}"
        url = _url(base, path, params)
        body = {"json": sc["body"]} if "body" in sc else {}
        try:
            a = c.request(method, url, headers=cfg.headers, **body)
            if not 200 <= a.status_code < 300:
                out.append(Finding("authz", "info", "BOLA scenario inconclusive", label,
                                   f"Owner (user A) got HTTP {a.status_code}; fix the scenario's IDs."))
                continue
            b = c.request(method, url, headers=cfg.headers_b, **body)
        except httpx.HTTPError as e:
            out.append(Finding("authz", "info", "BOLA request failed", label, str(e)))
            continue
        if 200 <= b.status_code < 300:
            out.append(Finding("authz", "critical", "BOLA: user B accessed user A's resource",
                               label, f"User B got HTTP {b.status_code}; expected 401/403/404."))
    return out
