"""Per-API coverage: what was really tested, what wasn't, and why.

Built after a run from the spec, the settings, the stage results and the test log. A test that
"ran" but only ever saw 401 Unauthorized didn't really test the API, and this says so.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .explain import STAGES
from .testlog import iter_entries

WRITE = {"post", "put", "patch", "delete"}
ID_LIKE = re.compile(r"(^id$|id$|_id$|Id$|uuid|key$)", re.I)

STATUS_ORDER = ["not_tested", "partial", "tested", "not_applicable"]


def _item(stage, name, status, reason, requests=0, failed=0):
    return {"stage": stage, "test": name, "status": status, "reason": reason, "requests": requests, "failed": failed}


def build(operations, settings: dict, stage_results: dict, log_path: Path) -> dict:
    """operations: spec Operation objects (all of them, including excluded).
    settings: stages, headers (dict, values may be masked), headers_b, bola, exclude_paths, operations (selected).
    stage_results: name -> {"status", "note"}."""
    by_op: dict[str, list[dict]] = defaultdict(list)
    for e in iter_entries(log_path):
        by_op[e.get("operation") or ""].append(e)

    stages = settings.get("stages") or []
    has_a, has_b = bool(settings.get("headers")), bool(settings.get("headers_b"))
    bola_ops = {f"{b.get('method', 'GET').upper()} {b.get('path', '').split('?')[0]}" for b in settings.get("bola") or []}
    excl = [re.compile(p) for p in settings.get("exclude_paths") or [] if _valid(p)]
    selected = set(settings.get("operations") or [])
    unrecorded = set(settings.get("unrecorded_stages") or [])  # old runs: stages whose requests weren't logged

    apis, warnings = [], []
    secured_401 = Counter()
    for o in operations:
        label = o.label
        entries = by_op.get(label, [])
        items = []
        if any(r.search(o.path) for r in excl):
            reason = "Excluded in Settings → Exclude paths, so no test sent anything to it."
            items = [_item(s, STAGES.get(s, (s,))[0], "not_tested", reason) for s in stages]
            apis.append(_api(o, items, entries, excluded=True))
            continue
        if selected and label not in selected:
            continue  # not part of this run's selection: leave it out of the report entirely
        for s in stages:
            name = STAGES.get(s, (s,))[0]
            sr = stage_results.get(s) or {}
            st = sr.get("status")
            mine = [e for e in entries if e["stage"] == s]
            if st in ("skipped", "error", "cancelled") and not mine:
                why = {"skipped": "The test was skipped", "error": "The test tool failed",
                       "cancelled": "The run was stopped before this test reached this API"}[st]
                note = f": {sr.get('note')}" if sr.get("note") and st != "cancelled" else ""
                items.append(_item(s, name, "not_tested", why + note + "."))
                continue
            if s in unrecorded and not mine:
                items.append(_item(s, name, "not_recorded",
                                   "This older run didn't save this test's individual requests, so its result for "
                                   f"this API is unknown. The test's overall summary: {sr.get('note') or 'none'}."))
                continue
            if s == "lint":
                fails = sum(1 for e in mine if e["verdict"] == "fail")
                items.append(_item(s, name, "tested", f"{fails} Swagger rule problem(s) for this API." if fails
                                   else "No Swagger rule problems for this API.", len(mine), fails))
            elif s == "conformance":
                items.append(_conformance(o, mine, has_a, secured_401))
            elif s == "types":
                items.append(_types(o, mine))
            elif s == "authz":
                items.extend(_authz(o, mine, has_b, label in bola_ops))
            elif s == "zap":
                fails = [e for e in mine if e["verdict"] == "fail"]
                items.append(_item(s, name, "tested",
                                   f"ZAP raised {len(fails)} alert(s) for this API." if fails else
                                   "Scanned by ZAP; no alerts were raised for this API. (ZAP reports only problems, "
                                   "so the individual requests it sent aren't listed.)", len(mine), len(fails)))
        apis.append(_api(o, items, entries))

    # run-level warnings, most important first
    secured = [o for o in operations if o.secured]
    if secured and not has_a and "conformance" in stages:
        warnings.append(f"No token was set for user A, but {len(secured)} of {len(operations)} APIs require login. "
                        "Their behaviour tests only saw \"401 Unauthorized\", so the real logic behind them was never "
                        "tested. Add a token under Settings → Test users and run again.")
    elif secured_401["refused"] and secured_401["refused"] >= 0.9 * max(secured_401["total"], 1) and has_a:
        warnings.append("User A's token was refused for almost every request to protected APIs (401/403). It may be "
                        "expired, for the wrong environment, or missing scopes. Most behaviour tests only covered the "
                        "\"not logged in\" path.")
    writes_ok = sum(1 for e in iter_entries(log_path)
                    if (e.get("request") or {}).get("method", "").lower() in WRITE
                    and 200 <= ((e.get("response") or {}).get("status") or 0) < 300)
    if writes_ok:
        warnings.append(f"{writes_ok} write request(s) (POST/PUT/PATCH/DELETE) were accepted by the API, so test "
                        "data was written to whatever database it uses. Exclude write APIs (Settings → Exclude paths) "
                        "when testing against real data.")
    if "authz" in stages and not has_b:
        warnings.append("No second user (user B) was set, so no API was checked for cross-user data leaks (BOLA).")
    elif "authz" in stages and not bola_ops:
        warnings.append("No cross-user scenarios are configured, so no API was checked for one user reading another "
                        "user's data (BOLA). Add some under Settings → Cross-user scenarios.")
    for s in stages:
        st = (stage_results.get(s) or {}).get("status")
        if st == "skipped":
            warnings.append(f"{STAGES.get(s, (s,))[0]} didn't run: {(stage_results[s].get('note') or '').strip()}")
        elif st == "error":
            warnings.append(f"{STAGES.get(s, (s,))[0]} failed to run: {(stage_results[s].get('note') or '')[:200]}")
        elif st == "cancelled":
            warnings.append(f"{STAGES.get(s, (s,))[0]} was stopped before it finished; its results are incomplete.")

    totals = Counter(a["verdict"] for a in apis)
    return {"warnings": warnings, "apis": apis, "totals": dict(totals)}


def _valid(p):
    try:
        re.compile(p)
        return True
    except re.error:
        return False


def _conformance(o, mine, has_a, secured_401):
    name = STAGES["conformance"][0]
    if not mine:
        return _item("conformance", name, "not_tested", "Schemathesis sent no requests to this API.")
    codes = Counter((e.get("response") or {}).get("status") for e in mine)
    fails = sum(1 for e in mine if e["verdict"] == "fail")
    refused = codes.get(401, 0) + codes.get(403, 0)
    accepted = sum(n for c, n in codes.items() if isinstance(c, int) and 200 <= c < 300)
    if o.secured:
        secured_401["refused"] += refused
        secured_401["total"] += len(mine)
    spread = ", ".join(f"{c}×{n}" for c, n in sorted(codes.items(), key=lambda x: str(x[0])))
    if o.secured and accepted == 0 and refused:
        why = ("no token was set for user A" if not has_a else
               "user A's token was refused (expired, wrong environment or missing scopes?)")
        parts = [f"{refused} refused with 401/403"]
        bad_input = sum(n for c, n in codes.items() if c in (400, 422))
        crashed = sum(n for c, n in codes.items() if isinstance(c, int) and c >= 500)
        if bad_input:
            parts.append(f"{bad_input} rejected as invalid input before the login check")
        if crashed:
            parts.append(f"{crashed} crashed the server")
        return _item("conformance", name, "partial",
                     f"None of the {len(mine)} requests was accepted ({', '.join(parts)}) because {why}. Only the "
                     "\"not logged in\" behaviour was tested; the API's real logic was never reached.", len(mine), fails)
    return _item("conformance", name, "tested",
                 f"{len(mine)} requests (responses: {spread}). {fails} failed a check." if fails else
                 f"{len(mine)} requests (responses: {spread}); all checks passed.", len(mine), fails)


def _types(o, mine):
    name = STAGES["types"][0]
    if o.method not in ("post", "put", "patch") or not o.has_body:
        return _item("types", name, "not_applicable", "No request body to put wrong types into.")
    if not mine:
        return _item("types", name, "not_applicable", "The request body isn't JSON, so field types weren't checked.")
    base = [e for e in mine if e["scenario"].startswith("Valid request first")]
    if base and base[0]["verdict"] != "pass":
        return _item("types", name, "not_tested", base[0].get("explanation") or "The valid request was refused.",
                     len(mine), 0)
    probes = [e for e in mine if e not in base]
    fails = sum(1 for e in probes if e["verdict"] == "fail")
    fields = len({(e.get("details") or {}).get("field") for e in probes})
    return _item("types", name, "tested", f"{fields} field(s), {len(probes)} wrong-type requests; "
                 f"{fails} were wrongly accepted or crashed the server." if fails else
                 f"{fields} field(s), {len(probes)} wrong-type requests; all were refused.", len(mine), fails)


def _authz(o, mine, has_b, has_bola):
    out = []
    access = [e for e in mine if not e["scenario"].startswith("Cross-user")]
    fails = sum(1 for e in access if e["verdict"] == "fail")
    if o.secured:
        if access:
            out.append(_item("authz", "Login required", "tested",
                             f"Called with no token and with a fake token; {fails} of {len(access)} were wrongly "
                             "served." if fails else "Called with no token and with a fake token; both were refused.",
                             len(access), fails))
        else:
            out.append(_item("authz", "Login required", "not_tested", "No request was sent to this API."))
    elif o.method in WRITE:
        out.append(_item("authz", "Public API checks", "not_tested",
                         "The Swagger marks this write API as public. No request was sent, to avoid writing data. If "
                         "it should require login, add `security` to it in the Swagger."))
    else:
        out.append(_item("authz", "Public API checks", "tested" if access else "not_tested",
                         ("Response checked for leaked errors and security headers"
                          + (f"; {fails} problem(s)." if fails else "; no problems.")) if access else
                         "No request was sent to this API.", len(access), fails))
    bola = [e for e in mine if e["scenario"].startswith("Cross-user")]
    takes_id = bool(o.path_params) or any(ID_LIKE.search(p.get("name", "")) for p in o.params if p.get("in") == "query")
    if bola:
        step1 = bola[0]
        if step1["verdict"] == "error":
            out.append(_item("authz", "Cross-user (BOLA)", "not_tested", step1.get("explanation") or "", len(bola)))
        else:
            f = sum(1 for e in bola if e["verdict"] == "fail")
            out.append(_item("authz", "Cross-user (BOLA)", "tested",
                             "User B could read user A's data." if f else "User B was refused, as it should be.",
                             len(bola), f))
    elif takes_id:
        out.append(_item("authz", "Cross-user (BOLA)", "not_tested",
                         "This API takes an ID, but no cross-user scenario is configured for it"
                         + ("" if has_b else " and no user B is set")
                         + ". Add one under Settings → Cross-user scenarios with an ID owned by user A."))
    return out


def _api(o, items, entries, excluded=False):
    fails = [e for e in entries if e["verdict"] == "fail"]
    counts = Counter(e["verdict"] for e in entries)
    statuses = {i["status"] for i in items}
    if excluded:
        verdict = "excluded"
    elif fails:
        verdict = "problems"
    elif statuses & {"not_tested", "partial", "not_recorded"}:
        verdict = "incomplete"
    else:
        verdict = "ok"
    return {"operation": o.label, "method": o.method, "path": o.path, "summary": o.op.get("summary") or "",
            "secured": o.secured, "excluded": excluded, "verdict": verdict, "counts": dict(counts),
            "tests": items}


def write(cov: dict, out: Path) -> None:
    (out / "coverage.json").write_text(json.dumps(cov, indent=2), encoding="utf-8")
    with open(out / "coverage.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["api", "overall", "test", "status", "requests", "failed", "reason"])
        for a in cov["apis"]:
            for t in a["tests"]:
                w.writerow([a["operation"], a["verdict"], t["test"], t["status"], t["requests"], t["failed"],
                            t["reason"]])
