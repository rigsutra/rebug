"""Runs the selected stages and writes reports. Shared by the CLI and the web UI."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .config import Config
from .models import StageResult, sev_rank
from .proc import Cancelled
from .report import write_reports
from .spec import METHODS, Spec, filter_operations, load_spec
from .stages import authz, conformance, lint, types, zap

STAGE_FUNCS = {"lint": lint.run, "conformance": conformance.run, "types": types.run,
               "authz": authz.run, "zap": zap.run}

Emit = Callable[[dict], None]


def run_pipeline(cfg: Config, emit: Emit = lambda e: None) -> list[StageResult]:
    """Run the stages. If cfg.cancel is set mid-run, the current stage is stopped, remaining stages
    are marked cancelled, a partial report is written, and a {"type": "cancelled"} event is emitted."""
    out = Path(cfg.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    emit({"type": "spec_loading", "spec": cfg.spec})
    spec = load_spec(cfg.spec, cfg.headers, cfg.timeout)
    if cfg.operations:
        spec = filter_operations(spec, cfg.operations)
    if cfg.exclude_paths:
        # Apply exclusions here, once, so every stage (including ZAP, which scans the whole
        # document it's given) skips them
        keep = [o.label for o in spec.operations if not any(re.search(p, o.path) for p in cfg.exclude_paths)]
        if not keep:
            raise ValueError("Exclude paths removed every operation; nothing to test")
        if len(keep) < len(spec.operations):
            spec = filter_operations(spec, keep)
    base = cfg.base_url or spec.base_url
    emit({"type": "spec", "version": spec.version, "operations": len(spec.operations), "base_url": base,
          "labels": [o.label for o in spec.operations]})

    results: list[StageResult] = []
    cancelled = False
    for name in cfg.stages:
        if cancelled or (cfg.cancel is not None and cfg.cancel.is_set()):
            cancelled = True
            results.append(StageResult(name, "cancelled", "Run stopped before this stage"))
            emit({"type": "stage_end", "stage": name, "status": "cancelled", "findings": 0,
                  "note": "not run", "duration": 0})
            continue
        emit({"type": "stage_start", "stage": name})
        t = time.time()
        try:
            res = STAGE_FUNCS[name](spec, cfg, out)
        except Cancelled:
            cancelled = True
            res = StageResult(name, "cancelled", "Stopped by user")
        except Exception as e:  # a broken stage must not hide the others
            res = StageResult(name, "error", f"{type(e).__name__}: {e}")
        res.duration = time.time() - t
        results.append(res)
        emit({"type": "stage_end", "stage": name, "status": res.status,
              "findings": len(res.findings), "note": res.note, "duration": res.duration})

    annotate(spec, base, results)
    write_reports(out, cfg.spec, base, results)
    emit({"type": "cancelled" if cancelled else "done", "report": str(out / "report.html")})
    return results


def _template_regex(path: str) -> re.Pattern:
    parts = re.split(r"({[^}]+})", path)
    return re.compile("^" + "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts) + "/?$")


def annotate(spec: Spec, base: str, results: list[StageResult]) -> None:
    """Fill Finding.operation ("GET /path") so findings can be shown per API."""
    labels = {o.label for o in spec.operations}
    by_regex = [(o, _template_regex(o.path)) for o in spec.operations]
    base_path = urlparse(base).path.rstrip("/") if base else ""
    for r in results:
        for f in r.findings:
            ep = f.endpoint or ""
            head = ep.split(" ")
            if len(head) >= 2 and head[0].lower() in METHODS:
                cand = f"{head[0].upper()} {head[1]}"
                if cand in labels:
                    f.operation = cand
                    continue
                url_path = urlparse(head[1]).path if head[1].startswith("http") else head[1].split("?")[0]
                if base_path and url_path.startswith(base_path):
                    url_path = url_path[len(base_path):] or "/"
                for o, rx in by_regex:  # concrete URLs (ZAP)
                    if o.method.upper() == head[0].upper() and rx.match(url_path):
                        f.operation = o.label
                        break
            elif ep.startswith("paths/"):  # Spectral JSON path: paths//items/{id}/get/...
                for o in spec.operations:
                    if ep == f"paths/{o.path}/{o.method}" or ep.startswith(f"paths/{o.path}/{o.method}/"):
                        f.operation = o.label
                        break


def failed(cfg: Config, results: list[StageResult]) -> bool:
    threshold = sev_rank(cfg.fail_on)
    return (any(sev_rank(f.severity) >= threshold for r in results for f in r.findings)
            or any(r.status == "error" for r in results))
