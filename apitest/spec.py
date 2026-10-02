"""Fetch a Swagger/OpenAPI document and extract what the stages need."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
import yaml

METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


@dataclass
class Operation:
    method: str
    path: str
    secured: bool
    has_body: bool
    path_params: dict[str, str] = field(default_factory=dict)  # name -> placeholder
    query_params: dict[str, str] = field(default_factory=dict)  # required only
    op: dict = field(default_factory=dict, repr=False)  # raw operation object
    params: list[dict] = field(default_factory=list, repr=False)  # resolved path+operation params

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Spec:
    raw: dict
    source: str
    version: str  # "swagger2" | "openapi3"
    base_url: str
    operations: list[Operation]
    text: str = ""       # document the stages test (reduced when operations are selected)
    full_text: str = ""  # whole document, for lint
    filtered: bool = False
    from_page: bool = False  # resolved from a Swagger UI page rather than fetched directly


def _load_text(source: str, headers: dict[str, str], timeout: float) -> tuple[str, dict | None, str, bool]:
    """Return (text, parsed doc, effective URL, from_page)."""
    from .discover import client_for, parse_spec, resolve_page
    if not re.match(r"^https?://", source):
        text = Path(source).read_text(encoding="utf-8")
        return text, parse_spec(text), source, False
    with client_for(source, headers=headers, timeout=timeout, follow_redirects=True) as c:
        r = c.get(source)
        r.raise_for_status()
        doc = parse_spec(r.text)
        if doc is not None:
            return r.text, doc, source, False
        # Not a spec: maybe a Swagger UI page. Use its embedded spec or the first spec URL it references.
        emb, urls = resolve_page(c, str(r.url), r.text)
        if emb is not None:
            return json.dumps(emb), emb, str(r.url), True
        for u in urls:
            rr = c.get(u)
            d = parse_spec(rr.text) if rr.status_code == 200 else None
            if d is not None:
                return rr.text, d, u, True
    return r.text, None, source, False


def filter_operations(spec: "Spec", labels: list[str]) -> "Spec":
    """Reduce the spec to the given "METHOD /path" operations (components are kept)."""
    want = {l.strip().upper().split(" ", 1)[0] + " " + l.strip().split(" ", 1)[1] for l in labels if " " in l.strip()}
    raw = json.loads(json.dumps(spec.raw))
    for path in list(raw.get("paths", {})):
        item = raw["paths"][path]
        for m in [k for k in item if k in METHODS]:
            if f"{m.upper()} {path}" not in want:
                del item[m]
        if not any(k in METHODS for k in item):
            del raw["paths"][path]
    ops = [o for o in spec.operations if o.label in want]
    missing = want - {o.label for o in ops}
    if missing:
        raise ValueError(f"Operation(s) not in the spec: {', '.join(sorted(missing))}")
    return Spec(raw, spec.source, spec.version, spec.base_url, ops, json.dumps(raw),
                spec.full_text or spec.text, True, spec.from_page)


def resolve(raw: dict, node):
    return _resolve(raw, node)


def _resolve(raw: dict, node):
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return node
        cur = raw
        for part in ref[2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~"), {})
        node = cur
        seen += 1
    return node


def _placeholder(p: dict) -> str:
    schema = p.get("schema", p)
    t, fmt = schema.get("type"), schema.get("format")
    if "enum" in schema and schema["enum"]:
        return str(schema["enum"][0])
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000001"
    if t in ("integer", "number"):
        return "1"
    if t == "boolean":
        return "true"
    return "1"


def _is_secured(sec) -> bool:
    return bool(sec) and all(bool(s) for s in sec)


def _derive_base_url(raw: dict, source: str) -> str:
    if "openapi" in raw:
        servers = raw.get("servers") or []
        if servers:
            url = servers[0].get("url", "/")
            if re.match(r"^https?://", url):
                return url.rstrip("/")
            if re.match(r"^https?://", source):  # relative server URL: resolve against spec URL
                return urljoin(source, url).rstrip("/")
            return ""  # relative URL in a local file: caller must pass --base-url
    else:
        host = raw.get("host")
        if host:
            scheme = (raw.get("schemes") or ["https"])[0]
            return f"{scheme}://{host}{raw.get('basePath', '')}".rstrip("/")
    if re.match(r"^https?://", source):
        u = urlparse(source)
        return f"{u.scheme}://{u.netloc}"
    return ""


def load_spec(source: str, headers: dict[str, str] | None = None, timeout: float = 15.0) -> Spec:
    text, raw, effective, from_page = _load_text(source, headers or {}, timeout)
    if raw is None:
        raise ValueError("Not a Swagger 2.0 / OpenAPI 3.x document, and no spec found on that page. "
                         "Use 'Discover' with the application's root URL.")
    version = "openapi3" if "openapi" in raw else "swagger2"
    ops: list[Operation] = []
    global_sec = raw.get("security")
    for path, item in (raw.get("paths") or {}).items():
        item = _resolve(raw, item) or {}
        shared = [_resolve(raw, p) for p in item.get("parameters", [])]
        for method, op in item.items():
            if method not in METHODS or not isinstance(op, dict):
                continue
            params = shared + [_resolve(raw, p) for p in op.get("parameters", [])]
            path_params = {p["name"]: _placeholder(p) for p in params if p.get("in") == "path"}
            for name in re.findall(r"{(\w+)}", path):
                path_params.setdefault(name, "1")
            query = {
                p["name"]: _placeholder(p)
                for p in params
                if p.get("in") == "query" and p.get("required")
            }
            has_body = "requestBody" in op or any(p.get("in") == "body" for p in params)
            sec = op["security"] if "security" in op else global_sec
            ops.append(Operation(method, path, _is_secured(sec), has_body, path_params, query, op, params))
    return Spec(raw, source, version, _derive_base_url(raw, effective), ops, text, text, False, from_page)
