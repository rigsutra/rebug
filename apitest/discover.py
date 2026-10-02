"""Find the OpenAPI/Swagger document(s) of a running application.

Accepts any of:
  * the spec itself                     https://host/swagger/v1/swagger.json
  * a Swagger UI page                   https://host/swagger, https://host/api-docs
  * the application root / a base path  https://host, https://host/api

For a root URL the well-known locations of common frameworks are probed. For a Swagger UI
page the spec URL(s) are read from its config, or the spec embedded in swagger-ui-express's
init script is extracted.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import httpx
import yaml

SPEC_PATHS = [
    "/swagger/v1/swagger.json",      # ASP.NET Core Swashbuckle / NSwag
    "/swagger/v2/swagger.json",
    "/openapi/v1.json",              # ASP.NET Core 9+ Microsoft.AspNetCore.OpenApi
    "/swagger.json",
    "/openapi.json",                 # FastAPI, many Node setups
    "/openapi.yaml",
    "/api-docs.json",
    "/api-docs/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/docs/swagger.json",
    "/swagger/docs/v1",              # .NET Framework Swashbuckle 5
    "/v3/api-docs",                  # Spring springdoc
    "/v2/api-docs",                  # Spring springfox
]
UI_PATHS = ["/swagger", "/swagger/index.html", "/api-docs", "/api-docs/", "/docs", "/api/docs",
            "/swagger-ui/index.html", "/swagger-ui.html"]
UI_SCRIPTS = ["swagger-initializer.js", "swagger-ui-init.js", "index.js"]


def client_for(url: str, **kw) -> httpx.Client:
    """httpx client; for localhost it binds IPv4 so Windows doesn't spend ~2s per connection
    trying ::1 first (most dev servers listen on 127.0.0.1 only)."""
    if urlparse(url).hostname == "localhost":
        kw["transport"] = httpx.HTTPTransport(local_address="0.0.0.0")
    return httpx.Client(**kw)


def parse_spec(text: str) -> dict | None:
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths", {}), dict):
        return doc
    return None


def _extract_object(text: str, start: int) -> str | None:
    """Return the balanced {...} JSON object starting at text[start] (string-aware)."""
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def from_ui_text(page_url: str, text: str) -> tuple[dict | None, list[str]]:
    """Look inside Swagger UI HTML/JS for an embedded spec or for spec URLs."""
    m = re.search(r'"swaggerDoc"\s*:\s*\{', text)  # swagger-ui-express inlines the document
    if m:
        obj = _extract_object(text, m.end() - 1)
        if obj:
            doc = parse_spec(obj)
            if doc:
                return doc, []
    urls = []
    for m in re.finditer(r'(?<![\w$])url\s*:\s*["\']([^"\']+\.(?:json|ya?ml)[^"\']*|[^"\']*api-docs[^"\']*|[^"\']*swagger[^"\']*)["\']', text):
        urls.append(urljoin(page_url, m.group(1)))
    for m in re.finditer(r'"url"\s*:\s*"([^"]+)"', text):  # Swashbuckle: "urls":[{"url":"/swagger/v1/swagger.json",...}]
        u = m.group(1)
        if not u.startswith(("http://", "https://", "/", "./")) and not re.search(r"\.(json|ya?ml)\b", u):
            continue
        urls.append(urljoin(page_url, u))
    seen, out = set(), []
    for u in urls:
        if u not in seen and not u.endswith((".js", ".css", ".png")):
            seen.add(u)
            out.append(u)
    return None, out


def resolve_page(client: httpx.Client, page_url: str, text: str) -> tuple[dict | None, list[str]]:
    """Given a Swagger UI page, return (embedded spec, spec URLs), also checking its init scripts."""
    doc, urls = from_ui_text(page_url, text)
    if doc or urls:
        return doc, urls
    base = page_url if page_url.endswith("/") else page_url + "/"
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text)
    candidates = [urljoin(page_url, s) for s in scripts if any(s.endswith(n) for n in UI_SCRIPTS)]
    candidates += [urljoin(base, n) for n in UI_SCRIPTS]
    for js_url in dict.fromkeys(candidates):
        try:
            r = client.get(js_url)
        except httpx.HTTPError:
            continue
        if r.status_code == 200:
            doc, urls = from_ui_text(page_url, r.text)
            if doc or urls:
                return doc, urls
    return None, []


def _summary(url: str, doc: dict, embedded: bool) -> dict:
    ops = sum(1 for item in (doc.get("paths") or {}).values() if isinstance(item, dict)
              for m in item if m in ("get", "put", "post", "delete", "patch", "head", "options"))
    info = doc.get("info", {})
    return {"url": url, "embedded": embedded, "title": info.get("title", ""), "api_version": info.get("version", ""),
            "spec_version": "swagger2" if "swagger" in doc else "openapi3", "operations": ops}


def discover(url: str, headers: dict[str, str] | None = None, timeout: float = 8.0) -> dict:
    """Return {"specs": [...], "tried": [...]}. Each spec: url, title, api_version, spec_version, operations."""
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "http://" + url
    found: dict[str, dict] = {}
    tried: list[str] = []
    with client_for(url, headers=headers or {}, timeout=timeout, follow_redirects=True) as c:

        def probe(u: str) -> None:
            tried.append(u)
            try:
                r = c.get(u)
            except httpx.HTTPError:
                return
            if r.status_code != 200:
                return
            doc = parse_spec(r.text)
            if doc:
                found.setdefault(str(r.url), _summary(str(r.url), doc, False))
                return
            if "html" in r.headers.get("content-type", "") or "<html" in r.text[:500].lower():
                emb, urls = resolve_page(c, str(r.url), r.text)
                if emb:
                    found.setdefault(str(r.url), _summary(str(r.url), emb, True))
                for su in urls:
                    try:
                        rr = c.get(su)
                    except httpx.HTTPError:
                        continue
                    d = parse_spec(rr.text) if rr.status_code == 200 else None
                    if d:
                        found.setdefault(str(rr.url), _summary(str(rr.url), d, False))

        probe(url)
        if not found:
            u = urlparse(url)
            root = f"{u.scheme}://{u.netloc}"
            prefix = u.path.rstrip("/")
            bases = [root + prefix, root] if prefix else [root]
            cands = list(dict.fromkeys(b + p for b in bases for p in SPEC_PATHS + UI_PATHS))
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(probe, cands))
    return {"specs": sorted(found.values(), key=lambda s: -s["operations"]), "tried": len(tried)}
