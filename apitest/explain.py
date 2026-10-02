"""Plain-language descriptions of what was tested and why something failed.

Schemathesis and ZAP speak in their own jargon ("negative_data_rejection", "coverage phase").
Everything shown to people goes through here first.
"""
from __future__ import annotations

import re

# Schemathesis phases, as people would say them
PHASES = {
    "probing": ("Capability probe", "Checks a few basics about the server before testing."),
    "examples": ("Swagger examples", "Sends the example values written in the Swagger and checks the API accepts them."),
    "coverage": ("Edge cases", "Deliberately chosen tricky inputs, one at a time: minimum/maximum values, empty "
                               "strings, a missing required field or header, a value of the wrong type, an HTTP "
                               "method the API doesn't support."),
    "fuzzing": ("Random data", "Many randomly generated requests, some valid and some invalid on purpose, to find "
                               "inputs that crash the API or get an answer the Swagger doesn't allow."),
    "stateful": ("Request chains", "Chains of calls that use each other's results (e.g. create something, then "
                                   "fetch it with the returned ID)."),
}

STAGES = {
    "lint": ("Swagger quality", "Checks the Swagger document itself against OpenAPI best-practice rules."),
    "conformance": ("Behaviour vs Swagger", "Sends many requests and checks every response against what the "
                                            "Swagger promises: status codes, response types, no server errors, "
                                            "and that invalid input is rejected."),
    "types": ("Wrong data types", "Takes a valid request and replaces one field at a time with a value of the "
                                  "wrong type (e.g. \"1\" for a number, \"yes\" for true/false). Each must be rejected."),
    "authz": ("Access control", "Calls protected APIs with no token and with a fake token (must be refused), "
                                "checks a second user can't read the first user's data, and looks for leaked "
                                "error details and missing security headers."),
    "zap": ("Security scan (OWASP ZAP)", "Attacks the APIs with common exploits (injection, header tricks, "
                                         "misconfiguration) and reports anything that looks vulnerable."),
}


def phase_label(phase: str) -> str:
    return PHASES.get(phase, (phase.capitalize() if phase else "Test", ""))[0]


def _clean(desc: str) -> str:
    """Make Schemathesis' generated-case descriptions readable."""
    d = desc.strip()
    d = re.sub(r"^- ", "", d, flags=re.M)
    d = d.replace("\n", "; ")
    d = re.sub(r"violates `(\w+)` at /properties/([\w.\-/]+)", lambda m: f"`{m[2]}` breaks its `{m[1]}` rule", d)
    d = re.sub(r"\(was (.+?), became (.+?)\)", r"(changed \1 → \2)", d)
    d = re.sub(r"([\w.\[\]\-]+): Incorrect type", r"`\1` has the wrong type", d)
    d = d.replace("Incorrect type", "has the wrong type")
    return d


def describe_case(phase: str, mode: str, description: str) -> str:
    """One readable line for a generated request."""
    head = phase_label(phase)
    desc = _clean(description or "")
    if desc.lower() in ("positive test case", "") and mode == "positive":
        return f"{head}: valid request"
    if not desc:
        return f"{head}: {'invalid request on purpose' if mode == 'negative' else 'generated request'}"
    if mode == "negative" and phase == "fuzzing":
        return f"{head}: invalid on purpose ({desc})"
    return f"{head}: {desc}"


def expected_for(mode: str) -> str:
    if mode == "negative":
        return "The API should refuse it with a 4xx error, because the request is invalid on purpose."
    return "The API should accept it without crashing and answer exactly as the Swagger describes."


CHECKS = {
    "not_a_server_error": lambda s: f"The server crashed (HTTP {s}). A server error is always a bug.",
    "status_code_conformance": lambda s: f"Answered HTTP {s}, which the Swagger doesn't list for this API. "
                                         "Either document it or don't return it.",
    "content_type_conformance": lambda s: "Answered with a Content-Type the Swagger doesn't list.",
    "response_headers_conformance": lambda s: "A response header that the Swagger requires was missing or wrong.",
    "response_schema_conformance": lambda s: "The response body doesn't match the Swagger (a field has the wrong "
                                             "type, is missing, or is null when it shouldn't be).",
    "negative_data_rejection": lambda s: f"Accepted invalid input (HTTP {s}). It should have refused it with a 4xx.",
    "positive_data_acceptance": lambda s: f"Refused a request that is valid according to the Swagger (HTTP {s}).",
    "missing_required_header": lambda s: f"Didn't refuse a request missing a required header (HTTP {s}).",
    "unsupported_method": lambda s: f"Answered an HTTP method this API doesn't support with HTTP {s}; "
                                    "the standard answer is 405 Method Not Allowed.",
    "ignored_auth": lambda s: f"Served the request although authentication was missing or invalid (HTTP {s}).",
    "use_after_free": lambda s: "Something that was deleted could still be fetched.",
    "ensure_resource_availability": lambda s: "Something that was just created couldn't be fetched afterwards.",
    "max_response_time": lambda s: "The response was slower than the allowed limit.",
}


def explain_check(name: str, status, failure: dict | None = None) -> str:
    if name in CHECKS:
        text = CHECKS[name](status if status is not None else "?")
    else:
        title = (failure or {}).get("title") or name.replace("_", " ")
        text = f"{title}."
    if name == "not_a_server_error" and failure:
        detail = _server_error_hint(failure.get("message") or "")
        if detail:
            text += f" Server said: {detail}"
    return text


def _server_error_hint(msg: str) -> str:
    m = re.search(r'"(?:message|detail|error)"\s*:\s*"([^"]{3,160})"', msg)
    return m[1] if m else ""


FINDING_TITLES = {
    "Server error": "The API crashes (HTTP 5xx) on some inputs",
    "Undocumented HTTP status code": "Returns status codes the Swagger doesn't list",
    "Unsupported methods": "Unsupported HTTP methods don't get 405 Method Not Allowed",
    "API accepted schema-violating request": "Accepts invalid input that the Swagger forbids",
    "API rejected schema-compliant request": "Refuses valid input",
    "Response violates schema": "Response body doesn't match the Swagger",
    "API accepts requests without authentication": "Works without login",
    "Missing header not rejected": "Doesn't refuse a request missing a required header",
    "Undocumented Content-Type": "Returns a Content-Type the Swagger doesn't list",
    "Missing Content-Type header": "Response has no Content-Type header",
    "Check failed": "A behaviour check failed",
}


def finding_title(title: str) -> str:
    return FINDING_TITLES.get(title.strip(), title)


def server_said(body: str | None) -> str:
    """Short 'what the server said' from an error body."""
    if not body:
        return ""
    m = re.search(r'"(?:detail|message|error|title)"\s*:\s*"([^"]{3,200})"', body)
    return m[1] if m else body.strip()[:160]
