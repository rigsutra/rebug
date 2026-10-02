from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

ALL_STAGES = ["lint", "conformance", "types", "authz", "zap"]


@dataclass
class Config:
    spec: str = ""
    base_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)  # user A
    headers_b: dict[str, str] = field(default_factory=dict)  # user B, for BOLA
    stages: list[str] = field(default_factory=lambda: list(ALL_STAGES))
    max_examples: int = 50
    fail_on: str = "high"
    out_dir: str = "reports"
    no_mutating_authz: bool = False
    exclude_paths: list[str] = field(default_factory=list)
    bola: list[dict] = field(default_factory=list)
    timeout: float = 15.0
    types_max_fields: int = 60  # per operation, for the wrong-type probing stage
    operations: list[str] = field(default_factory=list)  # "GET /path" to test; empty = all
    title: str = ""  # shown in reports (the project name in the web UI)
    cancel: threading.Event | None = field(default=None, repr=False, compare=False)
    on_progress: Callable[[dict], None] | None = field(default=None, repr=False, compare=False)
    testlog: object | None = field(default=None, repr=False, compare=False)  # testlog.TestLog, set by the runner
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"


ENV_REF = re.compile(r"\$\{(\w+)\}")


def expand_env(value: str) -> str:
    """Replace ${VAR} with the environment variable's value (so tokens can stay out of config files)."""
    def sub(m):
        if m.group(1) not in os.environ:
            raise ValueError(f"Environment variable {m.group(1)} is not set")
        return os.environ[m.group(1)]
    return ENV_REF.sub(sub, value)


def parse_header(h: str) -> tuple[str, str]:
    name, _, value = h.partition(":")
    if not value:
        raise ValueError(f"Header must look like 'Name: value', got {h!r}")
    return name.strip(), value.strip()


def load_config(path: str | None) -> Config:
    if not path:
        return Config()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    cfg = Config()
    for k, v in data.items():
        if not hasattr(cfg, k) or k == "cancel":
            raise ValueError(f"Unknown config key: {k}")
        setattr(cfg, k, v)
    cfg.headers = {k: expand_env(str(v)) for k, v in (cfg.headers or {}).items()}
    cfg.headers_b = {k: expand_env(str(v)) for k, v in (cfg.headers_b or {}).items()}
    return cfg
