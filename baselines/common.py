from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


@dataclass
class BaselineSetup:
    pre_run_memory_building_ms: float = 0.0
    disk_overhead_bytes: int = 0
    state: Optional[Dict[str, Any]] = None


@dataclass
class BaselineAdapter:
    name: str
    role: str
    setup: Callable
    teardown: Callable
    session_setup: Callable
    prepare_query: Callable
    captures_notices: bool = False
