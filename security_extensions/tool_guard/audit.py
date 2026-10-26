"""Append-only audit trail of every tool-guard decision."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    """Keeps records in memory for evaluation and optionally appends them as JSONL."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.records: list[dict[str, Any]] = []

    def write(self, record: dict[str, Any]) -> None:
        record = {"ts": time.time(), **record}
        self.records.append(record)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
