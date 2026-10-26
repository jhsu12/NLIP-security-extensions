"""Catalog check: inspect MCP tool metadata before the model ever sees it.

Two defenses against malicious MCP servers:
- description scanning: instructions hidden in a tool description (tool poisoning) are
  removed, keeping the part that documents the tool;
- pinning: the first description seen for each (server, tool) is hashed, and a tool whose
  description later changes (a rug pull) is withheld from the model.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

import yaml

from .scanner import ResultScanner


@dataclass(slots=True)
class CatalogDecision:
    tool_name: str
    # "allow" (unchanged), "replace" (description sanitized), or "drop" (withheld).
    action: str
    description: str | None
    reason: str
    flagged: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CatalogReport:
    decisions: list[CatalogDecision]
    latency_ms: float = 0.0
    judge_calls: int = 0
    judge_tokens: int = 0

    @property
    def flagged(self) -> list[str]:
        return [snippet for decision in self.decisions for snippet in decision.flagged]


class CatalogChecker:
    def __init__(self, scanner: ResultScanner, *, pin: bool = True) -> None:
        self.scanner = scanner
        self.pin = pin
        self._pins: dict[tuple[str, str], str] = {}

    async def inspect(self, server_id: str, tools: Sequence[tuple[str, str]]) -> CatalogReport:
        started = time.perf_counter()
        decisions: dict[str, CatalogDecision] = {}
        to_scan: dict[str, str] = {}
        for name, description in tools:
            digest = hashlib.sha256(description.encode("utf-8")).hexdigest()
            pinned = self._pins.get((server_id, name))
            if self.pin and pinned is not None and pinned != digest:
                decisions[name] = CatalogDecision(
                    name, "drop", None, "description changed since it was first approved (possible rug pull)"
                )
                continue
            self._pins.setdefault((server_id, name), digest)
            to_scan[name] = description

        # One scan over all descriptions, so the judge sees them in a single batch.
        scan = await self.scanner.scan(yaml.safe_dump(to_scan, sort_keys=False, allow_unicode=True))
        cleaned = yaml.safe_load(scan.sanitized) if scan.sanitized else to_scan
        for name, description in to_scan.items():
            new = cleaned.get(name, description)
            flagged = [snippet for snippet in scan.flagged if _from(snippet, description)]
            if new != description:
                decisions[name] = CatalogDecision(
                    name, "replace", new, "description contained instructions beyond documenting the tool", flagged
                )
            else:
                decisions[name] = CatalogDecision(name, "allow", description, "no hidden instructions found")
        return CatalogReport(
            decisions=[decisions[name] for name, _ in tools],
            latency_ms=(time.perf_counter() - started) * 1000,
            judge_calls=scan.judge_calls,
            judge_tokens=scan.judge_tokens,
        )


def _from(snippet: str, description: str) -> bool:
    """Whether a flagged snippet (possibly re-joined paragraphs) came from this description."""
    lines = [line.strip() for line in snippet.splitlines() if line.strip()]
    return bool(lines) and all(line in description for line in lines)
