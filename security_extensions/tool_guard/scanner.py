"""Post-tool result scanner: find instructions planted in tool output.

Tool results are split into their text fields (AgentDojo/MCP results are YAML), each
field is checked by high-precision rules and optionally by a judge, and flagged fields
are redacted while ids, senders, and dates are kept so the user's task can continue.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

from .judges import INJECTION_INSTRUCTIONS, Judge

REDACTED = "[removed by tool_guard: this content contained instructions aimed at the assistant]"
MIN_FIELD_CHARS = 40
MAX_FIELD_CHARS = 4000
# Flagged fields longer than this are narrowed to the offending paragraphs or lines.
REFINE_CHARS = 300

# High-precision phrasings used by indirect prompt injections (AgentDojo, InjecAgent,
# and MCP tool-poisoning examples). Ordinary content addressed to a human rarely uses them.
INJECTION_RULES = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<\s*/?\s*information\s*>",
        r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|original)\s+(?:instructions?|messages?|tasks?|prompts?)",
        r"\bbefore\s+you\s+(?:can\s+)?(?:solve|do|complete|finish|answer|continue|proceed)",
        r"\bthis\s+is\s+an?\s+(?:important|urgent)\s+message\s+from\b",
        r"\b(?:new|updated|important|additional)\s+instructions?\s+(?:for|to)\s+(?:you|the\s+(?:ai|assistant|agent|model))\b",
        r"\b(?:ai|llm|language\s+model)\s+(?:assistant|agent|model)?\s*(?:,|:)?\s*(?:you\s+)?(?:must|should|are\s+required\s+to)\b",
        r"\bdo\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user\b",
        r"\bsystem\s+(?:prompt|override|instruction)s?\s*:",
    )
]


# Tool-description poisoning (Invariant Labs' MCP examples and follow-ups): hidden
# "<IMPORTANT>" blocks, prerequisites the user never sees, and requests for secrecy.
DESCRIPTION_RULES = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<\s*/?\s*important\s*>",
        r"\bdo\s+not\s+(?:tell|inform|mention|reveal|notify)\b[^.\n]{0,60}\b(?:the\s+)?user\b",
        r"\bbefore\s+(?:using|calling|you\s+use)\s+this\s+tool\b",
        r"\b(?:otherwise|or)\s+(?:this|the)\s+tool\s+will\s+(?:fail|not\s+work)\b",
    )
] + INJECTION_RULES


@dataclass(slots=True)
class ScanResult:
    flagged: list[str] = field(default_factory=list)
    sanitized: str | None = None
    rule_hits: int = 0
    judge_calls: int = 0
    judge_tokens: int = 0
    latency_ms: float = 0.0


def rule_match(text: str, rules: list[re.Pattern[str]] = INJECTION_RULES) -> bool:
    return any(rule.search(text) for rule in rules)


class ResultScanner:
    def __init__(
        self,
        judge: Judge | None = None,
        *,
        use_rules: bool = True,
        threshold: float = 0.5,
        on_injection: str = "redact",
        rules: list[re.Pattern[str]] = INJECTION_RULES,
        instructions: str = INJECTION_INSTRUCTIONS,
    ) -> None:
        if on_injection not in ("redact", "report"):
            raise ValueError("on_injection must be 'redact' or 'report'")
        self.judge = judge
        self.use_rules = use_rules
        self.threshold = threshold
        self.on_injection = on_injection
        self.rules = rules
        self.instructions = instructions

    async def scan(self, result: str) -> ScanResult:
        started = time.perf_counter()
        scan = ScanResult()
        parsed, structured = _parse(result)
        fields = [text for text in _text_fields(parsed) if len(text) >= MIN_FIELD_CHARS] if structured else [result]
        flagged_fields = await self._detect(list(dict.fromkeys(fields)), scan)

        # A long field (e.g. a whole file) is narrowed down to the paragraphs or lines
        # that carry the injection, so the rest of it stays usable for the user's task.
        replacements: dict[str, str] = {}
        for text in flagged_fields:
            segments = _segments(text) if len(text) > REFINE_CHARS else []
            bad = set(await self._detect(segments, scan)) if len(segments) > 1 else set()
            if bad:
                # Injections span several paragraphs (tags, framing, the goal itself) and
                # not every piece trips a detector, so remove the whole span between the
                # first and last flagged segment.
                indexes = [index for index, segment in enumerate(segments) if segment in bad]
                first, last = indexes[0], indexes[-1]
                scan.flagged.append("\n".join(segments[first : last + 1]))
                replacements[text] = "\n".join([*segments[:first], REDACTED, *segments[last + 1 :]])
            else:
                scan.flagged.append(text)
                replacements[text] = REDACTED

        if replacements and self.on_injection == "redact":
            if structured:
                cleaned = _redact(parsed, replacements)
                scan.sanitized = yaml.safe_dump(cleaned, sort_keys=False, allow_unicode=True).strip()
            else:
                scan.sanitized = replacements[result]
        scan.latency_ms = (time.perf_counter() - started) * 1000
        return scan

    async def _detect(self, texts: list[str], scan: ScanResult) -> list[str]:
        """Return the texts that carry injected instructions, in input order."""
        if not texts:
            return []
        flagged = set()
        if self.use_rules:
            hits = {text for text in texts if rule_match(text, self.rules)}
            scan.rule_hits += len(hits)
            flagged |= hits
        if self.judge is not None:
            remaining = [text for text in texts if text not in flagged]
            if remaining:
                scores, tokens = await self.judge.detect_injection(
                    [text[:MAX_FIELD_CHARS] for text in remaining], self.instructions
                )
                scan.judge_calls += 1
                scan.judge_tokens += tokens
                flagged |= {text for text, score in zip(remaining, scores) if score >= self.threshold}
        return [text for text in texts if text in flagged]


def _parse(result: str) -> tuple[Any, bool]:
    try:
        parsed = yaml.safe_load(result)
    except yaml.YAMLError:
        return result, False
    return parsed, isinstance(parsed, (dict, list))


def _text_fields(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _text_fields(item)
    elif isinstance(value, list):
        for item in value:
            yield from _text_fields(item)


def _segments(text: str) -> list[str]:
    """Paragraphs if the text has them, otherwise lines; blank pieces dropped."""
    paragraphs = [part.strip("\n") for part in re.split(r"\n\s*\n", text) if part.strip()]
    if len(paragraphs) > 1:
        return paragraphs
    return [line for line in text.splitlines() if line.strip()]


def _redact(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, dict):
        return {key: _redact(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, replacements) for item in value]
    return value
