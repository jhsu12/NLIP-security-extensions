"""Per-NLIP-session state recorded by the tool guard itself (never by the agent)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_PATTERN = re.compile(r"https?://[^\s'\"<>)]+|www\.[^\s'\"<>)]+")


def extract_indicators(text: str) -> set[str]:
    """Email addresses and URLs, lower-cased: the values an attacker needs to plant."""
    return {match.casefold().rstrip(".,;") for match in EMAIL_PATTERN.findall(text)} | {
        match.casefold().rstrip(".,;") for match in URL_PATTERN.findall(text)
    }


@dataclass(slots=True)
class CallRecord:
    tool_name: str
    arguments: Any
    action: str
    call_id: str | None = None
    # What the model saw: the (possibly redacted) result text.
    result_text: str = ""


@dataclass(slots=True)
class GuardSession:
    """What the guard knows about one conversation.

    ``user_turns`` come from NLIP ingress, so they are the only trusted statement of
    the user's task. Everything a tool returns is untrusted.
    """

    session_id: str
    user_id: str | None = None
    user_turns: list[str] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    tainted: bool = False
    # Indicators (addresses, URLs) seen inside content flagged as injected instructions.
    tainted_indicators: set[str] = field(default_factory=set)
    flagged_snippets: list[str] = field(default_factory=list)

    @property
    def user_text(self) -> str:
        return "\n".join(self.user_turns)

    def user_indicators(self) -> set[str]:
        return extract_indicators(self.user_text)

    def taint(self, snippets: list[str], *, exposed: bool = True) -> None:
        """Record injected content. ``exposed`` means the model may have read it, which
        raises the judge threshold; content removed before the model saw it (e.g. from a
        tool description) only contributes its planted addresses and URLs."""
        self.tainted = self.tainted or exposed
        for snippet in snippets:
            self.flagged_snippets.append(snippet[:500])
            self.tainted_indicators |= extract_indicators(snippet)


def evidence_lines(arguments: Any, results: list[str], *, limit: int = 12, width: int = 300) -> list[str]:
    """Lines of earlier tool output that mention the call's targets.

    Lets the judge check where a recipient or id came from (e.g. a name in a file the
    user pointed to) without sending it every full result.
    """
    # Most specific first: exact addresses and ids, then full names, then first names.
    tiers: list[set[str]] = [set(), set(), set()]
    for key, value in _flatten(arguments):
        text = str(value)
        for address in EMAIL_PATTERN.findall(text):
            local = address.split("@")[0].casefold()
            tiers[0].add(address.casefold())
            parts = [part for part in re.split(r"[._-]", local) if part.isalpha()]
            if len(parts) >= 2:
                tiers[1].add(" ".join(parts))
            if parts and len(parts[0]) >= 3:
                tiers[2].add(parts[0])
        if key.endswith("id") and text:
            tiers[0].add(text.casefold())
    lines = [line.strip() for result in results for line in result.splitlines() if line.strip()]
    found: list[str] = []
    for terms in tiers:
        for line in lines:
            if len(found) >= limit:
                return found
            folded = line.casefold()
            if line[:width] not in found and any(_mentions(folded, term) for term in terms):
                found.append(line[:width])
    return found


def _mentions(line: str, term: str) -> bool:
    return re.search(rf"(?<![\w]){re.escape(term)}(?![\w])", line) is not None


def _flatten(value: Any, key: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        return [pair for name, item in value.items() for pair in _flatten(item, str(name))]
    if isinstance(value, (list, tuple)):
        return [pair for item in value for pair in _flatten(item, key)]
    return [(key, value)]


class GuardSessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, GuardSession] = {}

    def get(self, session_id: str) -> GuardSession | None:
        return self._sessions.get(session_id)

    def get_or_create(self, session_id: str) -> GuardSession:
        session = self._sessions.get(session_id)
        if session is None:
            session = self._sessions[session_id] = GuardSession(session_id)
        return session

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
