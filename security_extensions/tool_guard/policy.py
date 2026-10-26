"""Deterministic privilege policy: the fast first layer (Progent-style).

Each tool has a risk class. The policy settles what it can decide from structure
alone and escalates the rest to the judge. Each escalation also carries a
``fallback`` decision, used when the guard runs with no judge (policy-only mode).
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .session import EMAIL_PATTERN, GuardSession, extract_indicators


class Risk(str, Enum):
    READ = "read"
    WRITE_INTERNAL = "write_internal"
    EXTERNAL_SEND = "external_send"
    DESTRUCTIVE = "destructive"


class Outcome(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    outcome: Outcome
    reason: str
    risk: Risk | None
    fallback: Outcome = Outcome.BLOCK


@dataclass(frozen=True, slots=True)
class ToolRule:
    risk: Risk
    address_args: tuple[str, ...] = ()


@dataclass(slots=True)
class Policy:
    tools: dict[str, ToolRule]
    unknown_tool: Outcome = Outcome.BLOCK
    trusted_domains: tuple[str, ...] = ()
    destructive_intent: tuple[str, ...] = field(default_factory=tuple)
    # False keeps only the read/side-effect split and escalates every side-effecting
    # call to the judge (the "judge only" ablation).
    rules: bool = True

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with Path(path).open("rb") as policy_file:
            data = tomllib.load(policy_file)
        defaults = data.get("defaults", {})
        tools = {
            name: ToolRule(Risk(rule["risk"]), tuple(rule.get("address_args", ())))
            for name, rule in data.get("tools", {}).items()
        }
        return cls(
            tools=tools,
            unknown_tool=Outcome(defaults.get("unknown_tool", "block")),
            trusted_domains=tuple(domain.casefold() for domain in defaults.get("trusted_domains", ())),
            destructive_intent=tuple(word.casefold() for word in defaults.get("destructive_intent", ())),
        )

    def risk_of(self, tool_name: str) -> Risk | None:
        rule = self.tools.get(tool_name)
        return rule.risk if rule else None

    def evaluate(self, tool_name: str, arguments: dict[str, Any], session: GuardSession) -> PolicyDecision:
        rule = self.tools.get(tool_name)
        if rule is None:
            if self.unknown_tool is Outcome.BLOCK:
                return PolicyDecision(Outcome.BLOCK, f"tool {tool_name!r} is not in the policy", None)
            return PolicyDecision(Outcome.ESCALATE, f"tool {tool_name!r} is not in the policy", None)

        if rule.risk is Risk.READ:
            return PolicyDecision(Outcome.ALLOW, "read-only tool", rule.risk, Outcome.ALLOW)
        if not self.rules:
            return PolicyDecision(Outcome.ESCALATE, f"{rule.risk.value} action", rule.risk, Outcome.ALLOW)

        # Provenance: a value the attacker planted in flagged content, which the user
        # never mentioned, must not flow into a side-effecting call.
        user_indicators = session.user_indicators()
        planted = sorted(
            indicator
            for indicator in extract_indicators(" ".join(_strings(arguments)))
            if indicator in session.tainted_indicators and indicator not in user_indicators
        )
        if planted:
            return PolicyDecision(
                Outcome.BLOCK,
                f"argument uses {', '.join(planted)}, which only appeared in injected tool content",
                rule.risk,
            )

        if rule.risk is Risk.DESTRUCTIVE:
            user_text = session.user_text.casefold()
            if not any(word in user_text for word in self.destructive_intent):
                return PolicyDecision(
                    Outcome.BLOCK, "destructive action, but the user never asked to delete or cancel", rule.risk
                )
            return PolicyDecision(Outcome.ESCALATE, "destructive action the user asked for", rule.risk, Outcome.ALLOW)

        unknown = sorted(
            address
            for address in self._addresses(arguments, rule.address_args)
            if address not in user_indicators and not self._trusted(address)
        )
        if unknown:
            return PolicyDecision(
                Outcome.ESCALATE,
                f"recipient(s) not named by the user: {', '.join(unknown)}",
                rule.risk,
                Outcome.BLOCK,
            )
        return PolicyDecision(Outcome.ESCALATE, f"{rule.risk.value} action", rule.risk, Outcome.ALLOW)

    def _trusted(self, address: str) -> bool:
        domain = address.rpartition("@")[2]
        return any(domain == trusted or domain.endswith("." + trusted) for trusted in self.trusted_domains)

    @staticmethod
    def _addresses(arguments: dict[str, Any], names: tuple[str, ...]) -> set[str]:
        found: set[str] = set()
        for name in names:
            for value in _strings(arguments.get(name)):
                found |= {match.casefold() for match in EMAIL_PATTERN.findall(value)}
                # A bare name (no @) in an address field is still an unverified recipient.
                if value and "@" not in value:
                    found.add(value.casefold())
        return found


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
