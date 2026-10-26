"""ToolGuard: the Type-3 security function invoked around every tool call.

Layers, cheapest first:
  L0 validation  structural checks, and a trusted user task must exist (fail closed)
  L1 policy      per-tool risk class, recipient and provenance rules
  L2 judge       task alignment, only for calls the policy escalates
  L3 scanner     post-tool: redact injected instructions and taint the session;
                 while tainted, escalated calls must clear a higher threshold
  catalog        at tools/list: strip instructions hidden in tool descriptions and
                 withhold tools whose description changed (rug pull)

The guard is framework-agnostic. ``nlip_extension`` feeds it the user's task from NLIP
ingress; ``langchain_middleware`` calls it around tool execution.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .catalog import CatalogChecker
from .events import Layer, ToolAction, ToolCallEvent, ToolResultEvent, ToolVerdict
from .judges import TOOL_DESCRIPTION_INSTRUCTIONS, Judge, JudgeInput, build_judge
from .policy import Outcome, Policy
from .scanner import DESCRIPTION_RULES, REDACTED, ResultScanner
from .session import CallRecord, GuardSessionStore, evidence_lines

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = PACKAGE_DIR / "policies" / "workspace.toml"


@dataclass(slots=True)
class GuardConfig:
    threshold: float = 0.5
    tainted_threshold: float = 0.7
    taint: bool = True
    context_calls: int = 6
    preview_chars: int = 1500


class ToolGuard:
    def __init__(
        self,
        policy: Policy,
        *,
        judge: Judge | None = None,
        scanner: ResultScanner | None = None,
        catalog: CatalogChecker | None = None,
        config: GuardConfig | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.policy = policy
        self.judge = judge
        self.scanner = scanner
        self.catalog = catalog
        self.config = config or GuardConfig()
        self.audit = audit or AuditLog()
        self.sessions = GuardSessionStore()

    @classmethod
    def from_options(
        cls,
        *,
        policy: str | None = None,
        policy_rules: bool = True,
        judge: str = "d3",
        judge_model: str | None = None,
        threshold: float = 0.5,
        tainted_threshold: float = 0.7,
        taint: bool = True,
        scanner: str = "rules+judge",
        injection_threshold: float = 0.5,
        on_injection: str = "redact",
        catalog: str = "off",
        catalog_judge: str | None = None,
        audit_path: str | None = None,
    ) -> "ToolGuard":
        """Build from ``[security_extensions.<name>.options]`` in config.toml."""
        judge_instance = build_judge(judge, judge_model)
        modes = set(scanner.split("+")) - {"off", ""}
        if modes - {"rules", "judge"}:
            raise ValueError(f"unknown scanner mode {scanner!r}")
        result_scanner = None
        if modes:
            result_scanner = ResultScanner(
                judge_instance if "judge" in modes else None,
                use_rules="rules" in modes,
                threshold=injection_threshold,
                on_injection=on_injection,
            )
        catalog_modes = set(catalog.split("+")) - {"off", ""}
        if catalog_modes - {"rules", "judge"}:
            raise ValueError(f"unknown catalog mode {catalog!r}")
        catalog_checker = None
        if catalog_modes:
            # The catalog detector can differ from the call judge (e.g. calls unchecked,
            # descriptions checked by d3 in the catalog-only ablation).
            catalog_detector = build_judge(catalog_judge, None) if catalog_judge else judge_instance
            catalog_checker = CatalogChecker(
                ResultScanner(
                    catalog_detector if "judge" in catalog_modes else None,
                    use_rules="rules" in catalog_modes,
                    threshold=injection_threshold,
                    rules=DESCRIPTION_RULES,
                    instructions=TOOL_DESCRIPTION_INSTRUCTIONS,
                )
            )
        loaded_policy = Policy.load(_resolve(policy) if policy else DEFAULT_POLICY)
        loaded_policy.rules = policy_rules
        return cls(
            loaded_policy,
            judge=judge_instance,
            scanner=result_scanner,
            catalog=catalog_checker,
            config=GuardConfig(threshold=threshold, tainted_threshold=tainted_threshold, taint=taint),
            audit=AuditLog(audit_path),
        )

    # NLIP ingress/egress hooks -------------------------------------------------------

    def begin_turn(self, session_id: str, user_text: str, user_id: str | None = None) -> None:
        session = self.sessions.get_or_create(session_id)
        session.user_turns.append(user_text)
        if user_id:
            session.user_id = user_id
        self.audit.write({"point": "ingress", "session": session_id, "user_text": user_text, "user_id": user_id})

    def end_turn(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session is not None:
            self.audit.write(
                {"point": "egress", "session": session_id, "tainted": session.tainted, "calls": len(session.calls)}
            )

    # Tool catalog ---------------------------------------------------------------------

    async def inspect_catalog(
        self, session_id: str, server_id: str, tools: list[tuple[str, str]]
    ) -> dict[str, str | None]:
        """Return the description the model may see for each tool (None = withhold it)."""
        if self.catalog is None:
            return {name: description for name, description in tools}
        started = time.perf_counter()
        try:
            report = await self.catalog.inspect(server_id, tools)
        except Exception as error:
            # Fail closed: tools whose metadata could not be checked are not offered.
            self.audit.write(
                {"point": "catalog", "session": session_id, "server": server_id, "action": "block",
                 "reason": f"catalog check failed ({type(error).__name__}: {error})",
                 "latency_ms": (time.perf_counter() - started) * 1000}
            )
            return {name: None for name, _ in tools}
        session = self.sessions.get_or_create(session_id)
        if report.flagged and self.config.taint:
            # The injected text is stripped before the model sees the catalog, so only
            # the values it planted are remembered; the judge threshold is unchanged.
            session.taint(report.flagged, exposed=False)
        changed = [decision for decision in report.decisions if decision.action != "allow"]
        self.audit.write(
            {
                "point": "catalog",
                "session": session_id,
                "server": server_id,
                "action": "replace" if changed else "allow",
                "reason": f"{len(changed)} of {len(report.decisions)} tool descriptions changed or withheld",
                "tools": {d.tool_name: {"action": d.action, "reason": d.reason} for d in changed},
                "flagged": [snippet[:200] for snippet in report.flagged],
                "latency_ms": report.latency_ms,
                "judge_calls": report.judge_calls,
                "judge_tokens": report.judge_tokens,
            }
        )
        return {decision.tool_name: decision.description for decision in report.decisions}

    # Tool boundary --------------------------------------------------------------------

    async def before_tool_call(self, event: ToolCallEvent) -> ToolVerdict:
        started = time.perf_counter()
        verdict = await self._decide(event)
        verdict.latency_ms = (time.perf_counter() - started) * 1000
        session = self.sessions.get(event.session_id)
        if session is not None:
            session.calls.append(CallRecord(event.tool_name, event.arguments, verdict.action.value, event.call_id))
        self.audit.write(
            {
                "point": "pre_tool",
                "session": event.session_id,
                "server": event.server_id,
                "tool": event.tool_name,
                "arguments": event.arguments,
                "call_id": event.call_id,
                **verdict.to_dict(),
            }
        )
        return verdict

    async def _decide(self, event: ToolCallEvent) -> ToolVerdict:
        session = self.sessions.get(event.session_id)
        if session is None or not session.user_turns:
            return ToolVerdict(ToolAction.BLOCK, "no trusted user task was recorded at NLIP ingress", Layer.VALIDATION)
        if not event.tool_name:
            return ToolVerdict(ToolAction.BLOCK, "tool name is empty", Layer.VALIDATION)
        if not isinstance(event.arguments, dict):
            return ToolVerdict(ToolAction.BLOCK, "tool arguments must be an object", Layer.VALIDATION)

        decision = self.policy.evaluate(event.tool_name, event.arguments, session)
        details = {"risk": decision.risk.value if decision.risk else None, "policy": decision.reason}
        if decision.outcome is Outcome.ALLOW:
            return ToolVerdict(ToolAction.ALLOW, decision.reason, Layer.POLICY, details=details)
        if decision.outcome is Outcome.BLOCK:
            return ToolVerdict(ToolAction.BLOCK, decision.reason, Layer.POLICY, details=details)
        if self.judge is None:
            action = ToolAction.ALLOW if decision.fallback is Outcome.ALLOW else ToolAction.BLOCK
            return ToolVerdict(action, f"{decision.reason} (policy only)", Layer.POLICY, details=details)

        tainted = self.config.taint and session.tainted
        threshold = self.config.tainted_threshold if tainted else self.config.threshold
        judge_input = JudgeInput(
            user_turns=session.user_turns,
            tool_name=event.tool_name,
            arguments=event.arguments,
            recent_context=[
                {
                    "tool": record.tool_name,
                    "arguments": record.arguments,
                    "result": record.result_text[: self.config.preview_chars],
                }
                for record in session.calls[-self.config.context_calls :]
            ],
            evidence=evidence_lines(event.arguments, [record.result_text for record in session.calls]),
        )
        try:
            result = await self.judge.judge(judge_input)
        except Exception as error:
            return ToolVerdict(
                ToolAction.BLOCK, f"judge failed ({type(error).__name__}: {error})", Layer.JUDGE, details=details
            )
        details |= {"threshold": threshold, "tainted": tainted}
        action = ToolAction.ALLOW if result.p_aligned >= threshold else ToolAction.BLOCK
        return ToolVerdict(
            action,
            result.reason,
            Layer.JUDGE,
            p_aligned=result.p_aligned,
            judge_calls=1,
            judge_tokens=result.tokens,
            details=details,
        )

    async def after_tool_call(self, event: ToolResultEvent) -> ToolVerdict:
        started = time.perf_counter()
        verdict = await self._inspect(event)
        verdict.latency_ms = (time.perf_counter() - started) * 1000
        session = self.sessions.get(event.session_id)
        if session is not None:
            seen = verdict.replacement if verdict.action is ToolAction.REPLACE else event.result
            for record in reversed(session.calls):
                if record.call_id == event.call_id and record.tool_name == event.tool_name:
                    record.result_text = seen or ""
                    break
        self.audit.write(
            {
                "point": "post_tool",
                "session": event.session_id,
                "server": event.server_id,
                "tool": event.tool_name,
                "call_id": event.call_id,
                **verdict.to_dict(),
            }
        )
        return verdict

    async def _inspect(self, event: ToolResultEvent) -> ToolVerdict:
        if self.scanner is None:
            return ToolVerdict(ToolAction.ALLOW, "result scanning disabled", Layer.SCANNER)
        try:
            scan = await self.scanner.scan(event.result)
        except Exception as error:
            return ToolVerdict(
                ToolAction.REPLACE,
                f"result scan failed ({type(error).__name__}: {error})",
                Layer.SCANNER,
                replacement=REDACTED,
            )
        details = {"rule_hits": scan.rule_hits, "flagged": [text[:200] for text in scan.flagged]}
        if not scan.flagged:
            return ToolVerdict(
                ToolAction.ALLOW,
                "no injected instructions found",
                Layer.SCANNER,
                judge_calls=scan.judge_calls,
                judge_tokens=scan.judge_tokens,
                details=details,
            )
        session = self.sessions.get(event.session_id)
        if session is not None and self.config.taint:
            session.taint(scan.flagged)
        action = ToolAction.REPLACE if scan.sanitized is not None else ToolAction.ALLOW
        return ToolVerdict(
            action,
            f"{len(scan.flagged)} field(s) contained instructions aimed at the assistant",
            Layer.SCANNER,
            judge_calls=scan.judge_calls,
            judge_tokens=scan.judge_tokens,
            replacement=scan.sanitized,
            details=details,
        )

    async def aclose(self) -> None:
        if self.judge is not None and hasattr(self.judge, "aclose"):
            await self.judge.aclose()


_GUARDS: dict[str, ToolGuard] = {}


def register_guard(name: str, guard: ToolGuard) -> None:
    _GUARDS[name] = guard


def get_guard(name: str) -> ToolGuard | None:
    """The guard an enabled NLIP extension created for this entity, if any."""
    return _GUARDS.get(name)


def clear_guard(name: str) -> None:
    """Forget a previous guard before (re)loading an entity's configuration."""
    _GUARDS.pop(name, None)


def _resolve(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    return PACKAGE_DIR / path
