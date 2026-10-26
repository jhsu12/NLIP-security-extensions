"""NLIP side of the tool guard: record the trusted user task at ingress.

Enabled like any other security extension in config.toml. At server ingress it takes
the user's request from the NLIP message, the only source the guard trusts for "what
the user asked"; at server egress it closes the turn in the audit log. It always
allows the message: enforcement happens at the tool boundary.
"""

from __future__ import annotations

from typing import Any

from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
)

from .guard import ToolGuard, register_guard


class ToolGuardContextExtension(SecurityExtension):
    def __init__(self, instance: str = "default", **options: Any) -> None:
        self.instance = instance
        self.guard = ToolGuard.from_options(**options)
        # The agent application looks the guard up by this name to install its
        # tool-boundary middleware.
        register_guard(instance, self.guard)

    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        if event.component != "server":
            return SecurityDecision.allow()
        if event.point is EnforcementPoint.INGRESS:
            text = event.message.extract_text(language=None)
            if text:
                self.guard.begin_turn(event.session.id, text, user_id=event.session.peer)
        else:
            self.guard.end_turn(event.session.id)
        return SecurityDecision.allow()
