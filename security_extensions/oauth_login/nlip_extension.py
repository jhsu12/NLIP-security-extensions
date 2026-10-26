"""NLIP ingress extension: only signed-in users may talk to the agent.

The client signs in with Google (OpenID Connect) and attaches the ID token to every
request as an NLIP ``authorization`` token submessage (ECMA-430 reserved token type).
At server ingress this extension

- blocks a request with no token, or a token that is forged, expired, issued for
  another OAuth client, or for an email outside the allow-list;
- binds the NLIP session to the verified email (``session.peer``) and blocks a later
  request in that session from anyone else, so a leaked conversation token cannot be
  used to take over another user's conversation;
- removes the token from the message, so the agent, later extensions and the session
  history never hold the bearer credential.

List it first in ``ingress`` so later extensions (the tool guard) see the verified user.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from nlip_sdk import NLIPMessage, ReservedToken
from nlip_sdk.nlip import AllowedFormat
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
)

from .verifiers import STUB_AUDIENCE, STUB_SECRET, GoogleVerifier, StubVerifier, VerificationError


class OAuthLoginExtension(SecurityExtension):
    def __init__(
        self,
        provider: str = "google",
        client_id: str | Sequence[str] = "",
        allowed_emails: Sequence[str] = (),
        allowed_domains: Sequence[str] = (),
        stub_secret: str = STUB_SECRET,
        stub_audience: str = STUB_AUDIENCE,
    ) -> None:
        provider = provider.casefold()
        if provider == "google":
            # Empty: the CLI's Desktop client and the web page's client from the environment.
            client_ids = client_id or [os.getenv("GOOGLE_CLIENT_ID", ""), os.getenv("GOOGLE_WEB_CLIENT_ID", "")]
            self.verifier = GoogleVerifier(client_ids)
        elif provider == "stub":
            self.verifier = StubVerifier(stub_secret, audience=stub_audience)
        else:
            raise ValueError(f"unknown sign-in provider {provider!r} (google | stub)")
        self.provider = provider
        # Empty lists admit any verified account the OAuth client lets sign in.
        self.allowed_emails = {email.casefold() for email in allowed_emails}
        self.allowed_domains = {domain.casefold().lstrip("@") for domain in allowed_domains}

    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        if event.component != "server" or event.point is not EnforcementPoint.INGRESS:
            return SecurityDecision.allow()
        token = event.message.extract_authentication_token()
        if token is None:
            return SecurityDecision.block("no sign-in token; log in with Google first")
        try:
            identity = await self.verifier.verify(token)
        except VerificationError as error:
            return SecurityDecision.block(f"sign-in rejected: {error}")
        if not self._allowed(identity.email):
            return SecurityDecision.block(f"{identity.email} is not allowed to use this assistant")
        session = event.session
        if session.peer is not None and session.peer != identity.email:
            return SecurityDecision.block("this conversation belongs to a different signed-in user")
        session.peer = identity.email
        return SecurityDecision.replace(without_auth_tokens(event.message), reason=f"signed in as {identity.email}")

    def _allowed(self, email: str) -> bool:
        if not self.allowed_emails and not self.allowed_domains:
            return True
        return email in self.allowed_emails or email.rpartition("@")[2] in self.allowed_domains


def without_auth_tokens(message: NLIPMessage) -> NLIPMessage:
    stripped = message.model_copy(deep=True)
    if stripped.submessages:
        kept = [
            part
            for part in stripped.submessages
            if not (part.format == AllowedFormat.token and ReservedToken.is_authorization(part.subformat))
        ]
        stripped.submessages = kept or None
    return stripped
