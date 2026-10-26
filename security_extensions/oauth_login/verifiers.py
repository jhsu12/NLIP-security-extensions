"""Verify the OpenID Connect ID token a client attaches to an NLIP message.

``GoogleVerifier`` checks a Google ID token (signature against Google's published keys,
audience = our OAuth client id, issuer, expiry, verified email). ``StubVerifier`` checks
an HS256 token signed with a local secret, so tests and the offline demo run without
Google or a network; it is not meant for deployment.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

STUB_ISSUER = "nlip-stub-login"
STUB_AUDIENCE = "nlip-workspace"
# Offline demo/test default only; real deployments use provider = "google".
STUB_SECRET = "offline-demo-secret"


class VerificationError(ValueError):
    """The token is missing a claim, expired, forged, or issued for another app."""


@dataclass(frozen=True, slots=True)
class Identity:
    subject: str  # the provider's stable user id ("sub")
    email: str
    issuer: str
    expires_at: float


def identity_from_claims(claims: dict[str, Any]) -> Identity:
    email = claims.get("email")
    if not claims.get("sub") or not isinstance(email, str) or not email:
        raise VerificationError("ID token has no subject or email (request the openid and email scopes)")
    if claims.get("email_verified") is not True:
        raise VerificationError(f"email {email} is not verified by the identity provider")
    return Identity(str(claims["sub"]), email.casefold(), str(claims.get("iss", "")), float(claims["exp"]))


class GoogleVerifier:
    def __init__(self, client_id: str | Sequence[str], *, clock_skew: int = 10) -> None:
        # Several of our OAuth clients may sign users in (CLI = Desktop app, browser = Web
        # application); a token issued to any of them is accepted, any other app's is not.
        client_ids = [client_id] if isinstance(client_id, str) else list(client_id)
        client_ids = [item for item in client_ids if item]
        if not client_ids:
            raise ValueError("Google sign-in needs an OAuth client id (set GOOGLE_CLIENT_ID or client_id)")
        from google.auth.transport.requests import Request

        self.client_ids = client_ids
        self.clock_skew = clock_skew
        self._request = Request()
        # sha256(token) -> identity, so a token reused on every message of a turn is
        # checked against Google's keys once rather than per request.
        self._verified: dict[str, Identity] = {}

    async def verify(self, token: str) -> Identity:
        from google.auth.exceptions import GoogleAuthError
        from google.oauth2 import id_token

        key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = time.time()
        cached = self._verified.get(key)
        if cached is not None and cached.expires_at > now:
            return cached
        try:
            # Checks signature, audience, issuer (accounts.google.com) and expiry; the
            # key fetch is blocking, so it runs off the event loop.
            claims = await asyncio.to_thread(
                id_token.verify_oauth2_token,
                token,
                self._request,
                self.client_ids,
                clock_skew_in_seconds=self.clock_skew,
            )
        except (ValueError, GoogleAuthError) as error:
            raise VerificationError(f"invalid Google ID token ({error})") from error
        identity = identity_from_claims(claims)
        self._verified = {k: v for k, v in self._verified.items() if v.expires_at > now}
        self._verified[key] = identity
        return identity


class StubVerifier:
    def __init__(self, secret: str = STUB_SECRET, *, audience: str = STUB_AUDIENCE) -> None:
        if not secret:
            raise ValueError("stub sign-in needs a secret")
        self.secret = secret
        self.audience = audience

    async def verify(self, token: str) -> Identity:
        try:
            header, payload, signature = token.split(".")
            expected = _sign(self.secret, f"{header}.{payload}")
            if not hmac.compare_digest(signature, expected):
                raise VerificationError("bad token signature")
            claims = json.loads(_b64decode(payload))
        except VerificationError:
            raise
        except (ValueError, TypeError) as error:
            raise VerificationError(f"malformed token ({error})") from error
        if claims.get("iss") != STUB_ISSUER or claims.get("aud") != self.audience:
            raise VerificationError("token was issued for a different application")
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
            raise VerificationError("token has expired")
        return identity_from_claims(claims)


def make_stub_token(
    email: str,
    *,
    secret: str = STUB_SECRET,
    audience: str = STUB_AUDIENCE,
    ttl: float = 3600,
    email_verified: bool = True,
) -> str:
    """An HS256 JWT in the shape of a Google ID token, for offline tests and demos."""
    now = int(time.time())
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64encode(
        json.dumps(
            {
                "iss": STUB_ISSUER,
                "aud": audience,
                "sub": f"stub-{hashlib.sha256(email.casefold().encode()).hexdigest()[:16]}",
                "email": email,
                "email_verified": email_verified,
                "iat": now,
                "exp": now + int(ttl),
            }
        ).encode()
    )
    return f"{header}.{payload}.{_sign(secret, f'{header}.{payload}')}"


def unverified_claims(token: str) -> dict[str, Any]:
    """Read a JWT's claims without checking it (client-side display only)."""
    try:
        return json.loads(_b64decode(token.split(".")[1]))
    except (IndexError, ValueError):
        return {}


def _sign(secret: str, data: str) -> str:
    return _b64encode(hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest())


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
