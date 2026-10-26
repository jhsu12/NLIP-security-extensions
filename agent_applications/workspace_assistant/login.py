"""Sign-in for NLIP clients of the workspace assistant.

With ``provider = "google"`` the user signs in through Google's installed-app flow
(browser + loopback redirect; scopes ``openid email`` only) and the client sends the
resulting Google ID token with every request. The OAuth credentials are cached outside
the repo, so later runs refresh the ID token without opening the browser again. With
``provider = "stub"`` a locally signed token is minted instead (offline demo/tests).

    python -m agent_applications.workspace_assistant.login            # sign in, print the email
    python -m agent_applications.workspace_assistant.login --logout   # forget cached credentials
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from security_extensions.oauth_login.verifiers import STUB_AUDIENCE, STUB_SECRET, make_stub_token, unverified_claims

from ._config import CONFIG
from .nlip_agent import ENTITY_NAME

SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
CACHE_PATH = Path.home() / ".cache" / "nlip-workspace" / "google_credentials.json"
STUB_USER = "emma.johnson@bluesparrowtech.com"
LOGIN_EXTENSION = "oauth_verify"


def login_options(config: Mapping[str, Any] = CONFIG) -> dict[str, Any] | None:
    """The server's sign-in options, or None if its ingress does not require sign-in."""
    ingress = config["entities"][ENTITY_NAME].get("security", {}).get("ingress", [])
    if LOGIN_EXTENSION not in ingress:
        return None
    return dict(config.get("security_extensions", {}).get(LOGIN_EXTENSION, {}).get("options", {}))


def token_source(config: Mapping[str, Any] = CONFIG) -> Callable[[], str] | None:
    """A function returning a currently valid ID token, or None if sign-in is off."""
    options = login_options(config)
    if options is None:
        return None
    if options.get("provider", "google").casefold() == "stub":
        email = os.getenv("NLIP_STUB_USER", STUB_USER)
        secret = options.get("stub_secret", STUB_SECRET)
        audience = options.get("stub_audience", STUB_AUDIENCE)
        return lambda: make_stub_token(email, secret=secret, audience=audience)
    client_id = options.get("client_id") or os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise RuntimeError("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET (see .env.example) to sign in.")
    return lambda: google_id_token(client_id, client_secret)


def google_id_token(client_id: str, client_secret: str, *, cache_path: Path = CACHE_PATH) -> str:
    from google.auth.exceptions import RefreshError
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    credentials = None
    if cache_path.exists():
        credentials = Credentials.from_authorized_user_info(json.loads(cache_path.read_text()), SCOPES)
        if credentials.client_id != client_id:
            credentials = None
    # The cache keeps the refresh token, not the ID token; refreshing returns a new one.
    if credentials is not None and _expiring(credentials.id_token):
        try:
            credentials.refresh(Request())
        except RefreshError:
            credentials = None
    if credentials is None or not credentials.id_token:
        flow = InstalledAppFlow.from_client_config(
            {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            SCOPES,
        )
        credentials = flow.run_local_server(port=0, prompt="select_account")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(credentials.to_json())
    cache_path.chmod(0o600)
    return credentials.id_token


def logout(cache_path: Path = CACHE_PATH) -> None:
    cache_path.unlink(missing_ok=True)


def token_email(token: str) -> str:
    return str(unverified_claims(token).get("email", "unknown user"))


def _expiring(id_token: str | None, margin: float = 60) -> bool:
    return id_token is None or unverified_claims(id_token).get("exp", 0) < time.time() + margin


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--logout", action="store_true", help="Delete the cached Google credentials")
    args = parser.parse_args()
    if args.logout:
        logout()
        print(f"Removed {CACHE_PATH}")
        return
    source = token_source()
    if source is None:
        print(f"Sign-in is off: {LOGIN_EXTENSION!r} is not in the server's ingress list.")
        return
    print(f"Signed in as {token_email(source())}")


if __name__ == "__main__":
    main()
