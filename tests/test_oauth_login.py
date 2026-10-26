"""Offline tests for OAuth sign-in: token checks, session binding, and the NLIP HTTP path."""

import asyncio
import copy

import httpx
import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from agent_applications.workspace_assistant._config import CONFIG
from agent_applications.workspace_assistant.login import token_source
from agent_applications.workspace_assistant.nlip_agent import WorkspaceNLIPAgent
from nlip_sdk import NLIPMessage, NLIPSession
from nlip_sdk.nlip_security_extensions import EnforcementPoint, SecurityAction, SecurityEvent
from security_extensions.oauth_login import GoogleVerifier, OAuthLoginExtension, VerificationError, make_stub_token
from security_extensions.oauth_login import verifiers

USER = "emma.johnson@bluesparrowtech.com"


class ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def run(coroutine):
    return asyncio.run(coroutine)


def ingress(extension: OAuthLoginExtension, session: NLIPSession, token: str | None, text: str = "hi"):
    message = NLIPMessage.text(text)
    message.add_token("conversation-1", "conversation_user")
    if token is not None:
        message.add_authentication_token(token)
    event = SecurityEvent(EnforcementPoint.INGRESS, message, session, "workspace", session.peer, "server")
    return run(extension.evaluate(event))


# --- extension decisions -----------------------------------------------------------------


def test_valid_token_binds_session_and_strips_the_token() -> None:
    session = NLIPSession("s1")
    decision = ingress(OAuthLoginExtension(provider="stub"), session, make_stub_token(USER))
    assert decision.action is SecurityAction.REPLACE
    assert decision.message.extract_authentication_token() is None
    # Other tokens and the user's text are untouched.
    assert decision.message.extract_text(language=None) == "hi"
    assert [token.subformat for token in decision.message.token_submessages()] == ["conversation_user"]
    assert session.peer == USER


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        (None, "no sign-in token"),
        (make_stub_token(USER, secret="attacker-secret"), "bad token signature"),
        (make_stub_token(USER, ttl=-10), "expired"),
        (make_stub_token(USER, audience="some-other-app"), "different application"),
        (make_stub_token(USER, email_verified=False), "not verified"),
        ("not-a-jwt", "malformed"),
    ],
)
def test_bad_or_missing_tokens_are_blocked(token, reason) -> None:
    session = NLIPSession("s1")
    decision = ingress(OAuthLoginExtension(provider="stub"), session, token)
    assert decision.action is SecurityAction.BLOCK and reason in decision.reason
    assert session.peer is None


def test_allow_lists() -> None:
    by_email = OAuthLoginExtension(provider="stub", allowed_emails=[USER])
    assert ingress(by_email, NLIPSession("a"), make_stub_token(USER)).action is SecurityAction.REPLACE
    assert ingress(by_email, NLIPSession("b"), make_stub_token("eve@gmail.com")).action is SecurityAction.BLOCK
    by_domain = OAuthLoginExtension(provider="stub", allowed_domains=["bluesparrowtech.com"])
    assert ingress(by_domain, NLIPSession("c"), make_stub_token("Bob@BlueSparrowTech.com")).action is SecurityAction.REPLACE
    assert ingress(by_domain, NLIPSession("d"), make_stub_token("bob@evil.com")).action is SecurityAction.BLOCK


def test_another_user_cannot_continue_a_bound_session() -> None:
    extension = OAuthLoginExtension(provider="stub")
    session = NLIPSession("s1")
    assert ingress(extension, session, make_stub_token(USER)).action is SecurityAction.REPLACE
    hijack = ingress(extension, session, make_stub_token("eve@gmail.com"))
    assert hijack.action is SecurityAction.BLOCK and "different signed-in user" in hijack.reason
    assert ingress(extension, session, make_stub_token(USER)).action is SecurityAction.REPLACE


def test_egress_and_client_events_pass_through() -> None:
    extension = OAuthLoginExtension(provider="stub")
    session = NLIPSession("s1")
    message = NLIPMessage.text("reply")
    for point, component in [(EnforcementPoint.EGRESS, "server"), (EnforcementPoint.INGRESS, "client")]:
        event = SecurityEvent(point, message, session, "workspace", None, component)
        assert run(extension.evaluate(event)).action is SecurityAction.ALLOW


# --- Google verifier (Google's key check is replaced; no network) ------------------------


def google_claims(**overrides):
    claims = {"iss": "https://accounts.google.com", "sub": "1234", "email": USER, "email_verified": True, "exp": 9e9}
    return claims | overrides


def test_google_verifier_requires_a_client_id(monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_WEB_CLIENT_ID", raising=False)
    with pytest.raises(ValueError, match="client id"):
        OAuthLoginExtension(provider="google")


def test_google_verifier_checks_audience_and_caches(monkeypatch) -> None:
    from google.oauth2 import id_token

    calls = []

    def fake_verify(token, request, audience, clock_skew_in_seconds):
        calls.append((token, audience))
        if token == "forged":
            raise ValueError("Could not verify token signature.")
        return google_claims(email_verified=token != "unverified")

    monkeypatch.setattr(id_token, "verify_oauth2_token", fake_verify)
    verifier = GoogleVerifier("client-123.apps.googleusercontent.com")
    assert run(verifier.verify("good")).email == USER
    assert run(verifier.verify("good")).subject == "1234"
    assert calls == [("good", ["client-123.apps.googleusercontent.com"])]  # second check was cached
    with pytest.raises(VerificationError, match="signature"):
        run(verifier.verify("forged"))
    with pytest.raises(VerificationError, match="not verified"):
        run(verifier.verify("unverified"))


def test_stub_token_round_trip_reads_claims() -> None:
    assert verifiers.unverified_claims(make_stub_token(USER))["email"] == USER
    assert verifiers.unverified_claims("garbage") == {}


# --- full NLIP path over HTTP --------------------------------------------------------------


def signed_in_config(provider: str = "stub") -> dict:
    config = copy.deepcopy(CONFIG)
    config["entities"]["workspace"]["security"] = {"ingress": ["oauth_verify", "tool_guard"], "egress": ["tool_guard"]}
    config["security_extensions"]["oauth_verify"]["options"]["provider"] = provider
    config["security_extensions"]["tool_guard"]["options"].update(
        {"audit_path": None, "judge": "stub", "scanner": "rules", "catalog": "off"}
    )
    return config


def test_nlip_http_requires_sign_in_and_records_the_user() -> None:
    config = signed_in_config()
    server = WorkspaceNLIPAgent(config, chat_model_factory=lambda: ScriptedModel(messages=iter([AIMessage(content="Hello Emma.")])))
    app = server.create_nlip_app()

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            anonymous = await client.post("/nlip", json=NLIPMessage.text("Read my inbox").to_dict())
            assert anonymous.status_code == 403 and "no sign-in token" in anonymous.json()["detail"]
            forged = NLIPMessage.text("Read my inbox")
            forged.add_authentication_token(make_stub_token(USER, secret="attacker-secret"))
            assert (await client.post("/nlip", json=forged.to_dict())).status_code == 403
            assert server.agents == {} or all(not agent.messages for agent in server.agents.values())

            message = NLIPMessage.text("Hi")
            message.add_authentication_token(token_source(config)())
            response = await client.post("/nlip", json=message.to_dict())
            assert response.status_code == 200
            assert NLIPMessage.model_validate(response.json()).extract_text(language=None) == "Hello Emma."
        for agent in server.agents.values():
            await agent.close()

    run(scenario())
    (guard_session,) = [s for s in server.guard.sessions._sessions.values() if s.user_turns]
    assert guard_session.user_id == USER and guard_session.user_turns == ["Hi"]


def test_login_is_off_when_not_in_ingress() -> None:
    config = copy.deepcopy(CONFIG)
    config["entities"]["workspace"]["security"] = {"ingress": ["tool_guard"], "egress": ["tool_guard"]}
    assert token_source(config) is None


def test_desktop_and_web_clients_are_both_accepted(monkeypatch) -> None:
    from google.oauth2 import id_token

    audiences = []
    monkeypatch.setattr(
        id_token, "verify_oauth2_token", lambda token, request, audience, **_: audiences.append(audience) or google_claims()
    )
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "desktop.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_WEB_CLIENT_ID", "web.apps.googleusercontent.com")
    extension = OAuthLoginExtension(provider="google")
    assert ingress(extension, NLIPSession("s1"), "google-token").action is SecurityAction.REPLACE
    assert audiences == [["desktop.apps.googleusercontent.com", "web.apps.googleusercontent.com"]]
    monkeypatch.delenv("GOOGLE_WEB_CLIENT_ID")
    assert OAuthLoginExtension(provider="google").verifier.client_ids == ["desktop.apps.googleusercontent.com"]
