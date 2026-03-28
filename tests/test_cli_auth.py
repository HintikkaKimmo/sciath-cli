"""
Integration tests for auth commands via CliRunner + mock HTTP.
"""
import json

import httpx
import pytest
from typer.testing import CliRunner

from sciath_cli.config import SciathConfig, load_config, save_config
from sciath_cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    import sciath_cli.config as cfg_module
    monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath")
    monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath" / "config.json")
    monkeypatch.delenv("SCIATH_API_URL", raising=False)
    yield


def _mock_login_sequence(responses: list[dict]):
    """
    Build an httpx.MockTransport that returns responses in order.
    First call → /device/code, subsequent calls → /device/token.
    """
    call_count = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        idx = min(call_count[0], len(responses) - 1)
        call_count[0] += 1
        body = responses[idx]
        return httpx.Response(
            body.pop("_status", 200),
            content=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )

    return httpx.MockTransport(handler)


class TestLogin:
    def _patched_client(self, responses, monkeypatch):
        """Patch httpx.Client in the auth module using a fixed transport per instance."""
        _OriginalClient = httpx.Client

        def make_client(*args, **kwargs):
            return _OriginalClient(
                base_url=kwargs.get("base_url", "https://api.sciath.io"),
                transport=_mock_login_sequence(responses),
            )

        monkeypatch.setattr("sciath_cli.commands.auth.httpx.Client", make_client)
        monkeypatch.setattr("sciath_cli.commands.auth.time.sleep", lambda _: None)

    def test_happy_path_saves_credentials(self, monkeypatch):
        """Login succeeds: device code returned, then token delivered on second poll."""
        responses = [
            {
                "device_code": "ABCD-1234",
                "poll_code": "poll_xyz",
                "verification_uri": "https://app.sciath.io/auth/device",
                "expires_in": 900,
            },
            {"status": "pending"},
            {
                "api_key": "sk_live_abc",
                "user_email": "kim@acme.com",
                "customer_name": "Acme Corp",
            },
        ]
        self._patched_client(responses, monkeypatch)

        result = runner.invoke(app, ["login"])

        assert result.exit_code == 0, result.output
        assert "kim@acme.com" in result.output
        config = load_config()
        assert config.api_key == "sk_live_abc"
        assert config.user_email == "kim@acme.com"

    def test_expired_code_exits_1(self, monkeypatch):
        responses = [
            {
                "device_code": "ABCD-1234",
                "poll_code": "poll_xyz",
                "verification_uri": "https://app.sciath.io/auth/device",
                "expires_in": 900,
            },
            {"status": "expired", "_status": 410},
        ]
        self._patched_client(responses, monkeypatch)

        result = runner.invoke(app, ["login"])
        assert result.exit_code == 1
        assert "expired" in result.output.lower()

    def test_denied_exits_1(self, monkeypatch):
        responses = [
            {
                "device_code": "ABCD-1234",
                "poll_code": "poll_xyz",
                "verification_uri": "https://app.sciath.io/auth/device",
                "expires_in": 900,
            },
            {"status": "denied"},
        ]
        self._patched_client(responses, monkeypatch)

        result = runner.invoke(app, ["login"])
        assert result.exit_code == 1
        assert "denied" in result.output.lower()


class TestLogout:
    def test_clears_credentials(self):
        save_config(SciathConfig(api_key="sk_live_abc", user_email="kim@acme.com"))
        result = runner.invoke(app, ["logout"])
        assert result.exit_code == 0
        assert load_config().api_key is None

    def test_idempotent_when_not_logged_in(self):
        result = runner.invoke(app, ["logout"])
        assert result.exit_code == 0


class TestWhoami:
    def test_shows_user_info_when_authenticated(self):
        save_config(SciathConfig(
            api_key="sk_x",
            user_email="kim@acme.com",
            customer_name="Acme Corp",
        ))
        result = runner.invoke(app, ["whoami"])
        assert result.exit_code == 0
        assert "kim@acme.com" in result.output
        assert "Acme Corp" in result.output

    def test_exits_1_when_not_authenticated(self):
        result = runner.invoke(app, ["whoami"])
        assert result.exit_code == 1
        assert "sciath login" in result.output
