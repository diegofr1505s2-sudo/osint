import json
import os

from catexe.modules.secure_store import SecretStore


def test_secret_store_round_trip_and_permissions(tmp_path):
    path = tmp_path / "secrets.json"
    store = SecretStore(path, {})
    store.set("discord_token", "token-local-1234")
    assert store.get("discord_token") == "token-local-1234"
    assert "token-local-1234" in path.read_text(encoding="utf-8")
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_environment_secret_has_priority_and_is_redacted(tmp_path):
    path = tmp_path / "secrets.json"
    store = SecretStore(path, {"CATEXE_SECRET_API_TEST": "env-secret-1234"})
    store.set("api_test", "file-secret-1234")
    assert store.get("api_test") == "env-secret-1234"
    assert "env-secret-1234" not in store.redact("url=env-secret-1234")
    assert "[SECRET REDACTED]" in store.redact("url=env-secret-1234")


def test_legacy_migration_removes_plaintext_config_value(tmp_path):
    path = tmp_path / "secrets.json"
    store = SecretStore(path, {})
    config = {"discord_token": "legacy-token-1234", "theme": "graphite"}
    assert store.migrate(config, ("discord_token",))
    assert "discord_token" not in config
    assert store.get("discord_token") == "legacy-token-1234"
    assert json.loads(path.read_text(encoding="utf-8"))["discord_token"] == "legacy-token-1234"
