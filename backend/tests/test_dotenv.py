"""backend/.env is read for local development, and real environment variables always win."""

from app.config import load_dotenv


def test_dotenv_loads_mg_keys_without_overriding(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        '# comment\nMG_ENV=dev\nexport MG_HMAC_SECRET="' + "a" * 40 + '"\nOTHER=x\nMG_PROTECTED_DOMAINS=acme.com\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MG_LOAD_DOTENV", "1")
    monkeypatch.setenv("MG_PROTECTED_DOMAINS", "from-env.com")
    monkeypatch.delenv("MG_HMAC_SECRET", raising=False)
    monkeypatch.delenv("MG_ENV", raising=False)
    loaded = load_dotenv(env)
    import os

    assert os.environ["MG_HMAC_SECRET"] == "a" * 40
    assert os.environ["MG_PROTECTED_DOMAINS"] == "from-env.com"  # the real environment wins
    assert "OTHER" not in loaded and "OTHER" not in os.environ
    assert set(loaded) == {"MG_ENV", "MG_HMAC_SECRET"}


def test_dotenv_can_be_disabled(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("MG_ENV=dev\n", encoding="utf-8")
    monkeypatch.setenv("MG_LOAD_DOTENV", "0")
    assert load_dotenv(env) == []
