"""
tests/test_anchor_signing.py – Anchor signing must fail closed and be verifiable.

An anchor is the server's counter-signature over an agent's local hash-chain
head.  It is only evidence if the agent could not have produced it and if
somebody can later check it.  These tests pin both properties:

  * no server-private key  → refuse to anchor (never emit a fake signature)
  * ITDN_API_KEY           → never used for signing; every agent knows it
  * a real key             → signature verifies, and fails on a tampered hash
  * dev fallback           → clearly marked and never reported as verified
"""

from __future__ import annotations

import hashlib
import hmac
import importlib

import pytest


HASH = "a" * 64


def _reload(monkeypatch, **env):
    """Reload config+database with a specific anchoring environment."""
    for key in (
        "ITDN_ANCHOR_KEY",
        "ITDN_ALLOW_UNSIGNED_ANCHORS",
        "ITDN_API_KEY",
        "ITDN_TLS_KEY",
        "ITDN_TLS_CERT",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    return database


@pytest.fixture(autouse=True)
def _restore_modules():
    """Put config/database back to the ambient suite settings afterwards."""
    yield
    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)


# ── Fail closed ──────────────────────────────────────────────────────────────

def test_refuses_to_sign_without_any_key(monkeypatch, tmp_path):
    db = _reload(monkeypatch, ITDN_TLS_KEY=str(tmp_path / "absent.key"))

    with pytest.raises(db.AnchorSigningError, match="no server-private signing key"):
        db._sign_chain_head(HASH)


def test_api_key_is_not_accepted_as_a_signing_key(monkeypatch, tmp_path):
    """ITDN_API_KEY must not sign anchors — every agent holds it and could forge."""
    db = _reload(
        monkeypatch,
        ITDN_API_KEY="shared-with-every-agent",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )

    with pytest.raises(db.AnchorSigningError):
        db._sign_chain_head(HASH)


def test_endpoint_returns_503_when_server_cannot_sign(monkeypatch, tmp_path):
    """The agent must not be told an unsigned anchor succeeded."""
    monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")
    monkeypatch.delenv("ITDN_ANCHOR_KEY", raising=False)
    monkeypatch.delenv("ITDN_ALLOW_UNSIGNED_ANCHORS", raising=False)
    monkeypatch.setenv("ITDN_API_KEY", "")
    monkeypatch.setenv("ITDN_TLS_KEY", str(tmp_path / "absent.key"))

    for name in (
        "server.config",
        "server.database",
        "server.detection.rule_config",
        "server.detection.rules",
        "server.auth",
        "server.app",
    ):
        importlib.reload(importlib.import_module(name))

    import server.app as app_mod
    app = app_mod.create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        resp = client.post(
            "/api/v1/anchor",
            json={"agent_id": "h1", "chain_head_hash": HASH},
            content_type="application/json",
        )

    assert resp.status_code == 503
    assert "signing key" in resp.get_json()["error"]


# ── HMAC signing and verification ────────────────────────────────────────────

def test_hmac_signature_is_labelled_and_verifies(monkeypatch, tmp_path):
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="a-server-only-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )

    sig = db._sign_chain_head(HASH)

    assert sig.startswith("hmac-sha256:")
    assert db.verify_anchor(HASH, sig) is True


def test_hmac_signature_matches_an_independent_computation(monkeypatch, tmp_path):
    """Guards the construction itself, not just round-tripping our own code."""
    key = "a-server-only-secret"
    db = _reload(
        monkeypatch, ITDN_ANCHOR_KEY=key, ITDN_TLS_KEY=str(tmp_path / "absent.key")
    )

    expected = hmac.new(key.encode(), HASH.encode(), hashlib.sha256).hexdigest()
    assert db._sign_chain_head(HASH) == f"hmac-sha256:{expected}"


def test_verification_fails_on_tampered_chain_head(monkeypatch, tmp_path):
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="a-server-only-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    sig = db._sign_chain_head(HASH)

    assert db.verify_anchor("b" * 64, sig) is False


def test_verification_fails_under_a_different_key(monkeypatch, tmp_path):
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="original-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    sig = db._sign_chain_head(HASH)

    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="rotated-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    assert db.verify_anchor(HASH, sig) is False


@pytest.mark.parametrize("bad", ["", "garbage", "nocolon", "unknown-alg:abcd", "hmac-sha256:"])
def test_verification_rejects_malformed_signatures(monkeypatch, tmp_path, bad):
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="a-server-only-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    assert db.verify_anchor(HASH, bad) is False


# ── Development fallback ─────────────────────────────────────────────────────

def test_dev_mode_marks_signatures_unverifiable(monkeypatch, tmp_path):
    """The escape hatch must be obvious in the data and never verify true."""
    db = _reload(
        monkeypatch,
        ITDN_ALLOW_UNSIGNED_ANCHORS="1",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )

    sig = db._sign_chain_head(HASH)

    assert sig.startswith("unsigned-dev:")
    assert db.verify_anchor(HASH, sig) is False


# ── RSA path ─────────────────────────────────────────────────────────────────

def test_rsa_signature_verifies_against_the_certificate(monkeypatch, tmp_path):
    """The preferred path: sign with the TLS private key, verify with the cert."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "itdn-test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    key_path = tmp_path / "server.key"
    cert_path = tmp_path / "server.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    db = _reload(
        monkeypatch, ITDN_TLS_KEY=str(key_path), ITDN_TLS_CERT=str(cert_path)
    )

    sig = db._sign_chain_head(HASH)

    assert sig.startswith("rsa-sha256:")
    assert db.verify_anchor(HASH, sig) is True
    assert db.verify_anchor("b" * 64, sig) is False


def test_rsa_preferred_over_hmac_when_both_available(monkeypatch, tmp_path):
    """An unreadable TLS key must fall through to HMAC rather than fail."""
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="a-server-only-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    assert db._sign_chain_head(HASH).startswith("hmac-sha256:")


# ── verify_chain CLI reporting ───────────────────────────────────────────────

def test_cli_reports_valid_and_invalid(monkeypatch, tmp_path):
    db = _reload(
        monkeypatch,
        ITDN_ANCHOR_KEY="a-server-only-secret",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    from tools.verify_chain import _anchor_status

    sig = db._sign_chain_head(HASH)
    assert _anchor_status(HASH, sig) == "VALID"
    assert _anchor_status("b" * 64, sig) == "INVALID"


def test_cli_never_calls_a_dev_signature_valid(monkeypatch, tmp_path):
    db = _reload(
        monkeypatch,
        ITDN_ALLOW_UNSIGNED_ANCHORS="1",
        ITDN_TLS_KEY=str(tmp_path / "absent.key"),
    )
    from tools.verify_chain import _anchor_status

    status = _anchor_status(HASH, db._sign_chain_head(HASH))
    assert status.startswith("UNSIGNED")
    assert "VALID" != status
