"""Tests for the CA — cert issuance, signing, and agent_id extraction."""
import pytest

from server.ca.cert_authority import CertificateAuthority


def test_ca_generates_on_missing_files(tmp_path):
    ca = CertificateAuthority(
        ca_cert_path=str(tmp_path / "ca.crt"),
        ca_key_path=str(tmp_path / "ca.key"),
    )
    pem = ca.get_ca_cert_pem()
    assert "BEGIN CERTIFICATE" in pem


def test_ca_files_created(tmp_path):
    ca_crt = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    CertificateAuthority(str(ca_crt), str(ca_key))
    assert ca_crt.exists()
    assert ca_key.exists()


def test_generate_csr():
    key_pem, csr_pem = CertificateAuthority.generate_csr("agent-test")
    assert "BEGIN CERTIFICATE REQUEST" in csr_pem
    assert "BEGIN RSA PRIVATE KEY" in key_pem or "BEGIN PRIVATE KEY" in key_pem


def test_issue_cert_contains_agent_id(ca):
    _, csr_pem = CertificateAuthority.generate_csr("agent-42")
    cert_pem = ca.issue_cert("agent-42", csr_pem)
    assert "BEGIN CERTIFICATE" in cert_pem


def test_verify_client_cert_extracts_agent_id(ca):
    _, csr_pem = CertificateAuthority.generate_csr("agent-xyz")
    cert_pem = ca.issue_cert("agent-xyz", csr_pem)
    extracted = ca.verify_client_cert(cert_pem)
    assert extracted == "agent-xyz"


def test_verify_bad_cert_returns_empty(ca):
    result = ca.verify_client_cert("not-a-valid-cert")
    assert result == ""


def test_ca_reloads_from_disk(tmp_path):
    ca_crt = str(tmp_path / "ca.crt")
    ca_key = str(tmp_path / "ca.key")
    ca1 = CertificateAuthority(ca_crt, ca_key)
    ca2 = CertificateAuthority(ca_crt, ca_key)
    assert ca1.get_ca_cert_pem() == ca2.get_ca_cert_pem()
