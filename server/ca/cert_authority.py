"""Simple Certificate Authority for issuing per-agent X.509 certificates."""
from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


_VALIDITY_DAYS = 365


def _load_or_generate_key(key_path: str) -> rsa.RSAPrivateKey:
    p = Path(key_path)
    if p.exists():
        with open(p, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return key


class CertificateAuthority:
    """Issues and signs agent X.509 certificates."""

    def __init__(self, ca_cert_path: str, ca_key_path: str) -> None:
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
        self._ensure_ca()

    # ------------------------------------------------------------------
    def _ensure_ca(self) -> None:
        key_p = Path(self.ca_key_path)
        cert_p = Path(self.ca_cert_path)

        if key_p.exists() and cert_p.exists():
            with open(key_p, "rb") as fh:
                self._ca_key = serialization.load_pem_private_key(
                    fh.read(), password=None
                )
            with open(cert_p, "rb") as fh:
                self._ca_cert = x509.load_pem_x509_certificate(fh.read())
            return

        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InsiderThreatCA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "InsiderThreat Root CA"),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )

        key_p.parent.mkdir(parents=True, exist_ok=True)
        with open(key_p, "wb") as fh:
            fh.write(
                self._ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_p, "wb") as fh:
            fh.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

    # ------------------------------------------------------------------
    def get_ca_cert_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    def issue_cert(self, agent_id: str, csr_pem: str) -> str:
        """Sign a CSR and return the signed cert PEM. agent_id embedded in CN."""
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{agent_id}")]
                )
            )
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def verify_client_cert(self, cert_pem: str) -> str:
        """Verify cert against CA and extract agent_id from CN. Returns '' if invalid."""
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            # Verify RSA signature with PKCS1v15 (used by default in cert signing)
            self._ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                cert.signature_hash_algorithm,  # type: ignore[arg-type]
            )
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cn.startswith("agent:"):
                return cn[len("agent:"):]
            return cn
        except Exception:
            return ""

    @staticmethod
    def generate_csr(agent_id: str) -> tuple[str, str]:
        """Generate a private key + CSR for agent_id. Returns (key_pem, csr_pem)."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{agent_id}")]
                )
            )
            .sign(key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        return key_pem, csr_pem
