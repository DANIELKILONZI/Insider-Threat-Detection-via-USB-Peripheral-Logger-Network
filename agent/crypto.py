"""
agent/crypto.py – AES-256-GCM encryption helpers for the local audit log.

When ``ITDN_LOG_KEY`` is set to a 64-hex-character string (32 bytes), the
audit logger encrypts each record before appending it to disk.

Key format
----------
``ITDN_LOG_KEY`` must be exactly 64 lowercase (or uppercase) hex characters::

    python -c "import secrets; print(secrets.token_hex(32))"

Ciphertext format (written as a JSON-Lines string in the audit log)
-------------------------------------------------------------------
Each encrypted record is stored as a JSON object::

    {"v": 1, "nonce": "<12-byte nonce hex>", "ct": "<ciphertext hex>", "tag": "<16-byte tag hex>"}

The ``record_hash`` chaining logic in ``LocalAuditLogger`` operates on the
*plaintext* dict, so chain integrity is preserved regardless of whether
encryption is enabled.

Usage::

    from agent.crypto import encrypt_record, decrypt_record, is_encryption_enabled

    if is_encryption_enabled():
        line = encrypt_record(record)      # returns JSON string
    else:
        line = json.dumps(record)

    plaintext = decrypt_record(line)       # always returns the plain dict
"""

from __future__ import annotations

import binascii
import json
import os
from typing import Any, Dict


def _get_key() -> bytes | None:
    """Return the 32-byte encryption key, or None if encryption is disabled."""
    raw = os.environ.get("ITDN_LOG_KEY", "").strip()
    if not raw:
        return None
    if len(raw) != 64:
        raise ValueError(
            "ITDN_LOG_KEY must be exactly 64 hex characters (32 bytes); "
            f"got {len(raw)} characters"
        )
    return bytes.fromhex(raw)


def is_encryption_enabled() -> bool:
    """Return True when ITDN_LOG_KEY is set and valid."""
    try:
        return _get_key() is not None
    except ValueError:
        return False


def encrypt_record(record: Dict[str, Any]) -> str:
    """
    Encrypt *record* with AES-256-GCM.

    Returns a JSON string suitable for writing directly to the log file.
    Raises ``RuntimeError`` if ``ITDN_LOG_KEY`` is not set.
    """
    key = _get_key()
    if key is None:
        raise RuntimeError("encrypt_record called but ITDN_LOG_KEY is not set")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    aad = b"itdn-audit-v1"
    plaintext = json.dumps(record, sort_keys=True).encode("utf-8")
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad)

    # AESGCM appends the 16-byte tag to ciphertext
    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    envelope = {
        "v": 1,
        "nonce": nonce.hex(),
        "ct": ct.hex(),
        "tag": tag.hex(),
    }
    return json.dumps(envelope)


def decrypt_record(line: str) -> Dict[str, Any]:
    """
    Decrypt a log line that may be either:
    - A plaintext JSON record (returned as-is).
    - An encrypted envelope (``{"v": 1, ...}``).

    Raises ``ValueError`` on decryption failure or unknown envelope version.
    Raises ``RuntimeError`` if the line is encrypted but ITDN_LOG_KEY is not set.
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if not isinstance(obj, dict) or obj.get("v") != 1:
        # Plaintext record
        return obj

    # Encrypted envelope
    key = _get_key()
    if key is None:
        raise RuntimeError(
            "Log record is encrypted but ITDN_LOG_KEY is not set; "
            "set the key to verify this chain."
        )

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        nonce = bytes.fromhex(obj["nonce"])
        ct = bytes.fromhex(obj["ct"])
        tag = bytes.fromhex(obj["tag"])
    except (KeyError, binascii.Error) as exc:
        raise ValueError(f"Malformed encrypted envelope: {exc}") from exc

    aad = b"itdn-audit-v1"
    ciphertext_with_tag = ct + tag
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
    except Exception as exc:  # cryptography raises InvalidTag or similar
        raise ValueError(f"Decryption failed – record may be tampered: {exc}") from exc

    return json.loads(plaintext.decode("utf-8"))
