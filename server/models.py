"""SQLAlchemy ORM models."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text

from server.database import Base


def _now():
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), nullable=False, unique=True, index=True)
    agent_id = Column(String(128), nullable=False, index=True)
    actor = Column(String(256), nullable=False)
    device_id = Column(String(256), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    source_type = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    raw_json = Column(Text, nullable=False, default="{}")
    event_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_now)


class Anchor(Base):
    __tablename__ = "anchors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(128), nullable=False, index=True)
    chain_head_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_now)
    server_signature = Column(Text, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(128), nullable=False, index=True)
    rule = Column(String(256), nullable=False)
    score = Column(Float, nullable=False)
    device_id = Column(String(256), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_now)
    details_json = Column(Text, nullable=False, default="{}")


class AgentCert(Base):
    __tablename__ = "agent_certs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(128), nullable=False, index=True)
    cert_pem = Column(Text, nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, default=_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)


class BaselineDevice(Base):
    __tablename__ = "baseline_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(128), nullable=False, index=True)
    device_id = Column(String(256), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=_now)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=_now)
    seen_count = Column(Integer, nullable=False, default=1)


class TrustedBinaryHash(Base):
    __tablename__ = "trusted_binary_hashes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(128), nullable=False, unique=True, index=True)
    hash_value = Column(String(64), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_now)


class HoneypotProfile(Base):
    __tablename__ = "honeypot_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vid = Column(String(8), nullable=False)
    pid = Column(String(8), nullable=False)
    name = Column(String(256), nullable=False, default="")
    active = Column(Boolean, nullable=False, default=True)
