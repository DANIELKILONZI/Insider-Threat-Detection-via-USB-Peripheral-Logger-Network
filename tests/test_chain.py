"""Tests for the local EventChain (SQLite hash chain)."""
import tempfile

import pytest

from agent.chain import EventChain
from shared.schema import NormalizedEvent


@pytest.fixture
def chain(tmp_path):
    return EventChain(db_path=str(tmp_path / "test_chain.db"))


def make_event(device_id="0781:1234", action="connect", agent_id="agent-test"):
    return NormalizedEvent(
        agent_id=agent_id,
        actor="user",
        device_id=device_id,
        action=action,
        source_type="usb",
    )


def test_empty_chain_head_is_none(chain):
    assert chain.get_chain_head() is None


def test_add_event_returns_hash(chain):
    ev = make_event()
    h = chain.add_event(ev)
    assert len(h) == 64


def test_chain_head_updated(chain):
    ev1 = make_event(device_id="1111:1111")
    ev2 = make_event(device_id="2222:2222")
    h1 = chain.add_event(ev1)
    h2 = chain.add_event(ev2)
    assert chain.get_chain_head() == h2
    assert h1 != h2


def test_chain_links_prev_hash(chain):
    ev1 = make_event(device_id="aaaa:0001")
    ev2 = make_event(device_id="aaaa:0002")
    h1 = chain.add_event(ev1)
    chain.add_event(ev2)
    events = chain.get_events(limit=10)
    # Most recent first
    assert events[0].prev_hash == h1


def test_verify_chain_valid(chain):
    for i in range(5):
        chain.add_event(make_event(device_id=f"0001:{i:04x}"))
    assert chain.verify_chain() is True


def test_verify_chain_detects_tampering(chain, tmp_path):
    import sqlite3

    db_path = str(tmp_path / "tamper_chain.db")
    c = EventChain(db_path=db_path)
    for i in range(3):
        c.add_event(make_event(device_id=f"beef:{i:04x}"))

    # Tamper: change a hash directly in the DB
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET event_hash='deadbeef' WHERE seq=1")
    conn.commit()
    conn.close()

    assert c.verify_chain() is False


def test_get_events_returns_most_recent(chain):
    for i in range(10):
        chain.add_event(make_event(device_id=f"cafe:{i:04x}"))
    events = chain.get_events(limit=3)
    assert len(events) == 3
