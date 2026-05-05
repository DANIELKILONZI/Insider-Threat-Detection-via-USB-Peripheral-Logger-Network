"""POST /api/v1/anchor — server signs and stores chain-head anchors."""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Anchor

router = APIRouter(prefix="/api/v1/anchor", tags=["anchor"])
logger = logging.getLogger(__name__)

# Lazy-load the signing key to avoid import-time file access
_signing_key = None


def _get_signing_key():
    global _signing_key
    if _signing_key is None:
        from cryptography.hazmat.primitives import serialization
        from pathlib import Path
        from server.config import config

        kp = Path(config.ca_key_path)
        if kp.exists():
            with open(kp, "rb") as fh:
                _signing_key = serialization.load_pem_private_key(
                    fh.read(), password=None
                )
        else:
            # Generate ephemeral key for dev/testing
            from cryptography.hazmat.primitives.asymmetric import rsa

            _signing_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
    return _signing_key


def _sign(payload: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    key = _get_signing_key()
    sig = key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


class AnchorRequest(BaseModel):
    agent_id: str
    chain_head_hash: str
    timestamp: str


@router.post("", status_code=201)
async def create_anchor(req: AnchorRequest, db: AsyncSession = Depends(get_db)):
    payload = json.dumps(
        {
            "agent_id": req.agent_id,
            "chain_head_hash": req.chain_head_hash,
            "timestamp": req.timestamp,
        },
        sort_keys=True,
    ).encode()
    sig = _sign(payload)

    ts = datetime.now(timezone.utc)
    anchor = Anchor(
        agent_id=req.agent_id,
        chain_head_hash=req.chain_head_hash,
        timestamp=ts,
        server_signature=sig,
    )
    db.add(anchor)
    await db.commit()
    await db.refresh(anchor)
    return {"anchor_id": anchor.id, "signature": sig}


@router.get("/{agent_id}")
async def get_anchor(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Anchor)
        .where(Anchor.agent_id == agent_id)
        .order_by(Anchor.timestamp.desc())
        .limit(1)
    )
    row = result.scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="No anchor found")
    return {
        "anchor_id": row.id,
        "agent_id": row.agent_id,
        "chain_head_hash": row.chain_head_hash,
        "timestamp": row.timestamp.isoformat(),
        "signature": row.server_signature,
    }
