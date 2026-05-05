"""Certificate and trusted-hash management endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import AgentCert, TrustedBinaryHash

router = APIRouter(prefix="/api/v1/certs", tags=["certs"])
logger = logging.getLogger(__name__)

_ca = None


def _get_ca():
    global _ca
    if _ca is None:
        from server.ca.cert_authority import CertificateAuthority
        from server.config import config

        _ca = CertificateAuthority(config.ca_cert_path, config.ca_key_path)
    return _ca


class IssueRequest(BaseModel):
    agent_id: str
    csr_pem: str


class RevokeRequest(BaseModel):
    agent_id: str


class TrustedHashUpsert(BaseModel):
    agent_id: str
    hash_value: str


@router.post("/issue", status_code=201)
async def issue_cert(req: IssueRequest, db: AsyncSession = Depends(get_db)):
    ca = _get_ca()
    cert_pem = ca.issue_cert(req.agent_id, req.csr_pem)
    expires_at = datetime.now(timezone.utc) + timedelta(days=365)
    record = AgentCert(
        agent_id=req.agent_id,
        cert_pem=cert_pem,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(record)
    await db.commit()
    return {"cert_pem": cert_pem}


@router.post("/revoke")
async def revoke_cert(req: RevokeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AgentCert)
        .where(AgentCert.agent_id == req.agent_id)
        .where(AgentCert.revoked.is_(False))
        .order_by(AgentCert.issued_at.desc())
        .limit(1)
    )
    cert = result.scalars().first()
    if not cert:
        raise HTTPException(status_code=404, detail="No active cert found")
    cert.revoked = True
    await db.commit()
    return {"status": "revoked"}


@router.get("/trusted-hash/{agent_id}")
async def get_trusted_hash(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(TrustedBinaryHash).where(TrustedBinaryHash.agent_id == agent_id)
    )
    row = result.scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="No trusted hash registered")
    return {"agent_id": agent_id, "hash_value": row.hash_value}


@router.post("/trusted-hash", status_code=201)
async def set_trusted_hash(req: TrustedHashUpsert, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(TrustedBinaryHash).where(TrustedBinaryHash.agent_id == req.agent_id)
    )
    row = result.scalars().first()
    if row:
        row.hash_value = req.hash_value
        row.updated_at = datetime.now(timezone.utc)
    else:
        db.add(
            TrustedBinaryHash(
                agent_id=req.agent_id,
                hash_value=req.hash_value,
            )
        )
    await db.commit()
    return {"status": "ok"}
