"""Dashboard endpoints + WebSocket live alert feed."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Set

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Alert, Event

router = APIRouter(tags=["dashboard"])
logger = logging.getLogger(__name__)

# Lazily initialise templates only if the templates directory exists
_templates: Jinja2Templates | None = None

try:
    import pathlib

    _tpl_dir = pathlib.Path(__file__).parent.parent / "templates"
    if _tpl_dir.is_dir():
        _templates = Jinja2Templates(directory=str(_tpl_dir))
except Exception:
    pass

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------


class _ConnectionManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        logger.info("WS client connected (total: %d)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        logger.info("WS client disconnected (total: %d)", len(self._connections))

    async def broadcast(self, data: Dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)


manager = _ConnectionManager()


def get_manager() -> _ConnectionManager:
    """FastAPI dependency – returns the singleton connection manager."""
    return manager


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@router.get("/api/v1/dashboard/summary")
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Return a high-level summary for the dashboard."""
    # Total events
    total_events = (await db.execute(select(func.count(Event.id)))).scalar() or 0

    # Total alerts
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0

    # Open alerts (all alerts for now — no "resolved" state yet)
    open_alerts = total_alerts

    # Active agents (distinct agent_ids seen in last 24 h)
    from datetime import datetime, timedelta, timezone

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    active_agents_result = await db.execute(
        select(func.count(func.distinct(Event.agent_id))).where(Event.timestamp >= since)
    )
    active_agents = active_agents_result.scalar() or 0

    # Top 5 risky devices (by total alert score)
    top_devices_result = await db.execute(
        select(Alert.device_id, func.sum(Alert.score).label("total_score"))
        .group_by(Alert.device_id)
        .order_by(func.sum(Alert.score).desc())
        .limit(5)
    )
    top_devices = [
        {"device_id": r.device_id, "total_score": float(r.total_score)}
        for r in top_devices_result
    ]

    # Recent 10 alerts
    recent_alerts_result = await db.execute(
        select(Alert).order_by(Alert.timestamp.desc()).limit(10)
    )
    recent_alerts: List[Dict[str, Any]] = [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "rule": r.rule,
            "score": r.score,
            "device_id": r.device_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in recent_alerts_result.scalars().all()
    ]

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "active_agents_24h": active_agents,
        "top_risky_devices": top_devices,
        "recent_alerts": recent_alerts,
    }


# ---------------------------------------------------------------------------
# WebSocket live feed
# ---------------------------------------------------------------------------


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    """WebSocket endpoint — server pushes alert JSON on each new alert."""
    await manager.connect(websocket)
    try:
        # Keep the connection alive until the client disconnects
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# HTML dashboard page (served only when Jinja2 templates are available)
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request, db: AsyncSession = Depends(get_db)):
    summary = await dashboard_summary(db=db)
    if _templates:
        return _templates.TemplateResponse(
            "dashboard.html", {"request": request, "summary": summary}
        )
    # Fallback: minimal inline HTML (no Jinja2 dependency)
    html = _inline_dashboard(summary)
    return HTMLResponse(content=html)


def _inline_dashboard(summary: Dict[str, Any]) -> str:
    recent = "".join(
        f"<tr><td>{a['id']}</td><td>{a['agent_id']}</td>"
        f"<td>{a['rule']}</td><td>{a['score']:.0f}</td>"
        f"<td>{a['device_id']}</td><td>{a['timestamp']}</td></tr>"
        for a in summary["recent_alerts"]
    )
    top = "".join(
        f"<tr><td>{d['device_id']}</td><td>{d['total_score']:.0f}</td></tr>"
        for d in summary["top_risky_devices"]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="15">
<title>Insider Threat Dashboard</title>
<style>
  body {{ font-family: sans-serif; background:#111; color:#eee; margin:2rem; }}
  h1 {{ color:#f90; }} h2 {{ color:#aaa; }}
  .card {{ display:inline-block; background:#222; border-radius:8px;
           padding:1rem 2rem; margin:.5rem; text-align:center; }}
  .card .num {{ font-size:2.5rem; font-weight:bold; color:#f90; }}
  table {{ border-collapse:collapse; width:100%; margin-top:.5rem; }}
  th,td {{ border:1px solid #444; padding:.4rem .8rem; text-align:left; font-size:.85rem; }}
  th {{ background:#333; }}
</style>
</head>
<body>
<h1>&#x1F6E1; Insider Threat Detection Dashboard</h1>
<div>
  <div class="card"><div class="num">{summary["total_events"]}</div>Total Events</div>
  <div class="card"><div class="num">{summary["total_alerts"]}</div>Total Alerts</div>
  <div class="card"><div class="num">{summary["open_alerts"]}</div>Open Alerts</div>
  <div class="card"><div class="num">{summary["active_agents_24h"]}</div>Active Agents (24h)</div>
</div>

<h2>Recent Alerts</h2>
<table>
  <tr><th>ID</th><th>Agent</th><th>Rule</th><th>Score</th><th>Device</th><th>Time</th></tr>
  {recent or "<tr><td colspan=6>No alerts yet</td></tr>"}
</table>

<h2>Top Risky Devices</h2>
<table>
  <tr><th>Device ID</th><th>Total Score</th></tr>
  {top or "<tr><td colspan=2>None</td></tr>"}
</table>

<p style="color:#555;font-size:.75rem">Auto-refreshes every 15 s &mdash;
<a href="/ws/alerts" style="color:#777">WS feed</a> &mdash;
<a href="/docs" style="color:#777">API docs</a></p>
</body>
</html>"""
