"""FastAPI application factory."""
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from server.config import config
from server.database import init_db
from server.middleware import SecurityMiddleware
from server.routers import alerts, anchor, certs, events
from server.routers import dashboard, policy, reports


def _configure_notification_bus() -> None:
    """Register configured notification sinks on startup."""
    from server.notifications.bus import get_bus

    bus = get_bus()
    sinks_cfg = config.notification_sinks.strip()
    if not sinks_cfg:
        return

    for sink_name in [s.strip() for s in sinks_cfg.split(",") if s.strip()]:
        if sink_name == "email":
            if config.smtp_to:
                from server.notifications.email_sink import EmailSink

                bus.register(
                    EmailSink(
                        from_addr=config.smtp_from,
                        to_addrs=[a.strip() for a in config.smtp_to.split(",")],
                        smtp_host=config.smtp_host,
                        smtp_port=config.smtp_port,
                        smtp_user=config.smtp_user,
                        smtp_pass=config.smtp_pass,
                    )
                )
        elif sink_name == "slack":
            if config.slack_webhook_url:
                from server.notifications.slack_sink import SlackSink

                bus.register(SlackSink(webhook_url=config.slack_webhook_url))
        elif sink_name == "syslog":
            from server.notifications.syslog_sink import SyslogSink

            bus.register(SyslogSink(host=config.syslog_host, port=config.syslog_port))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    _configure_notification_bus()
    yield


app = FastAPI(
    title="Insider Threat Detection Server",
    version="2.0.0",
    lifespan=lifespan,
)

# Security middleware (API-key + rate-limiting)
# Auth is disabled when api_key is empty so tests run without headers.
app.add_middleware(
    SecurityMiddleware,
    api_key=config.api_key if config.api_key != "changeme" else "",
    rate_limit_requests=config.rate_limit_requests,
    rate_limit_window=config.rate_limit_window_seconds,
)

app.include_router(events.router)
app.include_router(anchor.router)
app.include_router(certs.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(policy.router)
app.include_router(reports.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("server.main:app", host=config.host, port=config.port, reload=False)
