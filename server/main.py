"""FastAPI application factory."""
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from server.config import config
from server.database import init_db
from server.routers import alerts, anchor, certs, events


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="Insider Threat Detection Server",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(events.router)
app.include_router(anchor.router)
app.include_router(certs.router)
app.include_router(alerts.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("server.main:app", host=config.host, port=config.port, reload=False)
