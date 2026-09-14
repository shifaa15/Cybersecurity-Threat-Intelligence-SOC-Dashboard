"""
main.py

FastAPI entrypoint. Wires together:
  - the stream-processing pipeline (stream_processor.py), run as a background
    asyncio task that continuously generates + processes synthetic events
  - a WebSocket connection manager that fans out every enriched event /
    incident update to connected dashboard clients in real time
  - a REST API for historical queries (event log, stats, MITRE matrix,
    attack timeline) that the frontend uses for its initial load and
    for filtering/searching
  - static file serving for the vanilla-JS frontend, so `uvicorn main:app`
    is the only command needed to run the whole project
"""

import asyncio
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import database
from mitre_attack import build_matrix_skeleton, TACTICS
from stream_processor import StreamProcessor

app = FastAPI(title="SOC Threat Intelligence Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- WebSocket connection manager ---------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


manager = ConnectionManager()
processor = StreamProcessor(on_broadcast=manager.broadcast)


@app.on_event("startup")
async def startup():
    database.init_db(reset=True)
    asyncio.create_task(processor.run())


# --- REST API ------------------------------------------------------------------------

@app.get("/api/events")
def list_events(
    limit: int = Query(100, le=1000),
    severity: Optional[str] = None,
    search: Optional[str] = None,
):
    return database.get_events(limit=limit, severity=severity, search=search)


@app.get("/api/incidents")
def list_incidents(limit: int = Query(50, le=200)):
    return database.get_incidents(limit=limit)


@app.get("/api/incidents/{incident_id}/events")
def incident_events(incident_id: str):
    return database.get_incident_events(incident_id)


@app.get("/api/stats")
def stats():
    s = database.get_stats()
    s["events_processed_this_session"] = processor.events_processed
    return s


@app.get("/api/mitre-matrix")
def mitre_matrix():
    matrix = build_matrix_skeleton()
    counts = database.get_mitre_counts()
    for tactic_id, bucket in matrix.items():
        for tech in bucket["techniques"]:
            tech["count"] = counts.get(tech["id"], 0)
    # Preserve kill-chain tactic order for the frontend
    ordered = [{"tactic_id": t["id"], **matrix[t["id"]]} for t in TACTICS]
    return ordered


@app.get("/api/timeline")
def timeline(minutes: int = Query(30, le=1440)):
    return database.get_timeline(minutes=minutes)


@app.get("/api/health")
def health():
    return {"status": "ok", "events_processed": processor.events_processed}


# --- WebSocket -------------------------------------------------------------------

@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Client doesn't need to send anything; keep the socket alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


# --- Static frontend ---------------------------------------------------------------

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
