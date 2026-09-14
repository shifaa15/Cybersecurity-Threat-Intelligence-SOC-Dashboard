"""
stream_processor.py

The heart of the "SIEM" simulation. Models the classic stream-processing
pipeline a real SOC platform runs (think: Kafka consumer -> enrichment
service -> scoring service -> correlation engine -> sink), collapsed into
a single asyncio task since this project runs as one process:

    ingest (event_simulator)
        -> normalize (already RawEvent)
        -> enrich (MITRE ATT&CK mapping)
        -> score (severity_engine)
        -> correlate (sliding-window incident grouping)
        -> persist (database)
        -> broadcast (websocket fan-out to connected dashboards)

A sliding time window tracks how often a given (src_ip, event_type) pair has
fired recently, which feeds the severity engine's frequency bonus, and a
separate correlation window groups events sharing a src_ip + asset into a
single "incident" so the frontend can render an attack timeline / kill chain
rather than a flat log.
"""

import asyncio
import random
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Awaitable

import database
from event_simulator import Campaign, generate_noise_event
from mitre_attack import techniques_for_event, tactic_name
from models import RawEvent
from severity_engine import score_event

FREQUENCY_WINDOW = timedelta(minutes=2)
CORRELATION_WINDOW = timedelta(minutes=3)
INCIDENT_TITLES = {
    "auth.brute_force": "Brute-force login activity",
    "network.exploit_attempt": "Exploit attempt against exposed service",
    "endpoint.recon_command": "Host reconnaissance activity",
    "network.c2_beacon": "Possible command-and-control beaconing",
    "data.exfil_to_external": "Suspected data exfiltration",
}


class StreamProcessor:
    def __init__(self, on_broadcast: Callable[[dict], Awaitable[None]]):
        self.on_broadcast = on_broadcast
        self._freq_window: dict[tuple, deque] = defaultdict(deque)
        self._active_incidents: dict[tuple, dict] = {}  # (src_ip, asset) -> incident dict
        self._active_campaign: Campaign | None = None
        self._running = False
        self.events_processed = 0

    # -- correlation -----------------------------------------------------------------

    def _frequency_bonus_count(self, src_ip: str, event_type: str, now: datetime) -> int:
        key = (src_ip, event_type)
        dq = self._freq_window[key]
        dq.append(now)
        while dq and now - dq[0] > FREQUENCY_WINDOW:
            dq.popleft()
        return len(dq) - 1  # occurrences prior to this one

    def _correlate(self, enriched: dict, now: datetime) -> str:
        key = (enriched["src_ip"], enriched["asset"])
        incident = self._active_incidents.get(key)

        if incident and now - datetime.fromisoformat(incident["last_seen_at"]) > CORRELATION_WINDOW:
            incident["status"] = "investigating"
            database.upsert_incident(incident)
            incident = None
            self._active_incidents.pop(key, None)

        if incident is None:
            title = INCIDENT_TITLES.get(enriched["event_type"], "Suspicious activity chain")
            incident = {
                "id": str(uuid.uuid4()),
                "title": f"{title} — {enriched['asset']}",
                "src_ip": enriched["src_ip"],
                "asset": enriched["asset"],
                "started_at": now.isoformat(),
                "last_seen_at": now.isoformat(),
                "event_ids": [],
                "max_severity_score": 0,
                "max_severity_label": "Low",
                "tactics_observed": [],
                "status": "open",
            }
            self._active_incidents[key] = incident

        incident["event_ids"].append(enriched["id"])
        incident["last_seen_at"] = now.isoformat()
        if enriched["severity_score"] > incident["max_severity_score"]:
            incident["max_severity_score"] = enriched["severity_score"]
            incident["max_severity_label"] = enriched["severity_label"]
        for t in enriched["mitre_techniques"]:
            if t["tactic"] not in incident["tactics_observed"]:
                incident["tactics_observed"].append(t["tactic"])

        database.upsert_incident(incident)
        return incident["id"]

    # -- pipeline ---------------------------------------------------------------------

    async def _process(self, raw: RawEvent):
        now = raw.timestamp

        techniques = techniques_for_event(raw.event_type)
        mitre_payload = [
            {"id": t.id, "name": t.name, "tactic_id": t.tactic_id, "tactic": tactic_name(t.tactic_id)}
            for t in techniques
        ]

        occurrences = self._frequency_bonus_count(raw.src_ip, raw.event_type, now)
        breakdown = score_event(
            event_type=raw.event_type,
            asset_criticality=raw.asset_criticality,
            raw_confidence=raw.raw_confidence,
            recent_occurrences=occurrences,
        )

        enriched = raw.model_dump()
        enriched["id"] = str(uuid.uuid4())
        enriched["timestamp"] = now.isoformat()
        enriched["mitre_techniques"] = mitre_payload
        enriched["severity_score"] = breakdown.score
        enriched["severity_label"] = breakdown.label

        incident_id = self._correlate(enriched, now)
        enriched["incident_id"] = incident_id

        database.insert_event(enriched)
        self.events_processed += 1

        await self.on_broadcast({"type": "event", "payload": enriched})
        incident = self._active_incidents.get((raw.src_ip, raw.asset))
        if incident:
            await self.on_broadcast({"type": "incident", "payload": incident})

    async def _next_raw_event(self) -> RawEvent:
        # ~35% chance to advance an in-flight scripted campaign (or start a new one),
        # otherwise emit isolated background noise. This keeps the feed realistic:
        # mostly noise, punctuated by coherent multi-stage attacks.
        if self._active_campaign and not self._active_campaign.done:
            return self._active_campaign.next_event()

        if self._active_campaign and self._active_campaign.done:
            self._active_campaign = None

        if random.random() < 0.30:
            self._active_campaign = Campaign()
            return self._active_campaign.next_event()

        return generate_noise_event()

    async def run(self):
        self._running = True
        while self._running:
            raw = await self._next_raw_event()
            await self._process(raw)
            # campaign stages fire in quicker bursts than background noise
            delay = random.uniform(0.4, 1.1) if self._active_campaign else random.uniform(0.8, 2.2)
            await asyncio.sleep(delay)

    def stop(self):
        self._running = False
