from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """What a log source (firewall, EDR agent, IdP, DNS resolver...) emits before
    any enrichment. This is the shape that would arrive off a Kafka topic / syslog
    feed / SIEM forwarder in a real deployment."""

    event_type: str
    source: str  # originating sensor, e.g. "edr-agent", "firewall-edge-01"
    src_ip: str
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    asset: str  # hostname / asset the event pertains to
    asset_criticality: str = "medium"  # low | medium | high | critical
    description: str
    raw_confidence: float = 0.6  # 0-1 sensor confidence the signal is real
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EnrichedEvent(RawEvent):
    """A RawEvent after it has passed through the stream-processing pipeline:
    MITRE-mapped, scored, and assigned an id + incident linkage."""

    id: str
    mitre_techniques: list[dict] = Field(default_factory=list)  # [{id, name, tactic_id, tactic}]
    severity_score: float
    severity_label: str  # Low | Medium | High | Critical
    incident_id: Optional[str] = None


class Incident(BaseModel):
    """A correlated chain of events the engine believes belong to a single
    attack narrative (e.g. recon -> brute force -> lateral movement)."""

    id: str
    title: str
    src_ip: str
    asset: str
    started_at: datetime
    last_seen_at: datetime
    event_ids: list[str] = Field(default_factory=list)
    max_severity_score: float = 0
    max_severity_label: str = "Low"
    tactics_observed: list[str] = Field(default_factory=list)
    status: str = "open"  # open | investigating | contained | closed
