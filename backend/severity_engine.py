"""
severity_engine.py

Turns a raw signal + context into a 0-100 severity score and a human label.
Real SOC platforms (Splunk ES risk-based alerting, Sentinel fusion, etc.) combine
several of these same ingredients: intrinsic signal severity, asset value, sensor
confidence, and behavioral frequency. This is a simplified, transparent version
of that model so the scoring logic is easy to follow and to tune.
"""

from dataclasses import dataclass

# Intrinsic severity (0-100) of each event type in isolation, before any
# contextual adjustment. Calibrated roughly against how far along the kill
# chain / how damaging the technique typically is.
BASE_SEVERITY: dict[str, float] = {
    "auth.brute_force": 40,
    "auth.impossible_travel": 55,
    "auth.privileged_login_anomaly": 65,
    "network.port_scan": 25,
    "network.exploit_attempt": 70,
    "network.c2_beacon": 75,
    "network.dns_tunneling": 68,
    "network.dos_flood": 60,
    "endpoint.suspicious_powershell": 58,
    "endpoint.scheduled_task_created": 45,
    "endpoint.defense_evasion": 62,
    "endpoint.credential_dump": 85,
    "endpoint.privilege_escalation": 80,
    "endpoint.recon_command": 35,
    "endpoint.ransomware_behavior": 95,
    "lateral.rdp_session": 50,
    "data.large_upload": 42,
    "data.exfil_to_external": 88,
    "email.mailbox_collection": 48,
    "fraud.unauthorized_transfer": 92,
}

CRITICALITY_MULTIPLIER = {
    "low": 0.80,
    "medium": 1.00,
    "high": 1.20,
    "critical": 1.40,
}

LABEL_THRESHOLDS = [
    (80, "Critical"),
    (55, "High"),
    (30, "Medium"),
    (0, "Low"),
]


@dataclass
class ScoreBreakdown:
    base: float
    criticality_multiplier: float
    confidence: float
    frequency_bonus: float
    score: float
    label: str


def label_for_score(score: float) -> str:
    for threshold, label in LABEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def score_event(
    event_type: str,
    asset_criticality: str,
    raw_confidence: float,
    recent_occurrences: int = 0,
) -> ScoreBreakdown:
    """
    score = base(event_type) * confidence * criticality_multiplier + frequency_bonus

    recent_occurrences: how many times this (src_ip, event_type) pair has fired
    in the current correlation window — repeated behavior (e.g. sustained brute
    force) escalates severity even if each individual attempt looks mild.
    """
    base = BASE_SEVERITY.get(event_type, 30)
    mult = CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)
    confidence = max(0.1, min(raw_confidence, 1.0))
    frequency_bonus = min(recent_occurrences * 3, 20)

    raw_score = base * confidence * mult + frequency_bonus
    score = max(0.0, min(round(raw_score, 1), 100.0))
    label = label_for_score(score)

    return ScoreBreakdown(
        base=base,
        criticality_multiplier=mult,
        confidence=confidence,
        frequency_bonus=frequency_bonus,
        score=score,
        label=label,
    )
