"""
event_simulator.py

Stands in for a real log stream (Kafka topic fed by Filebeat/Fluentd, a SIEM
forwarder, EDR telemetry, etc). Produces two kinds of traffic:

  1. Background noise — isolated, mostly-benign-looking events from random
     sources, the way a real network constantly generates low-grade signal.
  2. Attack campaigns — a scripted, multi-stage kill chain from a single
     attacker IP against a single asset, spaced out over time, so the
     correlation engine and attack-timeline UI have something coherent to
     stitch together (recon -> brute force -> priv esc -> lateral movement
     -> exfiltration).

Everything here is deterministic-ish randomness (no real network calls).
"""

import random
import uuid
from datetime import datetime

from models import RawEvent

ASSETS = [
    ("WKS-FIN-014", "high"),
    ("WKS-ENG-231", "medium"),
    ("SRV-DB-PROD-01", "critical"),
    ("SRV-APP-PROD-03", "critical"),
    ("SRV-WEB-EDGE-02", "high"),
    ("WKS-HR-009", "medium"),
    ("DC-CORP-01", "critical"),
    ("WKS-SALES-118", "low"),
    ("SRV-FILE-01", "high"),
    ("LAPTOP-EXEC-002", "critical"),
]

USERS = [
    "j.martinez", "s.chen", "a.patel", "r.okafor", "m.svensson",
    "t.nguyen", "k.oconnor", "d.silva", "admin-svc", "backup-svc",
]

EXTERNAL_IPS = [
    "185.220.101.47", "45.155.205.19", "91.242.217.5", "103.75.190.22",
    "194.165.16.71", "23.129.64.184", "146.70.44.93", "5.180.212.10",
]

INTERNAL_SUBNET = "10.20."

NOISE_EVENT_TYPES = [
    "network.port_scan",
    "auth.brute_force",
    "network.exploit_attempt",
    "endpoint.suspicious_powershell",
    "network.dns_tunneling",
    "lateral.rdp_session",
    "data.large_upload",
    "email.mailbox_collection",
    "endpoint.recon_command",
    "network.dos_flood",
]

NOISE_DESCRIPTIONS = {
    "network.port_scan": "Sequential connection attempts across {n} ports observed from {ip}",
    "auth.brute_force": "{n} failed login attempts for user {user} within 60s window",
    "network.exploit_attempt": "IDS signature match for known CVE exploit pattern from {ip}",
    "endpoint.suspicious_powershell": "Encoded PowerShell command executed on {asset}",
    "network.dns_tunneling": "Anomalous DNS query volume with high-entropy subdomains from {asset}",
    "lateral.rdp_session": "New RDP session to {asset} from unfamiliar internal host",
    "data.large_upload": "{mb} MB outbound transfer from {asset} to external endpoint",
    "email.mailbox_collection": "Bulk mailbox export detected for user {user}",
    "endpoint.recon_command": "Local account and system enumeration commands run on {asset}",
    "network.dos_flood": "Traffic spike ({n}x baseline) directed at {asset}",
}


def _internal_ip() -> str:
    return f"{INTERNAL_SUBNET}{random.randint(1, 254)}.{random.randint(1, 254)}"


def _fmt(event_type: str, **overrides) -> str:
    template = NOISE_DESCRIPTIONS[event_type]
    ctx = {
        "n": random.randint(4, 40),
        "ip": overrides.get("ip", random.choice(EXTERNAL_IPS)),
        "user": overrides.get("user", random.choice(USERS)),
        "asset": overrides.get("asset", random.choice(ASSETS)[0]),
        "mb": random.randint(50, 900),
    }
    return template.format(**ctx)


def generate_noise_event() -> RawEvent:
    event_type = random.choice(NOISE_EVENT_TYPES)
    asset, criticality = random.choice(ASSETS)
    src_is_external = random.random() < 0.55
    src_ip = random.choice(EXTERNAL_IPS) if src_is_external else _internal_ip()

    return RawEvent(
        event_type=event_type,
        source=random.choice(["firewall-edge-01", "edr-agent", "idp-okta", "dns-resolver", "ids-suricata"]),
        src_ip=src_ip,
        dest_ip=_internal_ip(),
        user=random.choice(USERS) if random.random() < 0.6 else None,
        asset=asset,
        asset_criticality=criticality,
        description=_fmt(event_type, ip=src_ip, asset=asset),
        raw_confidence=round(random.uniform(0.35, 0.85), 2),
        timestamp=datetime.utcnow(),
    )


# --- Scripted multi-stage campaigns -------------------------------------------------
# Each stage: (event_type, description_template, confidence)

CAMPAIGN_TEMPLATES = [
    {
        "name": "Credential stuffing -> lateral movement",
        "stages": [
            ("network.port_scan", "External scan sweeping open services on {asset}", 0.5),
            ("auth.brute_force", "37 failed logins for {user} followed by a successful login", 0.7),
            ("auth.impossible_travel", "Login for {user} from geolocation inconsistent with prior session", 0.75),
            ("endpoint.recon_command", "whoami / net group / systeminfo executed on {asset} moments after login", 0.8),
            ("lateral.rdp_session", "RDP session opened from {asset} to DC-CORP-01 using {user} credentials", 0.85),
            ("endpoint.credential_dump", "LSASS memory access consistent with credential dumping tool on {asset}", 0.9),
        ],
    },
    {
        "name": "Web exploit -> ransomware staging",
        "stages": [
            ("network.exploit_attempt", "Exploit payload matching known RCE signature sent to {asset}", 0.65),
            ("endpoint.suspicious_powershell", "Base64-encoded PowerShell dropper executed on {asset}", 0.8),
            ("endpoint.defense_evasion", "EDR service stopped and event log cleared on {asset}", 0.85),
            ("endpoint.privilege_escalation", "Token manipulation used to gain SYSTEM privileges on {asset}", 0.85),
            ("endpoint.scheduled_task_created", "Scheduled task created for persistence on {asset}", 0.7),
            ("endpoint.ransomware_behavior", "Mass file rename/encrypt pattern detected on {asset}", 0.95),
        ],
    },
    {
        "name": "Insider data exfiltration",
        "stages": [
            ("endpoint.recon_command", "File share enumeration commands run by {user} on {asset}", 0.5),
            ("data.large_upload", "612 MB archive uploaded from {asset} to personal cloud storage", 0.7),
            ("email.mailbox_collection", "Bulk export of finance mailbox performed by {user}", 0.75),
            ("data.exfil_to_external", "Encrypted archive transferred from {asset} to unrecognized external IP", 0.85),
        ],
    },
    {
        "name": "C2 beacon -> fraud attempt",
        "stages": [
            ("network.c2_beacon", "Periodic beaconing to known C2 infrastructure from {asset}", 0.7),
            ("network.dns_tunneling", "High-entropy DNS queries consistent with C2 tunneling from {asset}", 0.75),
            ("endpoint.privilege_escalation", "Privilege escalation attempt on {asset} following beacon activity", 0.8),
            ("fraud.unauthorized_transfer", "Unauthorized wire transfer initiated from {user} session on {asset}", 0.9),
        ],
    },
]


class Campaign:
    """A stateful iterator over one scripted attack chain, sharing a single
    attacker IP, asset and user across every stage so the correlation engine
    can group them into one incident."""

    def __init__(self):
        template = random.choice(CAMPAIGN_TEMPLATES)
        asset, criticality = random.choice(ASSETS)
        self.name = template["name"]
        self.src_ip = random.choice(EXTERNAL_IPS)
        self.asset = asset
        self.criticality = criticality
        self.user = random.choice(USERS)
        self.stages = template["stages"]
        self.index = 0

    @property
    def done(self) -> bool:
        return self.index >= len(self.stages)

    def next_event(self) -> RawEvent:
        event_type, template, confidence = self.stages[self.index]
        self.index += 1
        description = template.format(asset=self.asset, user=self.user)
        return RawEvent(
            event_type=event_type,
            source="correlated-campaign",
            src_ip=self.src_ip,
            dest_ip=_internal_ip(),
            user=self.user,
            asset=self.asset,
            asset_criticality=self.criticality,
            description=description,
            raw_confidence=confidence,
            timestamp=datetime.utcnow(),
        )
