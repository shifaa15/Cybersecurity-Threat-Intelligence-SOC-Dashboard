"""
mitre_attack.py

A trimmed-down local reference of MITRE ATT&CK (Enterprise) tactics and
techniques, plus the logic that maps a normalized security event onto one
or more techniques. In a production SOC this table would be pulled from
the official ATT&CK STIX bundle (https://github.com/mitre/cti) and kept
in a proper datastore; here it's inlined so the project runs with zero
external dependencies or network calls.
"""

from dataclasses import dataclass
from typing import Optional

# --- Tactics, in kill-chain order -------------------------------------------------

TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0040", "name": "Impact"},
]

TACTIC_ORDER = {t["id"]: i for i, t in enumerate(TACTICS)}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic_id: str


# --- A working subset of Enterprise ATT&CK techniques ------------------------------

TECHNIQUES: dict[str, Technique] = {
    "T1110": Technique("T1110", "Brute Force", "TA0006"),
    "T1110.001": Technique("T1110.001", "Brute Force: Password Guessing", "TA0006"),
    "T1078": Technique("T1078", "Valid Accounts", "TA0001"),
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "TA0001"),
    "T1595": Technique("T1595", "Active Scanning", "TA0007"),
    "T1046": Technique("T1046", "Network Service Discovery", "TA0007"),
    "T1059": Technique("T1059", "Command and Scripting Interpreter", "TA0002"),
    "T1059.001": Technique("T1059.001", "PowerShell", "TA0002"),
    "T1203": Technique("T1203", "Exploitation for Client Execution", "TA0002"),
    "T1547": Technique("T1547", "Boot or Logon Autostart Execution", "TA0003"),
    "T1053": Technique("T1053", "Scheduled Task/Job", "TA0003"),
    "T1068": Technique("T1068", "Exploitation for Privilege Escalation", "TA0004"),
    "T1548": Technique("T1548", "Abuse Elevation Control Mechanism", "TA0004"),
    "T1027": Technique("T1027", "Obfuscated Files or Information", "TA0005"),
    "T1562": Technique("T1562", "Impair Defenses", "TA0005"),
    "T1070": Technique("T1070", "Indicator Removal", "TA0005"),
    "T1003": Technique("T1003", "OS Credential Dumping", "TA0006"),
    "T1552": Technique("T1552", "Unsecured Credentials", "TA0006"),
    "T1087": Technique("T1087", "Account Discovery", "TA0007"),
    "T1082": Technique("T1082", "System Information Discovery", "TA0007"),
    "T1021": Technique("T1021", "Remote Services", "TA0008"),
    "T1021.001": Technique("T1021.001", "Remote Desktop Protocol", "TA0008"),
    "T1560": Technique("T1560", "Archive Collected Data", "TA0009"),
    "T1114": Technique("T1114", "Email Collection", "TA0009"),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "TA0010"),
    "T1048": Technique("T1048", "Exfiltration Over Alternative Protocol", "TA0010"),
    "T1071": Technique("T1071", "Application Layer Protocol", "TA0011"),
    "T1071.004": Technique("T1071.004", "DNS", "TA0011"),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "TA0011"),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "TA0040"),
    "T1498": Technique("T1498", "Network Denial of Service", "TA0040"),
    "T1657": Technique("T1657", "Financial Theft", "TA0040"),
}

# --- Event type -> candidate technique(s) -------------------------------------------
# A real SOC uses Sigma rules / correlation logic for this. This mapping stands in
# for that rule engine: each synthetic event type is pre-associated with the
# technique(s) it is characteristic of.

EVENT_TYPE_TECHNIQUES: dict[str, list[str]] = {
    "auth.brute_force": ["T1110.001", "T1110"],
    "auth.impossible_travel": ["T1078"],
    "auth.privileged_login_anomaly": ["T1078", "T1068"],
    "network.port_scan": ["T1595", "T1046"],
    "network.exploit_attempt": ["T1190"],
    "network.c2_beacon": ["T1071", "T1105"],
    "network.dns_tunneling": ["T1071.004"],
    "network.dos_flood": ["T1498"],
    "endpoint.suspicious_powershell": ["T1059.001", "T1027"],
    "endpoint.scheduled_task_created": ["T1053", "T1547"],
    "endpoint.defense_evasion": ["T1562", "T1070"],
    "endpoint.credential_dump": ["T1003"],
    "endpoint.privilege_escalation": ["T1068", "T1548"],
    "endpoint.recon_command": ["T1087", "T1082"],
    "endpoint.ransomware_behavior": ["T1486"],
    "lateral.rdp_session": ["T1021.001", "T1021"],
    "data.large_upload": ["T1560", "T1048"],
    "data.exfil_to_external": ["T1041", "T1048"],
    "email.mailbox_collection": ["T1114"],
    "fraud.unauthorized_transfer": ["T1657"],
}


def techniques_for_event(event_type: str) -> list[Technique]:
    """Return the ATT&CK techniques a given (already-classified) event type maps to."""
    ids = EVENT_TYPE_TECHNIQUES.get(event_type, [])
    return [TECHNIQUES[t] for t in ids if t in TECHNIQUES]


def tactic_name(tactic_id: str) -> str:
    for t in TACTICS:
        if t["id"] == tactic_id:
            return t["name"]
    return "Unknown"


def build_matrix_skeleton() -> dict:
    """Tactic-ordered skeleton with every known technique bucketed under its tactic.
    Used by the frontend to render the ATT&CK heat-matrix; hit-counts are merged
    in separately by the API layer.
    """
    matrix = {t["id"]: {"tactic": t["name"], "techniques": []} for t in TACTICS}
    for tech in TECHNIQUES.values():
        matrix[tech.tactic_id]["techniques"].append(
            {"id": tech.id, "name": tech.name, "count": 0}
        )
    return matrix
