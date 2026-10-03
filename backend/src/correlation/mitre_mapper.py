"""Deliberately small, explicit benchmark-label to MITRE mappings."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)
_unseen: set[str] = set()
MITRE_LABEL_MAP = {
    "PortScan": ["T1046"], "DDoS": ["T1498"], "DoS": ["T1499"], "DoS Hulk": ["T1499"],
    "DoS Slowhttptest": ["T1499"], "DoS slowloris": ["T1499"], "Bot": ["T1071", "T1105"],
    "Botnet": ["T1071", "T1105"], "Brute Force": ["T1110"], "Web Attack – SQL Injection": ["T1190"],
    "Web Attack - SQL Injection": ["T1190"], "Web Attack - XSS": ["T1190"],
    "Infiltration": ["T1041"], "Heartbleed": ["T1190"], "FTP-Patator": ["T1110"], "SSH-Patator": ["T1110"],
    "BENIGN": [],
}
TECHNIQUE_NAMES = {
    "T1046": "Network Service Discovery", "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service", "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application", "T1041": "Exfiltration Over C2 Channel"
}


def map_to_mitre(predicted_label: str) -> list[str]:
    """Map a classifier label, exposing unknown labels rather than guessing."""
    label = str(predicted_label or "UNKNOWN")
    if label not in MITRE_LABEL_MAP and label not in _unseen:
        _unseen.add(label)
        logger.warning("No MITRE mapping for predicted label '%s'", label)
    return MITRE_LABEL_MAP.get(label, ["T1499_UNKNOWN"])


def get_technique_name(technique_id: str) -> str:
    """Return a display name where the local mapping defines one."""
    return TECHNIQUE_NAMES.get(technique_id, "Unknown technique")
