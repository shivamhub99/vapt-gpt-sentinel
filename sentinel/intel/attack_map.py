"""
MITRE ATT&CK Mapping Engine for VAPT-GPT Sentinel.
Maps canonical CWE identifiers to MITRE Enterprise ATT&CK Techniques and Tactics.
"""

from typing import Dict, Optional

CWE_TO_ATTACK: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-79": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "CWE-78": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter: Unix/Windows Shell",
        "tactic": "Execution",
    },
    "CWE-798": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
    },
    "CWE-639": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts: Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "CWE-1395": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: Vulnerable Dependency",
        "tactic": "Initial Access",
    },
    "CWE-22": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery / Path Traversal",
        "tactic": "Discovery",
    },
    "CWE-502": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution: Insecure Deserialization",
        "tactic": "Execution",
    },
    "CWE-693": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses: Missing Security Configuration",
        "tactic": "Defense Evasion",
    },
}


def get_attack_technique(cwe: str) -> Optional[Dict[str, str]]:
    """Returns MITRE ATT&CK technique details for a canonical CWE."""
    return CWE_TO_ATTACK.get(cwe.upper())
