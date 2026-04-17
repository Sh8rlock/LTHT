#!/usr/bin/env python3
"""
LTHT - MITRE ATT&CK Mapper
============================
Maps detection findings to MITRE ATT&CK techniques with tactic context,
descriptions, and reference URLs.
"""

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique database (Linux-focused subset)
# ---------------------------------------------------------------------------

ATTACK_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may guess passwords to attempt access to accounts. "
            "This is a common technique against SSH services."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Persistence, Privilege Escalation, Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining access or persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation, Defense Evasion",
        "description": (
            "Adversaries may circumvent mechanisms designed to control elevated "
            "privileges to gain higher-level permissions."
        ),
        "url": "https://attack.mitre.org/techniques/T1548/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1548.003": {
        "id": "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation, Defense Evasion",
        "description": (
            "Adversaries may abuse sudo or sudo caching to escalate privileges. "
            "Sudo allows users to perform commands with elevated privileges."
        ),
        "url": "https://attack.mitre.org/techniques/T1548/003/",
        "platforms": ["Linux", "macOS"],
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse Unix shell commands and scripts for execution. "
            "Includes reverse shell spawning via bash, sh, and other interpreters."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "platforms": ["Linux", "macOS"],
    },
    "T1053": {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": (
            "Adversaries may abuse task scheduling functionality to facilitate "
            "initial or recurring execution of malicious code."
        ),
        "url": "https://attack.mitre.org/techniques/T1053/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1053.003": {
        "id": "T1053.003",
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": (
            "Adversaries may abuse the cron utility to perform task scheduling "
            "for initial or recurring execution of malicious code."
        ),
        "url": "https://attack.mitre.org/techniques/T1053/003/",
        "platforms": ["Linux", "macOS"],
    },
    "T1592": {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may gather information about the victim's hosts that "
            "can be used during targeting."
        ),
        "url": "https://attack.mitre.org/techniques/T1592/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to get detailed information about the "
            "operating system and hardware."
        ),
        "url": "https://attack.mitre.org/techniques/T1082/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may look for details about the network configuration "
            "and settings of systems they access."
        ),
        "url": "https://attack.mitre.org/techniques/T1016/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1070": {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete or modify artifacts generated within systems "
            "to remove evidence of their presence."
        ),
        "url": "https://attack.mitre.org/techniques/T1070/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1070.002": {
        "id": "T1070.002",
        "name": "Indicator Removal: Clear Linux or Mac System Logs",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may clear system logs to hide evidence of intrusion. "
            "This includes clearing bash history, auth logs, and syslog."
        ),
        "url": "https://attack.mitre.org/techniques/T1070/002/",
        "platforms": ["Linux", "macOS"],
    },
    "T1070.003": {
        "id": "T1070.003",
        "name": "Indicator Removal: Clear Command History",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may clear command history to conceal activity. "
            "On Linux this includes clearing .bash_history."
        ),
        "url": "https://attack.mitre.org/techniques/T1070/003/",
        "platforms": ["Linux", "macOS"],
    },
    "T1098.004": {
        "id": "T1098.004",
        "name": "Account Manipulation: SSH Authorized Keys",
        "tactic": "Persistence",
        "description": (
            "Adversaries may modify SSH authorized_keys files to maintain "
            "persistence on a victim host."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/004/",
        "platforms": ["Linux", "macOS"],
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing "
            "command and control channel."
        ),
        "url": "https://attack.mitre.org/techniques/T1041/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over a different "
            "protocol than the existing command and control channel."
        ),
        "url": "https://attack.mitre.org/techniques/T1048/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim environment "
            "in order to hinder or disable defensive mechanisms."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1562.004": {
        "id": "T1562.004",
        "name": "Impair Defenses: Disable or Modify System Firewall",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may disable or modify system firewalls in order to "
            "bypass controls limiting network usage."
        ),
        "url": "https://attack.mitre.org/techniques/T1562/004/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
    "T1571": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using a protocol and port pairing that "
            "are not typically associated."
        ),
        "url": "https://attack.mitre.org/techniques/T1571/",
        "platforms": ["Linux", "macOS", "Windows"],
    },
}

# ---------------------------------------------------------------------------
# Rule-to-technique mapping
# ---------------------------------------------------------------------------

RULE_TECHNIQUE_MAP = {
    "LTHT-BF-001": ["T1110", "T1110.001"],
    "LTHT-BF-002": ["T1110", "T1078"],
    "LTHT-PE-001": ["T1548"],
    "LTHT-PE-002": ["T1548.003"],
    "LTHT-RS-001": ["T1059.004", "T1571"],
    "LTHT-RC-001": ["T1592", "T1082", "T1016"],
    "LTHT-RC-002": ["T1592", "T1082"],
    "LTHT-PS-001": ["T1053.003"],
    "LTHT-PS-002": ["T1053.003"],
    "LTHT-PS-003": ["T1098.004"],
    "LTHT-LT-001": ["T1070.002", "T1070.003"],
    "LTHT-EX-001": ["T1041", "T1048"],
    "LTHT-FW-001": ["T1562.004"],
}


def map_finding_to_attack(finding: dict) -> dict:
    """Enrich a single finding with MITRE ATT&CK technique details."""
    rule_id = finding.get("rule_id", "")
    technique_ids = RULE_TECHNIQUE_MAP.get(rule_id, [])

    techniques = []
    tactics = set()
    for tid in technique_ids:
        tech = ATTACK_TECHNIQUES.get(tid)
        if tech:
            techniques.append(tech)
            for t in tech["tactic"].split(", "):
                tactics.add(t.strip())

    finding["mitre_techniques"] = techniques
    finding["mitre_tactics"] = sorted(tactics)

    return finding


def map_all_findings(findings: list) -> list:
    """Enrich all findings with MITRE ATT&CK mappings."""
    return [map_finding_to_attack(f) for f in findings]


def get_attack_summary(findings: list) -> dict:
    """Generate a summary of ATT&CK techniques and tactics across all findings."""
    technique_counts = {}
    tactic_counts = {}

    for finding in findings:
        for tech in finding.get("mitre_techniques", []):
            tid = tech["id"]
            if tid not in technique_counts:
                technique_counts[tid] = {
                    "technique": tech,
                    "finding_count": 0,
                    "max_severity": "LOW",
                    "max_risk": 0,
                }
            technique_counts[tid]["finding_count"] += 1
            if finding.get("risk_score", 0) > technique_counts[tid]["max_risk"]:
                technique_counts[tid]["max_risk"] = finding["risk_score"]
                technique_counts[tid]["max_severity"] = finding.get("severity", "LOW")

        for tactic in finding.get("mitre_tactics", []):
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    return {
        "techniques_observed": len(technique_counts),
        "tactics_observed": len(tactic_counts),
        "technique_details": technique_counts,
        "tactic_breakdown": dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)),
    }
