#!/usr/bin/env python3
"""
LTHT - Detection Engine
========================
IOC detection rules for common Linux attack patterns.
Each rule evaluates parsed log entries and produces findings with severity and risk scores.
"""

from collections import Counter, defaultdict


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _group_by_key(entries: list, key: str) -> dict:
    """Group a list of dicts by a given key."""
    groups = defaultdict(list)
    for e in entries:
        groups[e.get(key, "unknown")].append(e)
    return groups


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def detect_brute_force(auth_entries: list, threshold: int = 5) -> list:
    """Detect SSH brute force attempts — multiple failed logins from same IP."""
    findings = []
    failed = [e for e in auth_entries if e["event_type"] == "ssh_failed_login"]
    by_ip = _group_by_key(failed, "src_ip")

    for ip, attempts in by_ip.items():
        if len(attempts) >= threshold:
            users_targeted = list(set(a.get("user", "unknown") for a in attempts))
            first = attempts[0].get("timestamp", "unknown")
            last = attempts[-1].get("timestamp", "unknown")

            severity = "CRITICAL" if len(attempts) >= 20 else "HIGH"
            risk = min(100, len(attempts) * 5)

            findings.append({
                "rule_id": "LTHT-BF-001",
                "rule_name": "SSH Brute Force Detected",
                "severity": severity,
                "risk_score": risk,
                "description": (
                    f"Detected {len(attempts)} failed SSH login attempts from {ip} "
                    f"targeting user(s): {', '.join(users_targeted[:5])}"
                ),
                "source_ip": ip,
                "attempt_count": len(attempts),
                "users_targeted": users_targeted,
                "first_seen": first,
                "last_seen": last,
                "evidence": [a["raw"] for a in attempts[:5]],
                "recommendation": (
                    "Block the source IP via firewall rules. Implement fail2ban or "
                    "similar rate-limiting. Enforce key-based SSH authentication. "
                    "Review accounts for unauthorized access."
                ),
            })

    return findings


def detect_brute_force_success(auth_entries: list, threshold: int = 5) -> list:
    """Detect successful login after brute force — failed logins followed by accepted."""
    findings = []
    failed = [e for e in auth_entries if e["event_type"] == "ssh_failed_login"]
    accepted = [e for e in auth_entries if e["event_type"] == "ssh_accepted_login"]

    failed_ips = _group_by_key(failed, "src_ip")
    accepted_ips = _group_by_key(accepted, "src_ip")

    for ip in set(failed_ips) & set(accepted_ips):
        if len(failed_ips[ip]) >= threshold:
            findings.append({
                "rule_id": "LTHT-BF-002",
                "rule_name": "Successful Login After Brute Force",
                "severity": "CRITICAL",
                "risk_score": 95,
                "description": (
                    f"IP {ip} had {len(failed_ips[ip])} failed attempts then successfully "
                    f"authenticated. Likely credential compromise."
                ),
                "source_ip": ip,
                "failed_count": len(failed_ips[ip]),
                "successful_logins": [a["raw"] for a in accepted_ips[ip][:3]],
                "evidence": [a["raw"] for a in failed_ips[ip][:3]] + [a["raw"] for a in accepted_ips[ip][:2]],
                "recommendation": (
                    "Immediately investigate the authenticated session. Reset credentials "
                    "for affected user(s). Check for persistence mechanisms (SSH keys, "
                    "cron jobs, new user accounts). Block the source IP."
                ),
            })

    return findings


def detect_privilege_escalation(auth_entries: list) -> list:
    """Detect privilege escalation via sudo abuse and su attempts."""
    findings = []

    # Failed su attempts
    su_failed = [e for e in auth_entries if e["event_type"] == "su_attempt" and e.get("status") == "failed"]
    if su_failed:
        by_user = _group_by_key(su_failed, "user")
        for user, attempts in by_user.items():
            findings.append({
                "rule_id": "LTHT-PE-001",
                "rule_name": "Failed Privilege Escalation (su)",
                "severity": "HIGH",
                "risk_score": 70,
                "description": (
                    f"User '{user}' made {len(attempts)} failed su attempt(s) to escalate privileges."
                ),
                "user": user,
                "attempt_count": len(attempts),
                "evidence": [a["raw"] for a in attempts[:5]],
                "recommendation": (
                    "Review the user's activity and access permissions. Check for "
                    "lateral movement. Restrict su access via /etc/pam.d/su."
                ),
            })

    # Suspicious sudo commands
    sudo_entries = [e for e in auth_entries if e["event_type"] == "sudo_command"]
    suspicious_sudo_patterns = [
        "chmod +s", "chmod 4755", "useradd", "usermod", "passwd",
        "visudo", "/etc/shadow", "bash", "/bin/sh", "chown root",
        "iptables", "ufw", "systemctl", "rm -rf",
    ]
    for entry in sudo_entries:
        cmd = entry.get("command", "").lower()
        matched = [p for p in suspicious_sudo_patterns if p in cmd]
        if matched:
            findings.append({
                "rule_id": "LTHT-PE-002",
                "rule_name": "Suspicious Sudo Command",
                "severity": "HIGH" if "shadow" in cmd or "chmod +s" in cmd else "MEDIUM",
                "risk_score": 75 if "shadow" in cmd or "chmod +s" in cmd else 55,
                "description": (
                    f"User '{entry.get('user', 'unknown')}' executed suspicious sudo command: "
                    f"{entry.get('command', 'unknown')}"
                ),
                "user": entry.get("user", "unknown"),
                "command": entry.get("command", "unknown"),
                "matched_patterns": matched,
                "evidence": [entry["raw"]],
                "recommendation": (
                    "Validate the command was authorized. Review sudoers configuration. "
                    "Implement least-privilege sudo policies."
                ),
            })

    return findings


def detect_reverse_shells(history_entries: list) -> list:
    """Detect reverse shell indicators in bash history."""
    findings = []
    shell_patterns = [
        ("bash -i", "Bash interactive reverse shell"),
        ("/dev/tcp/", "Bash /dev/tcp reverse shell"),
        ("/dev/udp/", "Bash /dev/udp reverse shell"),
        ("nc -e", "Netcat reverse shell with -e flag"),
        ("ncat -e", "Ncat reverse shell"),
        ("nc -c", "Netcat reverse shell with -c flag"),
        ("python -c 'import socket", "Python reverse shell"),
        ("python3 -c 'import socket", "Python3 reverse shell"),
        ("perl -e 'use Socket", "Perl reverse shell"),
        ("ruby -e", "Ruby reverse shell"),
        ("mkfifo", "Named pipe reverse shell"),
    ]

    for entry in history_entries:
        cmd = entry.get("command", "")
        for pattern, label in shell_patterns:
            if pattern.lower() in cmd.lower():
                findings.append({
                    "rule_id": "LTHT-RS-001",
                    "rule_name": "Reverse Shell Detected",
                    "severity": "CRITICAL",
                    "risk_score": 100,
                    "description": f"{label} detected in command history: {cmd[:120]}",
                    "command": cmd,
                    "pattern_matched": pattern,
                    "evidence": [entry["raw"]],
                    "recommendation": (
                        "IMMEDIATE ACTION REQUIRED. Investigate the host for active "
                        "C2 connections. Isolate the system. Perform memory forensics. "
                        "Check for data exfiltration and lateral movement."
                    ),
                })
                break

    return findings


def detect_reconnaissance(history_entries: list) -> list:
    """Detect reconnaissance commands in bash history."""
    findings = []
    recon_patterns = [
        ("nmap ", "Network scanner execution"),
        ("whoami", "User identity enumeration"),
        ("id ", "User/group ID enumeration"),
        ("uname -a", "System information gathering"),
        ("cat /etc/passwd", "Password file enumeration"),
        ("cat /etc/shadow", "Shadow file access attempt"),
        ("ifconfig", "Network interface enumeration"),
        ("ip addr", "Network address enumeration"),
        ("find / -perm", "SUID/permission search"),
        ("find / -writable", "Writable directory search"),
        ("find / -name", "File system enumeration"),
        ("netstat ", "Network connection enumeration"),
        ("ss -", "Socket statistics enumeration"),
        ("ps aux", "Process enumeration"),
        ("lsof ", "Open file enumeration"),
    ]

    recon_cmds = []
    for entry in history_entries:
        cmd = entry.get("command", "")
        for pattern, label in recon_patterns:
            if pattern.lower() in cmd.lower():
                recon_cmds.append((entry, pattern, label))
                break

    if len(recon_cmds) >= 3:
        findings.append({
            "rule_id": "LTHT-RC-001",
            "rule_name": "Reconnaissance Activity Cluster",
            "severity": "HIGH",
            "risk_score": 70,
            "description": (
                f"Detected {len(recon_cmds)} reconnaissance commands in bash history, "
                f"indicating systematic enumeration of the target system."
            ),
            "command_count": len(recon_cmds),
            "commands": [c[0]["command"] for c in recon_cmds[:10]],
            "evidence": [c[0]["raw"] for c in recon_cmds[:5]],
            "recommendation": (
                "Investigate who executed these commands and whether they had "
                "authorization. Review for follow-on exploitation activity. "
                "Implement command logging and alerting."
            ),
        })
    elif recon_cmds:
        for entry, pattern, label in recon_cmds:
            findings.append({
                "rule_id": "LTHT-RC-002",
                "rule_name": f"Reconnaissance: {label}",
                "severity": "MEDIUM",
                "risk_score": 40,
                "description": f"{label} detected: {entry['command'][:120]}",
                "command": entry["command"],
                "evidence": [entry["raw"]],
                "recommendation": "Review command context and user authorization.",
            })

    return findings


def detect_persistence(cron_entries: list, history_entries: list) -> list:
    """Detect persistence mechanisms — suspicious cron jobs, authorized_keys, etc."""
    findings = []

    # Suspicious cron commands
    suspicious_cron = [
        "curl ", "wget ", "python", "bash ", "/tmp/", "nc ", "ncat ",
        "/dev/tcp", "base64", "chmod", "reverse", "shell",
    ]
    for entry in cron_entries:
        if entry["event_type"] == "cron_execution":
            cmd = entry.get("command", "").lower()
            matched = [p for p in suspicious_cron if p in cmd]
            if matched:
                findings.append({
                    "rule_id": "LTHT-PS-001",
                    "rule_name": "Suspicious Cron Job",
                    "severity": "CRITICAL" if any(p in cmd for p in ["/dev/tcp", "reverse", "nc "]) else "HIGH",
                    "risk_score": 90 if any(p in cmd for p in ["/dev/tcp", "reverse", "nc "]) else 65,
                    "description": (
                        f"Suspicious cron job executed by '{entry.get('user', 'unknown')}': "
                        f"{entry.get('command', 'unknown')[:120]}"
                    ),
                    "user": entry.get("user", "unknown"),
                    "command": entry.get("command", "unknown"),
                    "matched_patterns": matched,
                    "evidence": [entry["raw"]],
                    "recommendation": (
                        "Review the cron job for malicious intent. Check crontab for "
                        "unauthorized entries (crontab -l -u <user>). Remove suspicious "
                        "entries and investigate the source."
                    ),
                })

    # Crontab modifications
    cron_edits = [e for e in cron_entries if e["event_type"] == "cron_edit" and e.get("action") == "replace"]
    for entry in cron_edits:
        findings.append({
            "rule_id": "LTHT-PS-002",
            "rule_name": "Crontab Modified",
            "severity": "MEDIUM",
            "risk_score": 50,
            "description": f"Crontab modified by user '{entry.get('user', 'unknown')}'.",
            "user": entry.get("user", "unknown"),
            "evidence": [entry["raw"]],
            "recommendation": "Verify the crontab modification was authorized. Audit new entries.",
        })

    # authorized_keys manipulation in bash history
    for entry in history_entries:
        cmd = entry.get("command", "").lower()
        if "authorized_keys" in cmd:
            findings.append({
                "rule_id": "LTHT-PS-003",
                "rule_name": "SSH Authorized Keys Manipulation",
                "severity": "CRITICAL",
                "risk_score": 90,
                "description": f"SSH authorized_keys manipulation detected: {entry['command'][:120]}",
                "command": entry["command"],
                "evidence": [entry["raw"]],
                "recommendation": (
                    "Audit all authorized_keys files on the system. Remove unauthorized "
                    "keys. Investigate for backdoor SSH access."
                ),
            })

    return findings


def detect_log_tampering(history_entries: list, syslog_entries: list) -> list:
    """Detect log clearing and tampering activity."""
    findings = []

    tamper_patterns = [
        ("history -c", "Bash history cleared"),
        ("history -w /dev/null", "Bash history redirected to /dev/null"),
        ("shred ", "File shredding utility used"),
        ("rm -rf /var/log", "Log directory deletion attempted"),
        ("rm /var/log", "Log file deletion attempted"),
        ("> /var/log", "Log file truncated"),
        ("truncate ", "File truncation utility used"),
        ("echo '' > /var/log", "Log file emptied"),
    ]

    for entry in history_entries:
        cmd = entry.get("command", "")
        for pattern, label in tamper_patterns:
            if pattern.lower() in cmd.lower():
                findings.append({
                    "rule_id": "LTHT-LT-001",
                    "rule_name": "Log Tampering Detected",
                    "severity": "CRITICAL",
                    "risk_score": 85,
                    "description": f"{label}: {cmd[:120]}",
                    "command": cmd,
                    "pattern_matched": pattern,
                    "evidence": [entry["raw"]],
                    "recommendation": (
                        "CRITICAL: Anti-forensic activity detected. Preserve all "
                        "remaining logs immediately. Initiate incident response. "
                        "Consider the host compromised."
                    ),
                })
                break

    return findings


def detect_data_exfiltration(history_entries: list) -> list:
    """Detect potential data exfiltration commands."""
    findings = []

    exfil_patterns = [
        ("curl.*-d ", "Data upload via curl POST"),
        ("curl.*--data", "Data upload via curl"),
        ("wget.*--post", "Data upload via wget POST"),
        ("scp ", "Secure copy to external host"),
        ("rsync ", "Data sync to external host"),
        ("base64 ", "Base64 encoding (potential exfil prep)"),
        ("xxd ", "Hex encoding (potential exfil prep)"),
        ("tar.*-c.*|.*nc", "Archive piped to netcat"),
        ("zip.*|.*nc", "Archive piped to netcat"),
        ("openssl enc", "OpenSSL encryption (potential exfil prep)"),
    ]

    for entry in history_entries:
        cmd = entry.get("command", "")
        for pattern, label in exfil_patterns:
            if pattern.lower().split(".*")[0] in cmd.lower():
                findings.append({
                    "rule_id": "LTHT-EX-001",
                    "rule_name": "Potential Data Exfiltration",
                    "severity": "HIGH",
                    "risk_score": 75,
                    "description": f"{label}: {cmd[:120]}",
                    "command": cmd,
                    "evidence": [entry["raw"]],
                    "recommendation": (
                        "Investigate the destination of data transfers. Check for "
                        "unauthorized data movement. Review DLP controls."
                    ),
                })
                break

    return findings


def detect_firewall_tampering(history_entries: list) -> list:
    """Detect firewall rule modifications."""
    findings = []

    fw_patterns = [
        ("iptables -F", "Firewall rules flushed"),
        ("iptables --flush", "Firewall rules flushed"),
        ("ufw disable", "UFW firewall disabled"),
        ("firewalld stop", "Firewalld stopped"),
        ("systemctl stop firewalld", "Firewalld service stopped"),
        ("iptables -P.*ACCEPT", "Firewall default policy set to ACCEPT"),
    ]

    for entry in history_entries:
        cmd = entry.get("command", "")
        for pattern, label in fw_patterns:
            if pattern.lower() in cmd.lower():
                findings.append({
                    "rule_id": "LTHT-FW-001",
                    "rule_name": "Firewall Tampering",
                    "severity": "CRITICAL",
                    "risk_score": 85,
                    "description": f"{label}: {cmd[:120]}",
                    "command": cmd,
                    "evidence": [entry["raw"]],
                    "recommendation": (
                        "Restore firewall rules immediately. Investigate who disabled "
                        "the firewall and why. Review network logs for unauthorized access."
                    ),
                })
                break

    return findings


def run_all_detections(parsed_logs: dict) -> list:
    """Run all detection rules against parsed log data."""
    all_findings = []

    auth = parsed_logs.get("auth", [])
    syslog = parsed_logs.get("syslog", [])
    history = parsed_logs.get("bash_history", [])
    cron = parsed_logs.get("cron", [])

    all_findings.extend(detect_brute_force(auth))
    all_findings.extend(detect_brute_force_success(auth))
    all_findings.extend(detect_privilege_escalation(auth))
    all_findings.extend(detect_reverse_shells(history))
    all_findings.extend(detect_reconnaissance(history))
    all_findings.extend(detect_persistence(cron, history))
    all_findings.extend(detect_log_tampering(history, syslog))
    all_findings.extend(detect_data_exfiltration(history))
    all_findings.extend(detect_firewall_tampering(history))

    # Sort by risk score descending
    all_findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

    return all_findings
