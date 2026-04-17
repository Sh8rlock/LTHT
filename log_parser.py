#!/usr/bin/env python3
"""
LTHT - Log Parser Module
=========================
Parses common Linux log files: auth.log, syslog, bash_history, cron logs.
Normalizes entries into structured records for the detection engine.
"""

import re
import os
from datetime import datetime

# ---------- auth.log patterns ----------
AUTH_FAILED = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)"
)
AUTH_ACCEPTED = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)"
)
SUDO_CMD = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+sudo:\s+"
    r"(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
)
SU_ATTEMPT = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+su\[\d+\]:\s+"
    r"(?P<status>Successful|FAILED) su for (?P<target_user>\S+) by (?P<user>\S+)"
)
SESSION_OPENED = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+.*session opened for user (?P<user>\S+)"
)

# ---------- syslog patterns ----------
SYSLOG_SERVICE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+systemd\[\d+\]:\s+"
    r"(?P<action>Started|Stopped|Starting|Stopping)\s+(?P<service>.+)\."
)
SYSLOG_KERNEL = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+kernel:\s+\[\s*[\d.]+\]\s+(?P<message>.+)"
)
SYSLOG_GENERIC = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)"
)

# ---------- cron patterns ----------
CRON_ENTRY = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?:CRON|crontab)\[\d+\]:\s+"
    r"\((?P<user>\S+)\)\s+CMD\s+\((?P<command>.+)\)"
)
CRON_EDIT = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+crontab\[\d+\]:\s+"
    r"\((?P<user>\S+)\)\s+(?P<action>LIST|REPLACE|DELETE)"
)

# ---------- bash_history suspicious commands ----------
SUSPICIOUS_CMDS = [
    "nc ", "ncat ", "netcat ", "nmap ", "/dev/tcp/", "/dev/udp/",
    "bash -i", "python -c", "python3 -c", "perl -e", "ruby -e",
    "wget ", "curl ", "chmod +s", "chmod 4755", "chmod u+s",
    "useradd", "usermod", "passwd ", "chpasswd",
    "iptables -F", "iptables --flush", "ufw disable",
    "history -c", "shred ", "rm -rf /var/log",
    "cat /etc/shadow", "cat /etc/passwd",
    "whoami", "id ", "uname -a", "ifconfig", "ip addr",
    "find / -perm", "find / -writable", "find / -name",
    "base64 ", "xxd ", "openssl enc",
    "crontab -e", "at ", "systemctl enable",
    "ssh-keygen", "authorized_keys",
    "tcpdump ", "wireshark", "tshark",
    "mount ", "dd if=", "mkfs",
    "insmod ", "modprobe ", "rmmod ",
]


def _normalize_timestamp(raw: str, year: int = None) -> str:
    """Convert syslog-style timestamp to ISO format string."""
    if year is None:
        year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return raw


def parse_auth_log(filepath: str) -> list:
    """Parse auth.log and return structured log entries."""
    entries = []
    if not os.path.isfile(filepath):
        return entries

    with open(filepath, "r", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            m = AUTH_FAILED.search(line)
            if m:
                entries.append({
                    "source_file": "auth.log",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "ssh_failed_login",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "raw": line,
                })
                continue

            m = AUTH_ACCEPTED.search(line)
            if m:
                entries.append({
                    "source_file": "auth.log",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "ssh_accepted_login",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "raw": line,
                })
                continue

            m = SUDO_CMD.search(line)
            if m:
                entries.append({
                    "source_file": "auth.log",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "sudo_command",
                    "user": m.group("user"),
                    "command": m.group("command").strip(),
                    "raw": line,
                })
                continue

            m = SU_ATTEMPT.search(line)
            if m:
                entries.append({
                    "source_file": "auth.log",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "su_attempt",
                    "user": m.group("user"),
                    "target_user": m.group("target_user"),
                    "status": m.group("status").lower(),
                    "raw": line,
                })
                continue

            m = SESSION_OPENED.search(line)
            if m:
                entries.append({
                    "source_file": "auth.log",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "session_opened",
                    "user": m.group("user"),
                    "raw": line,
                })

    return entries


def parse_syslog(filepath: str) -> list:
    """Parse syslog and return structured log entries."""
    entries = []
    if not os.path.isfile(filepath):
        return entries

    with open(filepath, "r", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            m = SYSLOG_SERVICE.search(line)
            if m:
                entries.append({
                    "source_file": "syslog",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "service_action",
                    "action": m.group("action").lower(),
                    "service": m.group("service"),
                    "raw": line,
                })
                continue

            m = SYSLOG_KERNEL.search(line)
            if m:
                entries.append({
                    "source_file": "syslog",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "kernel_message",
                    "message": m.group("message"),
                    "raw": line,
                })
                continue

            m = SYSLOG_GENERIC.search(line)
            if m:
                entries.append({
                    "source_file": "syslog",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "syslog_generic",
                    "process": m.group("process"),
                    "message": m.group("message"),
                    "raw": line,
                })

    return entries


def parse_bash_history(filepath: str) -> list:
    """Parse bash_history and flag suspicious commands."""
    entries = []
    if not os.path.isfile(filepath):
        return entries

    with open(filepath, "r", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            is_suspicious = any(cmd in line.lower() for cmd in [c.lower().strip() for c in SUSPICIOUS_CMDS])

            entries.append({
                "source_file": "bash_history",
                "line_number": line_no,
                "event_type": "command_executed",
                "command": line,
                "suspicious": is_suspicious,
                "raw": line,
            })

    return entries


def parse_cron_log(filepath: str) -> list:
    """Parse cron log and return structured entries."""
    entries = []
    if not os.path.isfile(filepath):
        return entries

    with open(filepath, "r", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            m = CRON_ENTRY.search(line)
            if m:
                entries.append({
                    "source_file": "cron",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "cron_execution",
                    "user": m.group("user"),
                    "command": m.group("command").strip(),
                    "raw": line,
                })
                continue

            m = CRON_EDIT.search(line)
            if m:
                entries.append({
                    "source_file": "cron",
                    "line_number": line_no,
                    "timestamp": _normalize_timestamp(m.group("timestamp")),
                    "host": m.group("host"),
                    "event_type": "cron_edit",
                    "user": m.group("user"),
                    "action": m.group("action").lower(),
                    "raw": line,
                })

    return entries


def parse_all_logs(log_dir: str) -> dict:
    """Parse all log files in a directory and return categorized results."""
    results = {
        "auth": [],
        "syslog": [],
        "bash_history": [],
        "cron": [],
        "total_entries": 0,
        "files_parsed": [],
    }

    file_map = {
        "auth.log": ("auth", parse_auth_log),
        "syslog": ("syslog", parse_syslog),
        "bash_history": ("bash_history", parse_bash_history),
        ".bash_history": ("bash_history", parse_bash_history),
        "cron.log": ("cron", parse_cron_log),
        "cron_log": ("cron", parse_cron_log),
    }

    for filename, (category, parser_func) in file_map.items():
        filepath = os.path.join(log_dir, filename)
        if os.path.isfile(filepath):
            parsed = parser_func(filepath)
            results[category].extend(parsed)
            results["files_parsed"].append(filename)

    results["total_entries"] = sum(
        len(results[k]) for k in ["auth", "syslog", "bash_history", "cron"]
    )

    return results
