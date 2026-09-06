"""Deterministic string patterns for APK triage.

Reuses the repository's existing URL/IP regex approach from
``ai.feature_extraction.string_extractor`` and extends it with IPv6, emails,
file paths, shell commands, suspicious keywords and encoded-looking strings.
"""

from __future__ import annotations

import re

URL_RE = re.compile(r"https?://[^\s\"'<>`]+")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::"
    r")(?![0-9A-Fa-f:])"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
FILE_PATH_RE = re.compile(
    r"(?<![\w.])(?:"
    r"/data/[\w./-]+|/system/[\w./-]+|/sdcard/[\w./-]+|/proc/[\w./-]+"
    r"|/storage/[\w./-]+|/dev/[\w./-]+|/mnt/[\w./-]+|/tmp/[\w./-]+"
    r"|file:///[\w./]+"
    r")(?![\w.-])"
)
SHELL_CMD_RE = re.compile(
    r"(?:^|[;|&`\s])(?:"
    r"sh -c|/system/bin/sh|/bin/sh|cmd /c|powershell(?:\.exe)?|"
    r"su (?:-c|-s)|chmod|chown|chattr|nc -|netcat|iptables|"
    r"wget|curl|dd |mkfs|mount|umount|reboot|rm -rf"
    r")(?=\s|$)", re.IGNORECASE
)

SUSPICIOUS_KEYWORDS = (
    "payload", "exploit", "keylog", "botnet", "ransomware", "cryptominer",
    "minergrate", "xmr", "coinminer", "backdoor", "trojan", "spyware",
    "stealer", "phishing", "frida", "dynamically replace", "su",
    "rootme", "iamroot", "inject", "hook", "obfuscate", "packed",
)

BASE64_LIKE_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
HEX_LIKE_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")