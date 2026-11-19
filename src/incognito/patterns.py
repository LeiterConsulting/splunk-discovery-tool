"""Regular expressions and helpers that find identifying values in text.

Each finder returns spans; the masker decides what replaces them. Values that are shared
vocabulary (loopback and multicast addresses, well-known Windows accounts) are filtered here.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from .vocabulary import DOMAIN_TLDS, FILE_EXTENSIONS, PUBLIC_NT_AUTHORITIES

IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
    r"(?:/(?P<prefix>3[0-2]|[12]?\d))?"
    r"(?![\w]|\.\d)"
)

IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:.])"
    r"(?P<ip>(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?)"
    r"(?:/(?P<prefix>\d{1,3}))?"
    r"(?![\w:])"
)

MAC_RE = re.compile(
    r"(?<![\w:.-])(?P<mac>[0-9A-Fa-f]{2}(?P<sep>[:-])(?:[0-9A-Fa-f]{2}(?P=sep)){4}[0-9A-Fa-f]{2})(?![\w:-])"
    r"|(?<![\w.])(?P<cisco>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w.])"
)

EMAIL_RE = re.compile(
    r"(?<![\w.+%-])(?P<email>[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24})(?![\w-])"
)

GUID_RE = re.compile(
    r"(?<![\w-])(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?![\w-])"
)

SID_RE = re.compile(r"(?<![\w-])(?P<domain>[Ss]-1-5-21-\d{1,10}-\d{1,10}-\d{1,10})(?P<rid>-\d{1,10})?(?![\w-])")

FQDN_RE = re.compile(
    r"(?<![\w@.-])"
    r"(?P<fqdn>(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+(?P<tld>[A-Za-z]{2,24}))"
    r"(?![\w-]|\.[A-Za-z0-9])"
)

UNIX_HOME_RE = re.compile(r"(?<![\w.])(?P<prefix>/(?:home|Users)/)(?P<user>[A-Za-z0-9._$-]{1,64})(?=[/\s\"',;)\]]|$)")
WINDOWS_HOME_RE = re.compile(
    r"(?i)(?P<prefix>\b[A-Z]:(?:\\{1,2}|/)(?:Users|Documents and Settings)(?:\\{1,2}|/))"
    r"(?P<user>[^\\/\s\"':*?<>|]{1,64})"
)

# DOMAIN\user, also written with a doubled backslash inside JSON text. A single backslash
# followed by n, t, r, b, f, u, or a quote is far more often a JSON escape than an account.
DOMAIN_USER_RE = re.compile(
    r"(?<![\w\\:/.$-])(?P<domain>[A-Za-z][A-Za-z0-9.-]{0,30}[A-Za-z0-9])"
    r"(?P<sep>\\\\|\\(?![ntrbfu\"/\\]))"
    r"(?P<user>[A-Za-z0-9][A-Za-z0-9._$-]{0,63})(?![\w\\])"
)

SECRET_PATTERNS = (
    re.compile(r"(?<![\w-])(?P<value>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
    re.compile(r"(?i)\b(?:bearer|splunk|basic|token)\s+(?P<value>[A-Za-z0-9._~+/=-]{20,})"),
    re.compile(
        r"(?i)(?<![\w])(?:password|passwd|pwd|secret|client_secret|api_?key|access_?key|secret_?key|"
        r"auth_?token|access_?token|refresh_?token|private_?key|session_?key)"
        r"(?P<sep>\"?\s*[:=]\s*\"?)(?P<value>[^\s\"',;&)}\]]{4,})"
    ),
    re.compile(r"(?<![A-Za-z0-9])(?P<value>(?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])(?P<value>(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}))"),
)

# Long mixed-case strings with digits look like generated credentials. Pure hex strings are
# left alone because they are usually file hashes, which analysts need to see.
_TOKEN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])(?P<value>[A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/=_-])")

_SECRET_PLACEHOLDERS = {"*", "****", "*****", "******", "********", "<redacted>", "redacted", "masked", "none", "null"}

_WELL_KNOWN_IPV4 = {
    "0.0.0.0", "255.255.255.255", "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "208.67.220.220", "169.254.169.254",
}

_GENERIC_IPV4_NETWORKS = {
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "127.0.0.0/8", "0.0.0.0/0", "224.0.0.0/4", "240.0.0.0/4",
}

PUBLIC_PATH_USERS = frozenset({"public", "default", "default user", "all users", "shared", "guest", "administrator", "admin"})


def parse_ipv4(value: str) -> Optional[ipaddress.IPv4Address]:
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def parse_ipv6(value: str) -> Optional[ipaddress.IPv6Address]:
    candidate = value.split("%", 1)[0]
    if candidate.count(":") < 2:
        return None
    try:
        return ipaddress.IPv6Address(candidate)
    except ValueError:
        return None


def is_generic_ipv4(address: ipaddress.IPv4Address) -> bool:
    return (
        str(address) in _WELL_KNOWN_IPV4
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    )


def is_generic_ipv4_network(network_text: str) -> bool:
    return network_text in _GENERIC_IPV4_NETWORKS


def is_generic_ipv6(address: ipaddress.IPv6Address) -> bool:
    return address.is_loopback or address.is_unspecified or address.is_multicast


def is_generic_mac(normalized: str) -> bool:
    return normalized in {"000000000000", "ffffffffffff"}


def normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


def is_domain_like(fqdn: str, tld: str) -> bool:
    lowered = tld.lower()
    if lowered not in DOMAIN_TLDS or lowered in FILE_EXTENSIONS:
        return False
    labels = fqdn.split(".")
    if len(labels) < 2:
        return False
    # Dotted numbers with a letter suffix (for example 1.2.3.us) are versions, not domains.
    return not all(label.isdigit() for label in labels[:-1])


def is_public_nt_authority(domain: str) -> bool:
    return domain.strip().lower() in PUBLIC_NT_AUTHORITIES


def is_secret_placeholder(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    return not stripped or stripped.lower() in _SECRET_PLACEHOLDERS or set(stripped) <= {"*", "x", "X"}


def looks_like_generated_token(value: str) -> bool:
    stripped = value.rstrip("=")
    if len(stripped) < 32:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return False
    has_upper = any(ch.isupper() for ch in stripped)
    has_lower = any(ch.islower() for ch in stripped)
    has_digit = any(ch.isdigit() for ch in stripped)
    if not (has_upper and has_lower and has_digit):
        return False
    # Long identifiers made of words (snake_case or kebab-case field names) are not secrets.
    if re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z0-9]+)+", stripped):
        return False
    return True


def token_candidates(text: str):
    return _TOKEN_CANDIDATE_RE.finditer(text)
