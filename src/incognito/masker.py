"""Replace a deployment's own names with stand-ins, check for leftovers, and restore replies.

Text goes through a fixed sequence of passes. Each pass finds candidate values, asks the vault
for their stand-ins (assigning new ones in one batch), and substitutes them. Running the same
passes over masked text without substituting is the leak check: anything they still find was
not replaced.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import patterns as P
from .vault import (
    PREFIX_TO_NAMESPACE,
    StandInVault,
    format_stand_in,
    in_stand_in_address_space,
    normalize_key,
    stand_in_key,
)
from .vocabulary import (
    CIM_DATAMODELS,
    PUBLIC_ACCOUNTS,
    is_dashed_ipv4,
    is_public_domain,
    is_public_value,
    is_shipped_content_app,
)


def field_key(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


FIELD_NAMESPACES: Dict[str, str] = {}
for _namespace, _words in (
    ("host", "host hosts hostname hostnames host_name host_fqdn fqdn dest_host src_host dvc_host dest_nt_host "
             "src_nt_host nt_host computer computername computer_name workstation workstation_name splunk_server "
             "orig_host server servers servername server_name device_name dest_hostname src_hostname clientname "
             "client_name"),
    ("ip_or_host", "src dest dst dvc src_ip dest_ip dst_ip ip ips ip_address ipaddress clientip client_ip c_ip s_ip "
                   "dvc_ip remote_ip local_ip remote_addr remote_address src_translated_ip dest_translated_ip address "
                   "addr source_ip destination_ip source_address destination_address src_addr dest_addr dst_addr peer"),
    ("user", "user users username usernames user_name account account_name target_user_name subject_user_name "
             "target_user subject_user src_user dest_user owner owners author eai:acl.owner updated_by created_by "
             "realname real_name logon_account principal user_principal_name upn sam_account_name caller actor"),
    ("email", "email emails mail user_email sender recipient recipients"),
    ("index", "index indexes indices index_name idx orig_index srchindexesallowed srchindexesdefault default_index"),
    ("app", "eai:acl.app eai:appname app_name apps installed_apps splunk_app"),
    ("search", "savedsearch savedsearches saved_searches savedsearch_name search_name ss_name reports alerts"),
    ("kv", "collection collections kv_collections kvstore_collections"),
    ("role", "role roles imported_roles default_role"),
    ("domain", "domain domains nt_domain src_nt_domain dest_nt_domain account_domain user_domain target_domain_name "
               "subject_domain_name domain_name"),
    ("object", "macros lookups lookup_tables eventtypes transforms datamodels data_models field_extractions"),
):
    for _word in _words.split():
        FIELD_NAMESPACES[field_key(_word)] = _namespace

NAME_FIELDS = frozenset({"name", "title", "label", "displayname"})

# Event fields dropped from rows before they reach the model in incognito mode. The raw event
# is free text that pattern matching cannot fully clean; the others name internal servers.
RAW_EVENT_FIELDS = frozenset({"_raw", "_si", "_bkt", "_cd", "_serial"})

# Path and registry words that look like DOMAIN\user but are not accounts.
_PATH_WORDS = frozenset(
    """
    hklm hkcu hku hkcr hkey_local_machine hkey_current_user hkey_users hkey_classes_root software system
    system32 syswow64 windows files microsoft temp users appdata local roaming currentcontrolset services
    control drivers etc config logs bin var opt splunk splunkforwarder apps default documents programdata
    """.split()
)

_PREFIX_ALTERNATION = "|".join(sorted(PREFIX_TO_NAMESPACE, key=len, reverse=True))
STAND_IN_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<prefix>{_PREFIX_ALTERNATION})(?P<sep>\\?_|-)?(?P<num>\d{{4,7}})(?!\d)"
    r"(?P<suffix>\.example(?![\w-])|@example\.com(?![\w-]))?",
    re.IGNORECASE,
)
GUID_STAND_IN_RE = re.compile(r"(?<![\w-])00000000-0000-4000-8000-(?P<num>\d{12})(?![\w-])", re.IGNORECASE)
SID_STAND_IN_RE = re.compile(r"(?<![\w-])(?P<sid>[Ss]-1-5-21-0-0-\d{1,10})(?P<rid>-\d{1,10})?(?![\w-])")
MAC_STAND_IN_RE = re.compile(
    r"(?<![\w:.-])(?P<mac>02(?P<sep>[:-])00(?P=sep)00(?P=sep)[0-9A-Fa-f]{2}(?P=sep)[0-9A-Fa-f]{2}(?P=sep)[0-9A-Fa-f]{2})(?![\w:-])"
    r"|(?<![\w.])(?P<cisco>0200\.00[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{4})(?![\w.])"
)

_KEY = r"[A-Za-z_][A-Za-z0-9_.:]{0,60}"
# SPL that is itself inside a JSON string, as in a prompt that embeds JSON data, has its quotes
# escaped: user IN (\"admin\"). Those values are read between the \" marks and decoded as JSON.
_ESCAPED_QUOTED = r"\\\"(?:(?!\\\")[^\n])*\\\""
_SPL_EQ_RE = re.compile(
    rf"(?<![\w.:])(?P<key>{_KEY})\s*(?:==|!=|=)\s*"
    rf"(?P<val>{_ESCAPED_QUOTED}|\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|(?:[^\s|()\[\],;\"'&\\]|\\(?!\"))+)"
)
_SPL_IN_RE = re.compile(rf"(?<![\w.:])(?P<key>{_KEY})\s+(?:IN|in)\s*\((?P<vals>[^()]*)\)")
_SPL_LIST_ITEM_RE = re.compile(
    r"\\\"(?P<eq>(?:(?!\\\")[^\n])*)\\\"|\"(?P<dq>(?:[^\"\\]|\\.)*)\"|'(?P<sq>(?:[^'\\]|\\.)*)'"
    r"|(?P<bare>(?:[^\s,\"'\\]|\\(?!\"))+)"
)
_LIST_ITEM_GROUPS = ("eq", "dq", "sq", "bare")


def _decode_json_fragment(text: str) -> str:
    try:
        return json.loads(f'"{text}"')
    except ValueError:
        return text
_JSON_STR_RE = re.compile(r"\"(?P<key>[^\"\\\n]{1,60})\"\s*:\s*\"(?P<val>(?:[^\"\\\n]|\\.)*)\"")
_JSON_ARR_RE = re.compile(r"\"(?P<key>[^\"\\\n]{1,60})\"\s*:\s*\[(?P<vals>[^\[\]]*)\]")
_JSON_ITEM_RE = re.compile(r"\"(?P<val>(?:[^\"\\]|\\.)*)\"")
_PY_STR_RE = re.compile(r"'(?P<key>[^'\\\n]{1,60})'\s*:\s*'(?P<val>(?:[^'\\\n]|\\.)*)'")
_PY_ARR_RE = re.compile(r"'(?P<key>[^'\\\n]{1,60})'\s*:\s*\[(?P<vals>[^\[\]]*)\]")
_PY_ITEM_RE = re.compile(r"'(?P<val>(?:[^'\\]|\\.)*)'")
# An array counts as values of its key only when it holds nothing but strings; in an array of
# objects the quoted text includes the objects' own keys, such as "name".
_JSON_STRING_LIST = re.compile(r"\s*(?:\"(?:[^\"\\]|\\.)*\"\s*,?\s*)*")
_PY_STRING_LIST = re.compile(r"\s*(?:'(?:[^'\\]|\\.)*'\s*,?\s*)*")

_NUMERIC_LIKE = re.compile(r"[\d\s.,:/+%-]+")
# Punctuation that ends a sentence after an unquoted value, as in "is index=web_prod healthy?".
_SENTENCE_END = ".?!:"
_BOOLEAN_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", "enabled", "disabled"})
# Splunk index and role names and DNS or Windows domains never contain spaces, so a value with
# spaces under one of these keys means something else, such as "domain": "Data Quality".
_NO_SPACE_NAMESPACES = frozenset({"index", "role", "domain"})


def _identity(stand_in: str) -> str:
    return stand_in


def spl_field_values(spl: Any) -> List[Tuple[str, str]]:
    """Names an SPL search gives as field values, such as ``host=web01`` or ``user IN (a, b)``, by namespace."""
    if not isinstance(spl, str) or not spl:
        return []
    found: List[Tuple[str, str]] = []

    def add(namespace: Optional[str], value: str) -> None:
        value = value.strip()
        if namespace and value and "*" not in value and not value.startswith("$"):
            found.append((namespace, value))

    for match in _SPL_EQ_RE.finditer(spl):
        raw = match.group("val")
        if raw.startswith('\\"') and raw.endswith('\\"') and len(raw) >= 4:
            raw = _decode_json_fragment(raw[2:-2])
        elif raw[:1] in {'"', "'"} and raw[-1:] == raw[:1] and len(raw) >= 2:
            raw = raw[1:-1]
        else:
            raw = raw.rstrip(_SENTENCE_END)
        add(FIELD_NAMESPACES.get(field_key(match.group("key"))), raw)
    for match in _SPL_IN_RE.finditer(spl):
        namespace = FIELD_NAMESPACES.get(field_key(match.group("key")))
        for item in _SPL_LIST_ITEM_RE.finditer(match.group("vals")):
            group = next(name for name in _LIST_ITEM_GROUPS if item.group(name) is not None)
            value = item.group(group)
            if group == "bare":
                value = value.rstrip(_SENTENCE_END)
            elif group == "eq":
                value = _decode_json_fragment(value)
            add(namespace, value)
    return found


@dataclass(frozen=True)
class MaskSettings:
    """Admin choices that change what is masked."""

    always_mask: Tuple[str, ...] = ()
    keep_visible: FrozenSet[str] = frozenset()

    @classmethod
    def from_terms(cls, always_mask: Iterable[str] = (), keep_visible: Iterable[str] = ()) -> "MaskSettings":
        always = sorted({str(term).strip().lower() for term in always_mask if len(str(term).strip()) >= 3},
                        key=lambda term: (-len(term), term))
        keep = frozenset(str(term).strip().lower() for term in keep_visible if str(term).strip())
        return cls(tuple(always), keep)


@dataclass
class Candidate:
    start: int
    end: int
    namespace: str
    value: str
    render: Callable[[str], str] = _identity


def _drop_overlaps(candidates: List[Candidate]) -> List[Candidate]:
    kept: List[Candidate] = []
    position = -1
    for candidate in sorted(candidates, key=lambda item: (item.start, -(item.end - item.start))):
        if candidate.start >= position:
            kept.append(candidate)
            position = candidate.end
    return kept


def _trie_regex(words: Iterable[str]) -> Optional[str]:
    """Build one alternation that factors shared prefixes, so thousands of names match quickly."""
    trie: Dict[str, Any] = {}
    for word in words:
        if not word:
            continue
        node = trie
        for char in word:
            node = node.setdefault(char, {})
        node[""] = {}
    if not trie:
        return None

    def build(node: Dict[str, Any]) -> str:
        optional = "" in node
        branches: List[str] = []
        leaves: List[str] = []
        for char in sorted(key for key in node if key != ""):
            child = node[char]
            sub = build(child) if any(key != "" for key in child) else ""
            if sub:
                branches.append(re.escape(char) + sub)
            else:
                leaves.append(char)
        if len(leaves) == 1:
            branches.append(re.escape(leaves[0]))
        elif leaves:
            branches.append("[" + "".join(re.escape(char) for char in leaves) + "]")
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        if optional:
            return f"(?:{body})?"
        return body

    return build(trie)


def row_hint_for_tool(tool_name: str, args: Optional[Mapping[str, Any]] = None) -> Tuple[Optional[str], bool]:
    """Namespace for name and title fields in a Splunk MCP tool's rows, and whether app means a Splunk app."""
    name = str(tool_name or "").lower()
    arguments = args or {}
    if "get_indexes" in name:
        return "index", True
    if "knowledge_objects" in name:
        object_type = str(arguments.get("type") or arguments.get("object_type") or "").lower()
        if "saved" in object_type or "search" in object_type or "report" in object_type or "alert" in object_type:
            return "search", True
        if object_type in {"apps", "app"}:
            return "app", True
        return "object", True
    if "user" in name:
        return "user", True
    if "kv_store" in name or "collection" in name:
        return "kv", True
    if "get_info" in name or "metadata" in name:
        return None, True
    return None, False


_MAX_JSON_OBJECTS = 64


def _json_objects(text: str) -> List[Tuple[int, int, Any]]:
    """Top-level JSON objects embedded in text, as ``(start, end, parsed)``."""
    found: List[Tuple[int, int, Any]] = []
    decoder = json.JSONDecoder()
    position = text.find("{")
    attempts = 0
    while position != -1 and len(found) < _MAX_JSON_OBJECTS and attempts < 2000:
        attempts += 1
        try:
            parsed, end = decoder.raw_decode(text, position)
        except ValueError:
            position = text.find("{", position + 1)
            continue
        if isinstance(parsed, dict):
            found.append((position, end, parsed))
            position = text.find("{", end)
        else:
            position = text.find("{", position + 1)
    return found


class Masker:
    """Masks text and data for one connection's vault under the admin's settings."""

    _CACHE_LIMIT = 256

    def __init__(self, vault: StandInVault, settings: Optional[MaskSettings] = None) -> None:
        self.vault = vault
        self.settings = settings or MaskSettings()
        self._lock = threading.RLock()
        self._dictionary_version = -1
        self._dictionary_regex: Optional[re.Pattern] = None
        self._dictionary_terms: Dict[str, Tuple[str, str]] = {}
        self._cache: "OrderedDict[Tuple[int, str], str]" = OrderedDict()
        always = self.settings.always_mask
        self._always_regex = (
            re.compile("|".join(re.escape(term) for term in always), re.IGNORECASE) if always else None
        )

    # ----- shared checks ---------------------------------------------------------------------

    def _keep(self, value: str) -> bool:
        return value.strip().lower() in self.settings.keep_visible

    def _looks_masked(self, value: str) -> bool:
        if self.vault.is_stand_in(value):
            return True
        return any(
            pattern.search(value) for pattern in (STAND_IN_RE, GUID_STAND_IN_RE, SID_STAND_IN_RE, MAC_STAND_IN_RE)
        )

    def _should_mask(self, namespace: str, value: str) -> bool:
        if not value.strip() or self._keep(value):
            return False
        if self.vault.lookup(namespace, value) is not None:
            return True
        return not self._looks_masked(value)

    def _value_namespace(self, namespace: str, value: str) -> Optional[str]:
        """Namespace to mask a field value under, or None when it should stay visible."""
        lowered = value.strip().lower()
        if namespace in {"host", "ip_or_host"} and is_dashed_ipv4(value):
            return "host"
        if _NUMERIC_LIKE.fullmatch(value) or lowered in _BOOLEAN_WORDS:
            return None
        if namespace == "ip_or_host":
            namespace = "host"
        if namespace in _NO_SPACE_NAMESPACES and any(char.isspace() for char in value.strip()):
            return None
        if namespace == "object" and lowered in CIM_DATAMODELS:
            return None
        if namespace == "domain" and P.is_public_nt_authority(value):
            return None
        if namespace == "user" and lowered in PUBLIC_ACCOUNTS:
            return None
        if is_public_value(namespace, value):
            return None
        return namespace

    def _protected_spans(self, text: str) -> List[Tuple[int, int]]:
        spans: List[Tuple[int, int]] = []
        for pattern in (STAND_IN_RE, GUID_STAND_IN_RE, SID_STAND_IN_RE, MAC_STAND_IN_RE):
            spans.extend(match.span() for match in pattern.finditer(text))
        spans.sort()
        return spans

    @staticmethod
    def _overlaps(spans: List[Tuple[int, int]], starts: List[int], start: int, end: int) -> bool:
        index = bisect.bisect_right(starts, end) - 1
        while index >= 0:
            span_start, span_end = spans[index]
            if span_end > start and span_start < end:
                return True
            if span_end <= start and span_start < start - 400:
                break
            index -= 1
        return False

    # ----- passes ----------------------------------------------------------------------------

    def _scan_secrets(self, text: str) -> List[Candidate]:
        found: List[Candidate] = []
        for number, pattern in enumerate(P.SECRET_PATTERNS):
            for match in pattern.finditer(text):
                value = match.group("value")
                if P.is_secret_placeholder(value) or not self._should_mask("secret", value):
                    continue
                if number == 1 and not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)):
                    continue
                found.append(Candidate(match.start("value"), match.end("value"), "secret", value))
        for match in P.token_candidates(text):
            value = match.group("value")
            if P.looks_like_generated_token(value) and self._should_mask("secret", value):
                found.append(Candidate(match.start("value"), match.end("value"), "secret", value))
        return found

    def _scan_emails(self, text: str) -> List[Candidate]:
        found = []
        for match in P.EMAIL_RE.finditer(text):
            value = match.group("email")
            if self._should_mask("email", value):
                found.append(Candidate(match.start("email"), match.end("email"), "email", value))
        return found

    def _scan_home_paths(self, text: str) -> List[Candidate]:
        found = []
        for pattern in (P.UNIX_HOME_RE, P.WINDOWS_HOME_RE):
            for match in pattern.finditer(text):
                user = match.group("user")
                lowered = user.lower()
                if lowered in P.PUBLIC_PATH_USERS or lowered in PUBLIC_ACCOUNTS:
                    continue
                if self._should_mask("user", user):
                    found.append(Candidate(match.start("user"), match.end("user"), "user", user))
        return found

    def _scan_domain_users(self, text: str) -> List[Candidate]:
        found = []

        def without_suffix(stand_in: str) -> str:
            return stand_in[: -len(".example")] if stand_in.endswith(".example") else stand_in

        for match in P.DOMAIN_USER_RE.finditer(text):
            domain = match.group("domain")
            user = match.group("user")
            if P.is_public_nt_authority(domain):
                continue
            if domain.lower() in _PATH_WORDS or user.lower() in _PATH_WORDS:
                continue
            if self._value_namespace("domain", domain) and self._should_mask("domain", domain):
                found.append(Candidate(match.start("domain"), match.end("domain"), "domain", domain, without_suffix))
            if self._value_namespace("user", user) and self._should_mask("user", user):
                found.append(Candidate(match.start("user"), match.end("user"), "user", user))
        return found

    def _scan_sids(self, text: str) -> List[Candidate]:
        found = []
        for match in P.SID_RE.finditer(text):
            domain = match.group("domain")
            if self._should_mask("sid", domain):
                found.append(Candidate(match.start("domain"), match.end("domain"), "sid", domain))
        return found

    def _scan_guids(self, text: str) -> List[Candidate]:
        found = []
        for match in P.GUID_RE.finditer(text):
            value = match.group("guid")
            if value.strip("0-") == "":
                continue
            if self._should_mask("guid", value):
                found.append(Candidate(match.start("guid"), match.end("guid"), "guid", value))
        return found

    def _scan_macs(self, text: str) -> List[Candidate]:
        found = []
        for match in P.MAC_RE.finditer(text):
            group = "mac" if match.group("mac") else "cisco"
            value = match.group(group)
            if P.is_generic_mac(P.normalize_mac(value)) or not self._should_mask("mac", value):
                continue

            def render(stand_in: str, original: str = value, cisco: bool = group == "cisco") -> str:
                digits = stand_in.replace(":", "")
                if cisco:
                    rendered = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"
                else:
                    rendered = original[2].join(digits[i:i + 2] for i in range(0, 12, 2))
                return rendered.upper() if original.isupper() else rendered

            found.append(Candidate(match.start(group), match.end(group), "mac", value, render))
        return found

    def _scan_ipv4(self, text: str) -> List[Candidate]:
        found = []
        for match in P.IPV4_RE.finditer(text):
            ip = match.group("ip")
            address = P.parse_ipv4(ip)
            if address is None:
                continue
            prefix = match.group("prefix")
            if prefix is not None:
                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                if P.is_generic_ipv4_network(str(network)):
                    continue
            elif P.is_generic_ipv4(address):
                continue
            if self._should_mask("ip", ip):
                found.append(Candidate(match.start("ip"), match.end("ip"), "ip", ip))
        return found

    def _scan_ipv6(self, text: str) -> List[Candidate]:
        found = []
        for match in P.IPV6_CANDIDATE_RE.finditer(text):
            ip = match.group("ip")
            address = P.parse_ipv6(ip)
            if address is None or P.is_generic_ipv6(address):
                continue
            if self._should_mask("ip", ip):
                found.append(Candidate(match.start("ip"), match.end("ip"), "ip", ip))
        return found

    def _field_candidate(self, namespace: str, raw: str, start: int, *, escaped: str = "") -> Optional[Candidate]:
        value = raw
        if escaped == "json" and "\\" in raw:
            try:
                value = json.loads(f'"{raw}"')
            except ValueError:
                value = raw
        stripped = value.strip()
        if not stripped or len(stripped) > 200 or "\n" in stripped:
            return None
        if "*" in stripped or stripped.startswith("$") or self._keep(stripped):
            return None
        if P.IPV4_RE.search(stripped) or P.EMAIL_RE.search(stripped) or P.parse_ipv6(stripped):
            return None
        target = self._value_namespace(namespace, stripped)
        if target is None or not self._should_mask(target, stripped):
            return None
        if value == raw:
            offset = len(raw) - len(raw.lstrip())
            span_start, span_end = start + offset, start + offset + len(stripped)
        else:
            span_start, span_end = start, start + len(raw)
        render = (lambda stand_in: json.dumps(stand_in)[1:-1]) if escaped == "json" else _identity
        return Candidate(span_start, span_end, target, stripped, render)

    def _scan_fields(self, text: str) -> List[Candidate]:
        found: List[Candidate] = []

        def add(candidate: Optional[Candidate]) -> None:
            if candidate is not None:
                found.append(candidate)

        for match in _SPL_EQ_RE.finditer(text):
            namespace = FIELD_NAMESPACES.get(field_key(match.group("key")))
            if namespace is None:
                continue
            raw = match.group("val")
            start = match.start("val")
            if raw.startswith('\\"') and raw.endswith('\\"') and len(raw) >= 4:
                add(self._field_candidate(namespace, raw[2:-2], start + 2, escaped="json"))
            elif raw[:1] in {'"', "'"} and raw[-1:] == raw[:1] and len(raw) >= 2:
                add(self._field_candidate(namespace, raw[1:-1], start + 1, escaped="json" if raw[0] == '"' else ""))
            else:
                add(self._field_candidate(namespace, raw.rstrip(_SENTENCE_END), start))
        for match in _SPL_IN_RE.finditer(text):
            namespace = FIELD_NAMESPACES.get(field_key(match.group("key")))
            if namespace is None:
                continue
            base = match.start("vals")
            for item in _SPL_LIST_ITEM_RE.finditer(match.group("vals")):
                group = next(name for name in _LIST_ITEM_GROUPS if item.group(name) is not None)
                value = item.group(group).rstrip(_SENTENCE_END) if group == "bare" else item.group(group)
                add(self._field_candidate(namespace, value, base + item.start(group),
                                          escaped="json" if group == "eq" else ""))
        for string_re, array_re, item_re, list_re, escaped in (
            (_JSON_STR_RE, _JSON_ARR_RE, _JSON_ITEM_RE, _JSON_STRING_LIST, "json"),
            (_PY_STR_RE, _PY_ARR_RE, _PY_ITEM_RE, _PY_STRING_LIST, ""),
        ):
            for match in string_re.finditer(text):
                namespace = FIELD_NAMESPACES.get(field_key(match.group("key")))
                if namespace is not None:
                    add(self._field_candidate(namespace, match.group("val"), match.start("val"), escaped=escaped))
            for match in array_re.finditer(text):
                namespace = FIELD_NAMESPACES.get(field_key(match.group("key")))
                if namespace is None:
                    continue
                base = match.start("vals")
                if list_re.fullmatch(match.group("vals")):
                    for item in item_re.finditer(match.group("vals")):
                        add(self._field_candidate(namespace, item.group("val"), base + item.start("val"), escaped=escaped))
                    continue
                # Objects in the array: their name and title fields name things of the array's kind.
                for inner in string_re.finditer(match.group("vals")):
                    if field_key(inner.group("key")) in NAME_FIELDS:
                        add(self._field_candidate(namespace, inner.group("val"), base + inner.start("val"), escaped=escaped))
        return found

    def _scan_fqdns(self, text: str) -> List[Candidate]:
        found = []
        for match in P.FQDN_RE.finditer(text):
            fqdn = match.group("fqdn")
            if not P.is_domain_like(fqdn, match.group("tld")) or is_public_domain(fqdn):
                continue
            if self.vault.lookup("host", fqdn) is not None:
                namespace = "host"
            elif self.vault.lookup("domain", fqdn) is not None:
                namespace = "domain"
            else:
                namespace = "domain" if fqdn.count(".") == 1 else "host"
            if self._should_mask(namespace, fqdn):
                found.append(Candidate(match.start("fqdn"), match.end("fqdn"), namespace, fqdn))
        return found

    def _dictionary(self) -> Tuple[Optional[re.Pattern], Dict[str, Tuple[str, str]]]:
        with self._lock:
            if self._dictionary_version != self.vault.terms_version:
                version = self.vault.terms_version
                terms: Dict[str, Tuple[str, str]] = {}
                for key, (namespace, _stand_in) in self.vault.text_terms().items():
                    lowered = key.lower()
                    if lowered in self.settings.keep_visible:
                        continue
                    real = self.vault.entries_real(namespace, key)
                    terms.setdefault(lowered, (namespace, real if real is not None else key))
                body = _trie_regex(sorted(terms))
                self._dictionary_regex = (
                    re.compile(rf"(?<![A-Za-z0-9])(?:{body})(?![A-Za-z0-9])", re.IGNORECASE) if body else None
                )
                self._dictionary_terms = terms
                self._dictionary_version = version
            return self._dictionary_regex, self._dictionary_terms

    def _scan_dictionary(self, text: str) -> List[Candidate]:
        regex, terms = self._dictionary()
        if regex is None:
            return []
        protected = self._protected_spans(text)
        starts = [span[0] for span in protected]
        found = []
        for match in regex.finditer(text):
            if protected and self._overlaps(protected, starts, match.start(), match.end()):
                continue
            entry = terms.get(" ".join(match.group(0).lower().split()))
            if entry is None:
                continue
            namespace, real = entry
            found.append(Candidate(match.start(), match.end(), namespace, real))
        return found

    def _scan_always_mask(self, text: str) -> List[Candidate]:
        if self._always_regex is None:
            return []
        protected = self._protected_spans(text)
        starts = [span[0] for span in protected]
        found = []
        for match in self._always_regex.finditer(text):
            if protected and self._overlaps(protected, starts, match.start(), match.end()):
                continue
            found.append(Candidate(match.start(), match.end(), "term", match.group(0).lower()))
        return found

    def _scanners(self) -> Sequence[Callable[[str], List[Candidate]]]:
        return (
            self._scan_secrets,
            self._scan_emails,
            self._scan_home_paths,
            self._scan_domain_users,
            self._scan_sids,
            self._scan_guids,
            self._scan_macs,
            self._scan_ipv4,
            self._scan_ipv6,
            self._scan_fields,
            self._scan_fqdns,
            self._scan_dictionary,
            self._scan_always_mask,
        )

    def _apply(self, text: str, scanner: Callable[[str], List[Candidate]]) -> str:
        candidates = _drop_overlaps(scanner(text))
        if not candidates:
            return text
        mapping = self.vault.ensure((candidate.namespace, candidate.value) for candidate in candidates)
        parts: List[str] = []
        position = 0
        for candidate in candidates:
            stand_in = mapping[(candidate.namespace, normalize_key(candidate.namespace, candidate.value))]
            parts.append(text[position:candidate.start])
            parts.append(candidate.render(stand_in))
            position = candidate.end
        parts.append(text[position:])
        return "".join(parts)

    # ----- masking ---------------------------------------------------------------------------

    def mask_text(self, text: Any) -> Any:
        if not isinstance(text, str) or not text:
            return text
        with self._lock:
            cached = self._cache.get((self.vault.version, text))
            if cached is not None:
                self._cache.move_to_end((self.vault.version, text))
                return cached
        masked = text
        for scanner in self._scanners():
            masked = self._apply(masked, scanner)
        with self._lock:
            self._cache[(self.vault.version, text)] = masked
            while len(self._cache) > self._CACHE_LIMIT:
                self._cache.popitem(last=False)
        return masked

    def mask_value(self, value: Any, namespace: Optional[str]) -> Any:
        """Mask one field value. Identity fields get a stand-in for the whole value."""
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped or self._keep(stripped):
            return value
        if namespace is None or len(stripped) > 300 or "\n" in stripped:
            return self.mask_text(value)
        address = P.parse_ipv4(stripped) or P.parse_ipv6(stripped)
        if address is not None:
            generic = P.is_generic_ipv4(address) if address.version == 4 else P.is_generic_ipv6(address)
            if generic or not self._should_mask("ip", stripped):
                return value
            return self.vault.ensure_one("ip", stripped)
        if P.EMAIL_RE.fullmatch(stripped):
            return self.vault.ensure_one("email", stripped) if self._should_mask("email", stripped) else value
        if "*" in stripped or stripped.startswith("$") or P.IPV4_RE.search(stripped) or P.EMAIL_RE.search(stripped):
            return self.mask_text(value)
        target = self._value_namespace(namespace, stripped)
        if target is None:
            return self.mask_text(value)
        if not self._should_mask(target, stripped):
            return value
        return self.vault.ensure_one(target, stripped)

    def mask_structure(
        self,
        data: Any,
        *,
        hint: Optional[str] = None,
        splunk_apps: bool = True,
        drop: FrozenSet[str] = frozenset(),
    ) -> Any:
        """Mask nested data, using field names to decide what each value is."""
        return self._walk_settled(data, hint, splunk_apps, drop)

    def _walk_settled(self, data: Any, hint: Optional[str], splunk_apps: bool, drop: FrozenSet[str]) -> Any:
        terms_version = self.vault.terms_version
        masked = self._walk(data, hint, splunk_apps, drop, 0)
        if self.vault.terms_version != terms_version:
            # A name first seen in an identity field can also appear in free text walked before it.
            masked = self._walk(data, hint, splunk_apps, drop, 0)
        return masked

    def _walk(self, data: Any, hint: Optional[str], splunk_apps: bool, drop: FrozenSet[str], depth: int) -> Any:
        if depth > 40:
            return "[nested data omitted]"
        if isinstance(data, Mapping):
            names_visible = hint == "object" and is_shipped_content_app(
                str(data.get("app") or data.get("eai:acl.app") or "")
            )
            masked: Dict[Any, Any] = {}
            for key, value in data.items():
                if str(key) in drop:
                    continue
                normalized = field_key(key)
                namespace = FIELD_NAMESPACES.get(normalized)
                if namespace is None and splunk_apps and normalized == "app":
                    namespace = "app"
                if namespace is None and hint and normalized in NAME_FIELDS and not names_visible:
                    namespace = hint
                new_key = self.mask_text(key) if isinstance(key, str) else key
                if isinstance(value, str):
                    masked[new_key] = self.mask_value(value, namespace)
                else:
                    masked[new_key] = self._walk(value, namespace, splunk_apps, drop, depth + 1)
            return masked
        if isinstance(data, (list, tuple)):
            return [
                self.mask_value(item, hint) if isinstance(item, str) else self._walk(item, hint, splunk_apps, drop, depth + 1)
                for item in data
            ]
        if isinstance(data, str):
            return self.mask_value(data, hint)
        return data

    def mask_rows(self, rows: Sequence[Any], *, hint: Optional[str] = None, splunk_apps: bool = False,
                  drop_raw: bool = True) -> List[Any]:
        drop = RAW_EVENT_FIELDS if drop_raw else frozenset()
        return self._walk_settled(list(rows or []), hint, splunk_apps, drop)

    def seed(self, inventory: Mapping[str, Iterable[Any]]) -> int:
        """Register known names (from discovery) so they are masked wherever they appear."""
        items: List[Tuple[str, str]] = []
        for namespace, values in inventory.items():
            for value in values or ():
                if not isinstance(value, str):
                    continue
                stripped = value.strip()
                if not stripped or self._keep(stripped) or self._looks_masked(stripped):
                    continue
                address = P.parse_ipv4(stripped) or P.parse_ipv6(stripped)
                if address is not None:
                    generic = P.is_generic_ipv4(address) if address.version == 4 else P.is_generic_ipv6(address)
                    if not generic:
                        items.append(("ip", stripped))
                    continue
                if P.EMAIL_RE.fullmatch(stripped):
                    items.append(("email", stripped))
                    continue
                target = self._value_namespace(namespace, stripped)
                if target is not None:
                    items.append((target, stripped))
        if items:
            self.vault.ensure(items)
        return len(items)

    # ----- leak check ------------------------------------------------------------------------

    def find_leaks(self, text: Any) -> List[Tuple[str, str]]:
        """Values in already-masked text that masking would still replace."""
        if not isinstance(text, str) or not text:
            return []
        leaks: List[Tuple[str, str]] = []
        seen = set()
        for scanner in self._scanners():
            for candidate in scanner(text):
                key = (candidate.namespace, normalize_key(candidate.namespace, candidate.value))
                if key not in seen:
                    seen.add(key)
                    leaks.append((candidate.namespace, candidate.value))
        return leaks

    # ----- restore ---------------------------------------------------------------------------

    @staticmethod
    def _quote_if_needed(text: str, start: int, real: str) -> str:
        if not re.search(r"[\s|()\[\],=\"]", real):
            return real
        before = text[:start].rstrip()
        if text[start - 1:start] in {'"', "'"}:
            return real
        if before.endswith("=") or before.lower().endswith("savedsearch"):
            return '"' + real.replace('"', '\\"') + '"'
        return real

    def _restore_spans(self, text: str, allowed: Optional[Callable[[str], bool]] = None
                       ) -> Tuple[List[Tuple[int, int, Optional[str]]], List[str]]:
        spans: List[Tuple[int, int, Optional[str]]] = []
        unknown: List[str] = []

        def resolve(stand_in: str, shown: str) -> Optional[Tuple[str, str]]:
            found = self.vault.real_for(stand_in)
            if found is not None and allowed is not None and not allowed(stand_in_key(stand_in)):
                found = None
            if found is None and shown not in unknown:
                unknown.append(shown)
            return found

        for match in STAND_IN_RE.finditer(text):
            namespace = PREFIX_TO_NAMESPACE[match.group("prefix").lower()]
            found = resolve(format_stand_in(namespace, int(match.group("num"))), match.group(0))
            if found is None:
                continue
            suffix = match.group("suffix") or ""
            keep_suffix = namespace not in {"domain", "email"}
            end = match.end() - (len(suffix) if keep_suffix else 0)
            spans.append((match.start(), end, self._quote_if_needed(text, match.start(), found[1])))
        for match in GUID_STAND_IN_RE.finditer(text):
            found = resolve(match.group(0), match.group(0))
            if found is not None:
                spans.append((match.start(), match.end(), found[1]))
        for match in SID_STAND_IN_RE.finditer(text):
            found = resolve(match.group("sid"), match.group("sid"))
            if found is not None:
                spans.append((match.start("sid"), match.end("sid"), found[1]))
        for match in MAC_STAND_IN_RE.finditer(text):
            group = "mac" if match.group("mac") else "cisco"
            value = match.group(group)
            digits = P.normalize_mac(value)
            found = resolve(":".join(digits[i:i + 2] for i in range(0, 12, 2)), value)
            if found is not None:
                spans.append((match.start(group), match.end(group), found[1]))
        for match in P.IPV4_RE.finditer(text):
            ip = match.group("ip")
            address = P.parse_ipv4(ip)
            if address is None or not in_stand_in_address_space(address):
                continue
            found = resolve(ip, ip)
            if found is not None:
                spans.append((match.start("ip"), match.end("ip"), found[1]))
        for match in P.IPV6_CANDIDATE_RE.finditer(text):
            address = P.parse_ipv6(match.group("ip"))
            if address is None or not in_stand_in_address_space(address):
                continue
            found = resolve(str(address), match.group("ip"))
            if found is not None:
                spans.append((match.start("ip"), match.end("ip"), found[1]))
        return spans, unknown

    def restore_text(self, text: Any, allowed: Optional[Callable[[str], bool]] = None) -> Tuple[Any, List[str]]:
        """Put real names back in a reply. Returns the text and any stand-ins left as they were.

        ``allowed`` limits restoring to stand-ins the model was actually shown, so a reply that
        lists made-up or guessed stand-ins cannot reveal other names from the vault.
        """
        if not isinstance(text, str) or not text:
            return text, []
        spans, unknown = self._restore_spans(text, allowed)
        if not spans:
            return text, unknown
        parts: List[str] = []
        position = 0
        for start, end, replacement in sorted(spans, key=lambda item: (item[0], -(item[1] - item[0]))):
            if start < position or replacement is None:
                continue
            parts.append(text[position:start])
            parts.append(replacement)
            position = end
        parts.append(text[position:])
        return "".join(parts), unknown

    def restore_reply(self, text: Any, allowed: Optional[Callable[[str], bool]] = None) -> Tuple[Any, List[str]]:
        """Restore a model reply, rebuilding any JSON objects in it so restored names stay valid JSON.

        Tool calls arrive as JSON inside the reply; restoring them as plain text could put a raw
        quote or backslash from a real name inside a JSON string.
        """
        if not isinstance(text, str) or not text:
            return text, []
        unknown: List[str] = []
        parts: List[str] = []
        position = 0

        def add_unknown(items: Sequence[str]) -> None:
            unknown.extend(item for item in items if item not in unknown)

        for start, end, parsed in _json_objects(text):
            segment = text[start:end]
            if not self.stand_ins_present(segment):
                continue
            restored_plain, missing = self.restore_text(text[position:start], allowed)
            add_unknown(missing)
            parts.append(restored_plain)
            restored, missing = self.restore_structure(parsed, allowed)
            add_unknown(missing)
            parts.append(json.dumps(restored, ensure_ascii=False, indent=2 if "\n" in segment else None))
            position = end
        restored_plain, missing = self.restore_text(text[position:], allowed)
        add_unknown(missing)
        parts.append(restored_plain)
        return "".join(parts), unknown

    @staticmethod
    def stand_ins_present(text: str) -> bool:
        return bool(
            STAND_IN_RE.search(text) or GUID_STAND_IN_RE.search(text) or SID_STAND_IN_RE.search(text)
            or MAC_STAND_IN_RE.search(text) or P.IPV4_RE.search(text) or P.IPV6_CANDIDATE_RE.search(text)
        )

    def restore_structure(self, data: Any, allowed: Optional[Callable[[str], bool]] = None) -> Tuple[Any, List[str]]:
        unknown: List[str] = []

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                restored, missing = self.restore_text(value, allowed)
                unknown.extend(item for item in missing if item not in unknown)
                return restored
            if isinstance(value, Mapping):
                return {walk(key) if isinstance(key, str) else key: walk(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [walk(item) for item in value]
            return value

        return walk(data), unknown

    def unknown_stand_ins(self, text: Any, allowed: Optional[Callable[[str], bool]] = None) -> List[str]:
        if not isinstance(text, str):
            text = json.dumps(text, default=str)
        return self._restore_spans(text, allowed)[1]

    def stand_ins_in(self, text: Any) -> Dict[str, set]:
        """Assigned stand-ins that appear in masked text, grouped by namespace."""
        used: Dict[str, set] = {}
        if not isinstance(text, str) or not text:
            return used

        def add(stand_in: str) -> None:
            found = self.vault.real_for(stand_in)
            if found is not None:
                used.setdefault(found[0], set()).add(stand_in_key(stand_in))

        for match in STAND_IN_RE.finditer(text):
            namespace = PREFIX_TO_NAMESPACE[match.group("prefix").lower()]
            add(format_stand_in(namespace, int(match.group("num"))))
        for match in GUID_STAND_IN_RE.finditer(text):
            add(match.group(0))
        for match in SID_STAND_IN_RE.finditer(text):
            add(match.group("sid"))
        for match in MAC_STAND_IN_RE.finditer(text):
            digits = P.normalize_mac(match.group("mac") or match.group("cisco"))
            add(":".join(digits[i:i + 2] for i in range(0, 12, 2)))
        for match in P.IPV4_RE.finditer(text):
            address = P.parse_ipv4(match.group("ip"))
            if address is not None and in_stand_in_address_space(address):
                add(match.group("ip"))
        for match in P.IPV6_CANDIDATE_RE.finditer(text):
            address = P.parse_ipv6(match.group("ip"))
            if address is not None and in_stand_in_address_space(address):
                add(str(address))
        return used
