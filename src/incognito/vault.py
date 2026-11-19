"""Encrypted mapping between real names and their stand-ins for one Splunk connection.

The mapping never leaves this machine. It is encrypted with the application's key and shared by
the web server and its worker processes, so every assignment happens under a file lock and the
in-memory copy is reloaded whenever another process has written a newer one.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from .patterns import normalize_mac
from .vocabulary import is_free_text_term

# Prefix of the plain stand-ins (host_0012) for each namespace.
PREFIXES = {
    "host": "host",
    "index": "idx",
    "user": "user",
    "app": "app",
    "search": "search",
    "kv": "kv",
    "role": "role",
    "object": "object",
    "term": "term",
    "secret": "secret",
    "domain": "domain",
    "email": "email",
}
PREFIX_TO_NAMESPACE = {prefix: namespace for namespace, prefix in PREFIXES.items()}

# Namespaces whose distinctive names are replaced wherever they appear in text. When the same
# name is known in several namespaces, the first one listed wins.
TEXT_NAMESPACES = ("host", "index", "user", "app", "search", "kv", "role", "object", "domain", "secret")

NAMESPACES = frozenset(PREFIXES) | {"ip", "mac", "guid", "sid"}

_INTERNAL_POOL_PRIMARY = 512  # /24 networks in 198.18.0.0/15
_PUBLIC_POOL_PRIMARY = ("192.0.2", "198.51.100", "203.0.113")
_IPV6_STAND_IN_BASE = 0x20010DB8 << 32  # 2001:db8::/32, as the upper 64 bits of a /64

_IPV4_STAND_IN_NETWORKS = (
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_IPV6_STAND_IN_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


class VaultError(RuntimeError):
    """The stand-in mapping could not be read or extended."""


def format_stand_in(namespace: str, number: int) -> str:
    if namespace == "domain":
        return f"domain_{number:04d}.example"
    if namespace == "email":
        return f"email_{number:04d}@example.com"
    if namespace == "guid":
        return f"00000000-0000-4000-8000-{number:012d}"
    if namespace == "sid":
        return f"S-1-5-21-0-0-{number}"
    if namespace == "mac":
        return f"02:00:00:{(number >> 16) & 255:02x}:{(number >> 8) & 255:02x}:{number & 255:02x}"
    return f"{PREFIXES[namespace]}_{number:04d}"


def normalize_key(namespace: str, value: str) -> str:
    text = str(value).strip()
    if namespace == "secret":
        return text
    if namespace == "ip":
        try:
            return str(ipaddress.ip_address(text.split("%", 1)[0]))
        except ValueError:
            return text.lower()
    if namespace == "mac":
        return normalize_mac(text)
    if namespace == "sid":
        return text.upper()
    return " ".join(text.lower().split())


def stand_in_key(stand_in: str) -> str:
    text = str(stand_in).strip()
    if text.count(":") >= 2 and "." not in text:
        try:
            return str(ipaddress.IPv6Address(text))
        except ValueError:
            pass
    if text[:1] in {"S", "s"} and text[1:2] == "-":
        return text.upper()
    return text.lower()


def in_stand_in_address_space(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        if str(address) == "255.255.255.255":
            return False
        return any(address in network for network in _IPV4_STAND_IN_NETWORKS)
    return address in _IPV6_STAND_IN_NETWORK


def _ipv4_pool_network(pool: str, index: int) -> Optional[str]:
    if pool == "ip4_internal":
        if index < _INTERNAL_POOL_PRIMARY:
            return f"198.{18 + index // 256}.{index % 256}"
        value = (240 << 16) + (index - _INTERNAL_POOL_PRIMARY)
        limit = 248 << 16
    else:
        if index < len(_PUBLIC_POOL_PRIMARY):
            return _PUBLIC_POOL_PRIMARY[index]
        value = (248 << 16) + (index - len(_PUBLIC_POOL_PRIMARY))
        limit = (255 << 16) | (255 << 8) | 255
    if value >= limit:
        return None
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` across processes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        if os.name != "nt":
            os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _empty_state() -> dict:
    return {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counters": {},
        "entries": {},
        "net4": {},
        "net6": {},
        "meta": {},
    }


class StandInVault:
    """Real-to-stand-in mapping for one connection, encrypted at rest."""

    def __init__(self, path: Path, fernet) -> None:
        self.path = Path(path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._fernet = fernet
        self._lock = threading.RLock()
        self._signature: Optional[Tuple[int, int]] = None
        self._state = _empty_state()
        self._reverse: Dict[str, Tuple[str, str]] = {}
        self._used_stand_in_nets: set = set()
        self.version = 0
        self.terms_version = 0
        with self._lock:
            self._load()

    # ----- persistence -------------------------------------------------------------------

    def _disk_signature(self) -> Optional[Tuple[int, int]]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def _load(self) -> None:
        signature = self._disk_signature()
        if signature is None:
            state = _empty_state()
        else:
            try:
                payload = self._fernet.decrypt(self.path.read_bytes())
                state = json.loads(payload.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - any failure means the mapping is unusable
                raise VaultError(
                    "The incognito stand-in mapping could not be decrypted. Reset the stand-ins to start a new mapping."
                ) from exc
            if not isinstance(state, dict):
                raise VaultError("The incognito stand-in mapping is not in the expected format.")
            for key, default in _empty_state().items():
                state.setdefault(key, default)
        self._state = state
        self._signature = signature
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        reverse: Dict[str, Tuple[str, str]] = {}
        for namespace, entries in self._state["entries"].items():
            for real, stand_in in entries.values():
                reverse[stand_in_key(stand_in)] = (namespace, real)
        self._reverse = reverse
        self._used_stand_in_nets = set(self._state["net4"].values())
        self.version += 1
        self.terms_version += 1

    def _save(self) -> None:
        payload = json.dumps(self._state, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        write_private_file(self.path, self._fernet.encrypt(payload))
        self._signature = self._disk_signature()

    def refresh(self) -> bool:
        """Reload when another process has written a newer mapping. Returns True if reloaded."""
        with self._lock:
            if self._disk_signature() == self._signature:
                return False
            self._load()
            return True

    # ----- lookups -----------------------------------------------------------------------

    def lookup(self, namespace: str, value: str) -> Optional[str]:
        key = normalize_key(namespace, value)
        with self._lock:
            entry = self._state["entries"].get(namespace, {}).get(key)
        return entry[1] if entry else None

    def real_for(self, stand_in: str) -> Optional[Tuple[str, str]]:
        """Return ``(namespace, real)`` for a stand-in, or None if it was never assigned."""
        key = stand_in_key(stand_in)
        with self._lock:
            found = self._reverse.get(key)
        if found is None and self.refresh():
            with self._lock:
                found = self._reverse.get(key)
        return found

    def is_stand_in(self, value: str) -> bool:
        with self._lock:
            return stand_in_key(value) in self._reverse

    def counts(self) -> Dict[str, int]:
        with self._lock:
            return {namespace: len(entries) for namespace, entries in self._state["entries"].items() if entries}

    def text_terms(self) -> Dict[str, Tuple[str, str]]:
        """Distinctive real names to replace in free text: lowercase name -> (namespace, stand-in)."""
        terms: Dict[str, Tuple[str, str]] = {}
        with self._lock:
            entries = self._state["entries"]
            for namespace in TEXT_NAMESPACES:
                for key, (real, stand_in) in entries.get(namespace, {}).items():
                    if key in terms:
                        continue
                    if namespace == "secret" or is_free_text_term(real):
                        terms[key] = (namespace, stand_in)
        return terms

    def entries_real(self, namespace: str, key: str) -> Optional[str]:
        with self._lock:
            entry = self._state["entries"].get(namespace, {}).get(key)
        return entry[0] if entry else None

    def get_meta(self, key: str, default=None):
        with self._lock:
            return self._state["meta"].get(key, default)

    def set_meta(self, key: str, value) -> None:
        with self._lock, file_lock(self._lock_path):
            if self._disk_signature() != self._signature:
                self._load()
            self._state["meta"][key] = value
            self._save()

    # ----- assignment --------------------------------------------------------------------

    def ensure(self, items: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str], str]:
        """Assign stand-ins to any values that do not have one yet and return all of them."""
        wanted: List[Tuple[str, str, str]] = []
        seen = set()
        for namespace, value in items:
            if namespace not in NAMESPACES:
                raise VaultError(f"Unknown stand-in namespace: {namespace}")
            text = str(value).strip()
            if not text:
                continue
            key = normalize_key(namespace, text)
            if (namespace, key) in seen:
                continue
            seen.add((namespace, key))
            wanted.append((namespace, key, text))
        result: Dict[Tuple[str, str], str] = {}
        if not wanted:
            return result
        with self._lock:
            missing = [item for item in wanted if self._state["entries"].get(item[0], {}).get(item[1]) is None]
            if missing:
                with file_lock(self._lock_path):
                    if self._disk_signature() != self._signature:
                        self._load()
                    added_terms = False
                    changed = False
                    for namespace, key, text in missing:
                        entries = self._state["entries"].setdefault(namespace, {})
                        if key in entries:
                            continue
                        stand_in = self._allocate(namespace, text)
                        entries[key] = [text, stand_in]
                        self._reverse[stand_in_key(stand_in)] = (namespace, text)
                        changed = True
                        if namespace in TEXT_NAMESPACES:
                            added_terms = True
                    if changed:
                        self._save()
                        self.version += 1
                        if added_terms:
                            self.terms_version += 1
            entries = self._state["entries"]
            for namespace, key, _text in wanted:
                result[(namespace, key)] = entries[namespace][key][1]
        return result

    def ensure_one(self, namespace: str, value: str) -> str:
        key = normalize_key(namespace, value)
        return self.ensure([(namespace, value)])[(namespace, key)]

    def _next_number(self, counter: str) -> int:
        number = int(self._state["counters"].get(counter, 0)) + 1
        self._state["counters"][counter] = number
        return number

    def _allocate(self, namespace: str, value: str) -> str:
        if namespace == "ip":
            return self._allocate_ip(value)
        while True:
            stand_in = format_stand_in(namespace, self._next_number(namespace))
            if stand_in_key(stand_in) not in self._reverse:
                return stand_in

    def _allocate_ip(self, value: str) -> str:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        if isinstance(address, ipaddress.IPv4Address):
            return self._allocate_ipv4(address)
        return self._allocate_ipv6(address)

    def _allocate_ipv4(self, address: ipaddress.IPv4Address) -> str:
        octets = str(address).split(".")
        network = ".".join(octets[:3])
        stand_in_network = self._state["net4"].get(network)
        if stand_in_network is None:
            pool = "ip4_public" if address.is_global else "ip4_internal"
            while True:
                index = int(self._state["counters"].get(pool, 0))
                self._state["counters"][pool] = index + 1
                candidate = _ipv4_pool_network(pool, index)
                if candidate is None:
                    raise VaultError("No stand-in addresses are left. Reset the stand-ins to start a new mapping.")
                if candidate in self._state["net4"] or candidate in self._used_stand_in_nets:
                    continue
                break
            stand_in_network = candidate
            self._state["net4"][network] = stand_in_network
            self._used_stand_in_nets.add(stand_in_network)
        return f"{stand_in_network}.{octets[3]}"

    def _allocate_ipv6(self, address: ipaddress.IPv6Address) -> str:
        prefix = str(int(address) >> 64)
        record = self._state["net6"].get(prefix)
        if record is None:
            index = int(self._state["counters"].get("ip6", 0))
            self._state["counters"]["ip6"] = index + 1
            record = [_IPV6_STAND_IN_BASE | (index & 0xFFFFFFFF), 0]
            self._state["net6"][prefix] = record
        record[1] = int(record[1]) + 1
        return str(ipaddress.IPv6Address((int(record[0]) << 64) | record[1]))

    def rotate(self) -> None:
        """Forget every assignment so the next request starts a new mapping."""
        with self._lock, file_lock(self._lock_path):
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self._state = _empty_state()
            self._signature = None
            self._rebuild_indexes()

    def entries(self) -> Mapping[str, Mapping[str, List[str]]]:
        with self._lock:
            return json.loads(json.dumps(self._state["entries"]))
