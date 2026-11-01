"""Proof Pack: evidence you can hand to someone else without handing over your network.

A Proof Pack is a zip with the report, one evidence capture per finding, a manifest of SHA-256 hashes and a
README. Before anything goes in:

- Every IP and MAC address is replaced by a pseudonym. IPs use a keyed prefix-preserving map, the
  construction of Crypto-PAn (Xu, Fan, Ammar, Moon, 2002; also IETF draft-denis-ipcrypt "pfx"): bit i of
  the output is bit i of the input XOR a keyed function of the first i input bits. Two addresses that
  share an n-bit prefix still share an n-bit prefix, so "same subnet" and "same server" survive, while the
  addresses themselves do not. The keyed function is HMAC-SHA256, from the standard library. The key is
  random for each pack and never stored, so nobody, us included, can reverse it. Private ranges keep their
  range prefix (192.168.x.x stays 192.168.x.x) and public addresses stay public, so the evidence still reads
  correctly. MACs keep their vendor prefix (OUI) and lose the device part.
- Packets are cut after their transport header. What a packet said is gone; who talked to whom, when, with
  which flags, TTLs and IP IDs (the relay proof) stays. TCP, UDP and ICMP checksums are zeroed, because a
  16-bit checksum over the real addresses would let someone test guesses of them.
- The capture's own file name, the list of names looked up and device hostnames are left out. The SHA-256 of
  the original capture is kept: it lets the owner prove which capture the pack came from and reveals nothing.

Tamper evidence: the manifest lists the SHA-256 of every file, and the pack's root hash is the SHA-256 of
those lines. Share the root separately (a ticket, a chat); ``nettriage verify`` recomputes everything offline.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import ipaddress
import json
import re
import secrets
import struct
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .. import __version__
from ..config import Limits
from ..ingest.capture import IngestCounters, read_capture
from ..schema import Report
from .pcapwriter import pcap_bytes

FORMAT = "nettriage-proof-pack/1"
MAX_ENTRIES = 512
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_RATIO = 200  # a zip entry that inflates more than this is treated as a zip bomb
_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

# (network, prefix bits kept as they are). Anything else is public and is mapped to a public address.
_KEEP_V4 = [(ipaddress.ip_network(n), k) for n, k in (
    ("0.0.0.0/32", 32), ("255.255.255.255/32", 32), ("224.0.0.0/4", 32), ("127.0.0.0/8", 8), ("10.0.0.0/8", 8),
    ("172.16.0.0/12", 12), ("192.168.0.0/16", 16), ("169.254.0.0/16", 16), ("100.64.0.0/10", 10))]
_KEEP_V6 = [(ipaddress.ip_network(n), k) for n, k in (
    ("::/128", 128), ("::1/128", 128), ("ff00::/8", 128), ("fe80::/10", 10), ("fc00::/7", 8))]
_VIRTUAL_MACS = ("00:00:5e:00:01:", "00:00:5e:00:02:", "00:00:0c:07:ac:", "00:00:0c:9f:f", "00:07:b4:00:")

# Addresses inside prose: a sentence's full stop or a "MAC:" label next to one must not hide it.
_IPV4_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f]|:[0-9a-f])")
_IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")


class Pseudonymizer:
    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(32)
        self._ips: dict[str, str] = {}
        self._macs: dict[str, str] = {}

    def _bit(self, *parts: bytes) -> int:
        return hmac.new(self.key, b"|".join(parts), hashlib.sha256).digest()[0] >> 7

    def _prefix_preserving(self, value: int, bits: int, keep: int, tweak: int) -> int:
        out = 0
        for i in range(bits):
            bit = (value >> (bits - 1 - i)) & 1
            if i >= keep:
                prefix = value >> (bits - i) if i else 0
                bit ^= self._bit(b"pfx", bytes([bits, i, tweak]), prefix.to_bytes(16, "big"))
            out = (out << 1) | bit
        return out

    def ip(self, text: str) -> str:
        if text in self._ips:
            return self._ips[text]
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return text
        rules, bits = (_KEEP_V4, 32) if addr.version == 4 else (_KEEP_V6, 128)
        keep = next((k for net, k in rules if addr in net), 0)
        value = int(addr)
        new = value
        if keep < bits:
            # Cycle-walk so a public address never lands in a private or special range (and vice versa).
            for tweak in range(32):
                new = self._prefix_preserving(value, bits, keep, tweak)
                special = any(ipaddress.ip_address(new) in net for net, _ in rules)
                if keep or not special:
                    break
        out = str(ipaddress.ip_address(new)) if addr.version == 4 else str(ipaddress.IPv6Address(new))
        self._ips[text] = out
        return out

    def mac(self, text: str) -> str:
        low = text.lower()
        if low in self._macs:
            return self._macs[low]
        octets = bytes.fromhex(low.replace(":", ""))
        if len(octets) != 6 or octets[0] & 1 or low.startswith(_VIRTUAL_MACS) or octets == b"\0" * 6:
            out = low  # broadcast, multicast, router-redundancy virtual MACs and zero keep their meaning
        else:
            tail = hmac.new(self.key, b"mac|" + octets, hashlib.sha256).digest()[:3]
            out = ":".join(f"{b:02x}" for b in octets[:3] + tail)
        self._macs[low] = out
        return out

    def ip_bytes(self, raw: bytes) -> bytes:
        addr = ipaddress.ip_address(raw)
        return ipaddress.ip_address(self.ip(str(addr))).packed

    def mac_bytes(self, raw: bytes) -> bytes:
        return bytes.fromhex(self.mac(":".join(f"{b:02x}" for b in raw)).replace(":", ""))

    def text(self, s: str) -> str:
        s = _MAC_RE.sub(lambda m: self.mac(m.group(0)), s)
        s = _IPV4_RE.sub(lambda m: self.ip(m.group(0)), s)

        def v6(m: re.Match) -> str:
            try:
                ipaddress.IPv6Address(m.group(0))
            except ValueError:
                return m.group(0)
            return self.ip(m.group(0))

        return _IPV6_RE.sub(v6, s)


# --- packets -------------------------------------------------------------------------------------------

def _ipv4_checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _transport(proto: int, data: bytes, at: int) -> bytes:
    """The transport header at ``at`` with its checksum zeroed, or nothing for other protocols."""
    if proto == 6 and len(data) >= at + 20:
        hl = min(max((data[at + 12] >> 4) * 4, 20), len(data) - at)
        seg = bytearray(data[at:at + hl])
        seg[16:18] = b"\0\0"
        return bytes(seg)
    if proto == 17 and len(data) >= at + 8:
        seg = bytearray(data[at:at + 8])
        seg[6:8] = b"\0\0"
        return bytes(seg)
    if proto in (1, 58) and len(data) >= at + 8:
        seg = bytearray(data[at:at + 8])
        seg[2:4] = b"\0\0"
        return bytes(seg)
    return b""


def _network(ethertype: int, data: bytes, at: int, ps: Pseudonymizer) -> bytes | None:
    if ethertype == 0x0806 and len(data) >= at + 28 and data[at + 4] == 6 and data[at + 5] == 4:
        arp = bytearray(data[at:at + 28])
        arp[8:14] = ps.mac_bytes(arp[8:14])
        arp[14:18] = ps.ip_bytes(bytes(arp[14:18]))
        arp[18:24] = ps.mac_bytes(arp[18:24])
        arp[24:28] = ps.ip_bytes(bytes(arp[24:28]))
        return bytes(arp)
    if ethertype == 0x0800 and len(data) >= at + 20 and data[at] >> 4 == 4:
        ihl = (data[at] & 0x0F) * 4
        if ihl < 20 or len(data) < at + ihl:
            return None
        hdr = bytearray(data[at:at + ihl])
        hdr[12:16] = ps.ip_bytes(bytes(hdr[12:16]))
        hdr[16:20] = ps.ip_bytes(bytes(hdr[16:20]))
        hdr[20:] = b"\x01" * (ihl - 20)  # options can carry addresses (record route): NOPs instead
        hdr[10:12] = b"\0\0"
        hdr[10:12] = struct.pack("!H", _ipv4_checksum(bytes(hdr)))
        first_fragment = (struct.unpack("!H", hdr[6:8])[0] & 0x1FFF) == 0
        return bytes(hdr) + (_transport(hdr[9], data, at + ihl) if first_fragment else b"")
    if ethertype == 0x86DD and len(data) >= at + 40 and data[at] >> 4 == 6:
        hdr = bytearray(data[at:at + 40])
        hdr[8:24] = ps.ip_bytes(bytes(hdr[8:24]))
        hdr[24:40] = ps.ip_bytes(bytes(hdr[24:40]))
        return bytes(hdr) + _transport(hdr[6], data, at + 40)
    return b""


def scrub_frame(linktype: int, data: bytes, ps: Pseudonymizer) -> bytes | None:
    """Pseudonymized headers of one frame, or None when the link type is not one we can rewrite safely."""
    if linktype == 1:
        if len(data) < 14:
            return None
        out = bytearray(ps.mac_bytes(data[0:6]) + ps.mac_bytes(data[6:12]))
        at, ethertype = 12, struct.unpack("!H", data[12:14])[0]
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8, 0x9100) or len(data) < at + 6:
                break
            out += data[at:at + 4]
            at += 4
            ethertype = struct.unpack("!H", data[at:at + 2])[0]
        out += data[at:at + 2]
        net = _network(ethertype, data, at + 2, ps)
        return None if net is None else bytes(out) + net
    if linktype in (101, 12, 14, 228, 229):
        version = data[0] >> 4 if data else 0
        net = _network(0x0800 if version == 4 else 0x86DD if version == 6 else -1, data, 0, ps)
        return net or None
    return None


def scrub_pcap(pcap: bytes, ps: Pseudonymizer) -> tuple[bytes, int, int]:
    """(pseudonymized pcap, packets kept, packets dropped because their link type can't be rewritten)."""
    limits = Limits()
    kept, dropped, linktype = [], 0, 1
    for raw in read_capture(io.BytesIO(pcap), limits, IngestCounters(limits)):
        linktype = raw.linktype
        frame = scrub_frame(raw.linktype, raw.data, ps)
        if frame is None:
            dropped += 1
            continue
        kept.append((raw.ts_ns, frame, raw.wire_len))
    return pcap_bytes(kept, linktype), len(kept), dropped


# --- the pack --------------------------------------------------------------------------------------------

@dataclass
class ProofPack:
    data: bytes
    root: str
    files: list[dict] = field(default_factory=list)


def _scrub_json(value, ps: Pseudonymizer):
    if isinstance(value, str):
        return ps.text(value)
    if isinstance(value, list):
        return [_scrub_json(v, ps) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_json(v, ps) for k, v in value.items()}
    return value


def _root(entries: list[dict]) -> str:
    lines = "".join(f"{e['sha256']}  {e['path']}\n" for e in sorted(entries, key=lambda e: e["path"]))
    return hashlib.sha256(lines.encode()).hexdigest()


def build_proof_pack(report: Report, evidence: dict[str, bytes], key: bytes | None = None) -> ProofPack:
    ps = Pseudonymizer(key)
    doc = report.model_dump(mode="json")
    original = doc["capture"]["file_name"]
    doc["capture"]["file_name"] = "capture" + (original[original.rfind("."):] if "." in original else "")
    doc["names"], doc["device_names"] = [], []
    doc = _scrub_json(doc, ps)

    files: dict[str, bytes] = {}
    kept_total = dropped_total = 0
    for fid, pcap in sorted(evidence.items()):
        scrubbed, kept, dropped = scrub_pcap(pcap, ps)
        kept_total += kept
        dropped_total += dropped
        files[f"evidence/{fid}.pcap"] = scrubbed
    files["report.json"] = json.dumps(doc, indent=2, ensure_ascii=False).encode()
    files["README.txt"] = _readme().encode()

    entries = [{"path": p, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for p, b in sorted(files.items())]
    root = _root(entries)
    manifest = {
        "format": FORMAT,
        "tool": f"NetTriage {__version__}",
        "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_capture_sha256": report.capture.sha256,
        "privacy": {
            "addresses": "IP and MAC addresses replaced with keyed, prefix-preserving pseudonyms; the key was "
                         "random and was discarded",
            "payloads": "packets cut after the TCP/UDP/ICMP header; transport checksums zeroed",
            "removed": ["capture file name", "names looked up", "device hostnames"],
            "packets_kept": kept_total,
            "packets_left_out": dropped_total,
        },
        "files": entries,
        "root": root,
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[path])
    return ProofPack(data=buf.getvalue(), root=root, files=entries)


def _readme() -> str:
    return (
        "NetTriage Proof Pack\n"
        "====================\n\n"
        "report.json      what NetTriage found, why, and what to do\n"
        "evidence/*.pcap  the packets behind each finding; open them in Wireshark\n"
        "manifest.json    the SHA-256 of every file and the pack's root hash\n\n"
        "Addresses are pseudonyms: addresses on the same network still share a prefix, but the real\n"
        "addresses cannot be recovered. Packets are cut after their transport header, so no content is\n"
        "included.\n\n"
        "To check that nothing was changed, compare the root hash with the one you were given, then run\n"
        "    nettriage verify <this-file>.zip --root <root hash>\n"
        "or recompute each file's SHA-256 against manifest.json.\n"
    )


# --- verification -----------------------------------------------------------------------------------------

@dataclass
class Verification:
    ok: bool
    root: str | None
    problems: list[str]
    files: int = 0
    source_capture_sha256: str | None = None
    created: str | None = None


def _safe_name(name: str) -> bool:
    return bool(name) and not name.startswith(("/", "\\")) and ".." not in name.split("/") \
        and "\\" not in name and ":" not in name and len(name) <= 200


def verify_proof_pack(data: bytes, expected_root: str | None = None) -> Verification:
    """Check a Proof Pack that may have come from anyone: every limit is enforced before anything is read."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return Verification(False, None, ["Not a valid zip file."])
    if len(infos) > MAX_ENTRIES:
        return Verification(False, None, [f"Too many entries ({len(infos)})."])
    total = sum(i.file_size for i in infos)
    if total > MAX_TOTAL_BYTES:
        return Verification(False, None, ["Unpacked size is too large."])
    for i in infos:
        if not _safe_name(i.filename) or i.is_dir():
            return Verification(False, None, ["The zip contains an unsafe path."])
        if i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
            return Verification(False, None, ["An entry inflates suspiciously (possible zip bomb)."])
    names = {i.filename for i in infos}
    if "manifest.json" not in names:
        return Verification(False, None, ["No manifest.json: this is not a NetTriage Proof Pack."])
    try:
        manifest = json.loads(zf.read("manifest.json"))
        entries = manifest["files"]
        if manifest.get("format") != FORMAT or not isinstance(entries, list):
            raise ValueError
    except (ValueError, KeyError, TypeError, zipfile.BadZipFile):
        return Verification(False, None, ["manifest.json is not a Proof Pack manifest."])

    problems = []
    listed = set()
    for e in entries:
        path = e.get("path") if isinstance(e, dict) else None
        if not isinstance(path, str) or not _safe_name(path):
            problems.append("The manifest lists an unsafe path.")
            continue
        listed.add(path)
        if path not in names:
            problems.append(f"Missing file: {path}")
            continue
        try:
            digest = hashlib.sha256(zf.read(path)).hexdigest()
        except (zipfile.BadZipFile, OSError):
            problems.append(f"Unreadable file: {path}")
            continue
        if digest != e.get("sha256"):
            problems.append(f"Changed since packing: {path}")
    for extra in sorted(names - listed - {"manifest.json"}):
        problems.append(f"Not in the manifest: {extra}")
    root = _root([e for e in entries if isinstance(e, dict) and isinstance(e.get("path"), str)
                  and isinstance(e.get("sha256"), str)])
    if root != manifest.get("root"):
        problems.append("The manifest's root hash does not match its file list.")
    if expected_root and expected_root.strip().lower() != root:
        problems.append("The root hash differs from the one you were given.")
    return Verification(not problems, root, problems, files=len(listed),
                        source_capture_sha256=manifest.get("source_capture_sha256"), created=manifest.get("created"))
