"""Decide whether a file is a capture we will parse, before any parsing happens."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "<", 1_000),      # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": ("pcap", ">", 1_000),      # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("pcap", "<", 1),          # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": ("pcap", ">", 1),          # big-endian, nanoseconds
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# Common non-capture formats, so a rejection can say what the file really is.
KNOWN_SIGNATURES = [
    (b"MZ", "a Windows executable"),
    (b"\x7fELF", "a Linux executable"),
    (b"\x1f\x8b", "a gzip archive (decompress it first)"),
    (b"PK\x03\x04", "a ZIP archive"),
    (b"\x89PNG", "a PNG image"),
    (b"\xff\xd8\xff", "a JPEG image"),
    (b"%PDF", "a PDF document"),
    (b"<", "an HTML or XML document"),
    (b"#!", "a script"),
]


@dataclass(frozen=True, slots=True)
class Sniffed:
    ok: bool
    format: str | None
    message: str


def check_extension(file_name: str) -> bool:
    return PurePath(file_name).suffix.lower() in ALLOWED_EXTENSIONS


def sniff(head: bytes) -> Sniffed:
    """Identify the capture format from its first bytes (at least 12 for pcapng)."""
    if len(head) < 4:
        return Sniffed(False, None, "File is too small to be a capture.")
    magic = head[:4]
    if magic in PCAP_MAGICS:
        if len(head) < 24:
            return Sniffed(False, None, "File ends inside the pcap header.")
        return Sniffed(True, "pcap", "pcap magic number found.")
    if magic == PCAPNG_SHB:
        if len(head) < 12:
            return Sniffed(False, None, "File ends inside the pcapng header.")
        if head[8:12] not in (b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"):
            return Sniffed(False, None, "pcapng header has an invalid byte-order magic.")
        return Sniffed(True, "pcapng", "pcapng section header found.")
    for sig, what in KNOWN_SIGNATURES:
        if head.startswith(sig):
            return Sniffed(False, None, f"This is not a capture; it looks like {what}.")
    return Sniffed(False, None, "Unrecognised file format: no pcap or pcapng magic number.")
