"""Shared types for the streaming capture readers, and the format dispatcher."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from ..config import Limits
from .validate import sniff


@dataclass(slots=True)
class RawPacket:
    frame: int          # 1-based, matches Wireshark's "No." column
    ts_ns: int          # absolute timestamp in nanoseconds since the epoch
    linktype: int
    data: bytes
    wire_len: int
    offset: int         # byte offset of the record in the file, for error messages


@dataclass
class IngestCounters:
    """Mutable counters filled in while reading and decoding."""

    limits: Limits
    format: str = "unknown"
    link_types: set[int] = field(default_factory=set)
    frames: int = 0
    decoded: int = 0
    skip_reasons: Counter = field(default_factory=Counter)
    skip_examples: list[tuple[int, str]] = field(default_factory=list)
    stopped_early: bool = False
    stop_reason: str | None = None
    state_caps_hit: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    def skip(self, frame: int, reason: str) -> None:
        self.skip_reasons[reason] += 1
        if len(self.skip_examples) < self.limits.max_skip_examples:
            self.skip_examples.append((frame, reason))

    def stop(self, reason: str) -> None:
        self.stopped_early = True
        self.stop_reason = reason

    @property
    def skipped(self) -> int:
        return sum(self.skip_reasons.values())


class CaptureFormatError(Exception):
    """The file is not a capture we accept. Raised before any packet is read."""


def read_capture(f: BinaryIO, limits: Limits, counters: IngestCounters) -> Iterator[RawPacket]:
    """Sniff the format from the first bytes and stream packets from the right reader."""
    from .pcap import read_pcap
    from .pcapng import read_pcapng

    head = f.read(24)
    result = sniff(head)
    if not result.ok:
        raise CaptureFormatError(result.message)
    f.seek(0)
    counters.format = result.format or "unknown"
    if result.format == "pcap":
        return read_pcap(f, limits, counters)
    return read_pcapng(f, limits, counters)
