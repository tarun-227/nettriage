"""Read and decode a capture as one stream of packets, counting what we skip."""

from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from ..config import Limits
from ..decode import decode
from ..decode.model import Packet
from .capture import IngestCounters, read_capture


def stream_packets(f: BinaryIO, limits: Limits, counters: IngestCounters) -> Iterator[Packet]:
    for raw in read_capture(f, limits, counters):
        p = decode(raw)
        if p.error:
            counters.skip(raw.frame, p.error)
        else:
            counters.decoded += 1
        yield p
