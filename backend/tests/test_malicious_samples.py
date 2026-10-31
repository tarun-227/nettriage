"""Every committed hostile sample is handled gracefully, with the outcome we document."""

from __future__ import annotations

from pathlib import Path

import pytest
from helpers import read_all
from nettriage.ingest.capture import CaptureFormatError

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "malicious"
CONTROL = set(range(0x00, 0x20)) | {0x7F}


def load(name: str):
    return read_all((SAMPLES / name).read_bytes())


def test_disguised_executable():
    with pytest.raises(CaptureFormatError, match="Windows executable"):
        load("not_a_pcap.exe.pcap")


def test_empty_file():
    with pytest.raises(CaptureFormatError, match="too small"):
        load("empty.pcap")


def test_truncated_capture_keeps_complete_packets():
    packets, c = load("truncated.pcap")
    assert len(packets) == 4 and c.stopped_early and "cut short" in c.stop_reason


def test_huge_caplen():
    packets, c = load("huge_caplen.pcap")
    assert len(packets) == 1 and c.stopped_early and "limit" in c.stop_reason


def test_bad_pcapng_block_length():
    packets, c = load("bad_block_len.pcapng")
    assert packets == [] and c.stopped_early and "invalid length" in c.stop_reason


def test_corrupt_packets_are_skipped_and_good_ones_survive():
    packets, c = load("corrupt_packets.pcap")
    assert len(packets) == 9 and not c.stopped_early
    assert sum(1 for p in packets if p.dns is not None) == 4
    for reason in ("malformed IPv4 header", "malformed TCP header", "malformed DHCP message",
                   "malformed link-layer header"):
        assert c.skip_reasons[reason] >= 1, reason


def test_dns_pointer_loops():
    packets, c = load("dns_pointer_loop.pcap")
    assert c.skip_reasons["malformed DNS message"] == 2
    assert sum(1 for p in packets if p.dns is not None) == 2


def test_xss_payloads_decode_as_inert_text():
    packets, c = load("xss_payloads.pcap")
    assert c.skipped == 0
    texts = [p.dns.qname for p in packets if p.dns] + [p.dhcp.hostname for p in packets if p.dhcp]
    assert any("<script>" in t for t in texts)
    assert any(t.startswith("=HYPERLINK") for t in texts)
    for t in texts:
        assert not any(ord(ch) in CONTROL or ord(ch) > 0x7E for ch in t), t
