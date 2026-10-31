"""Broken and hostile captures must never crash the reader or the decoders."""

from __future__ import annotations

import io
import struct

import pytest
from helpers import (
    TS0,
    build_pcap,
    pcap_header,
    pcapng_block,
    pcapng_epb,
    pcapng_idb,
    pcapng_shb,
    read_all,
)
from hypothesis import given, settings
from hypothesis import strategies as st
from nettriage.config import Limits
from nettriage.decode import decode
from nettriage.ingest.capture import CaptureFormatError, IngestCounters, RawPacket
from nettriage.ingest.stream import stream_packets
from nettriage.security.sanitize import csv_safe, display_safe, strip_ansi

ETH_IP = bytes.fromhex("020000000002" "020000000001" "0800")


def ipv4(proto: int, payload: bytes, ihl: int = 5, total: int | None = None) -> bytes:
    total = 20 + len(payload) if total is None else total
    return struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 1, 0, 64, proto, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def frame_udp(sport: int, dport: int, payload: bytes) -> bytes:
    return ETH_IP + ipv4(17, udp(sport, dport, payload))


# --- file-level problems -------------------------------------------------

def test_disguised_executable_is_rejected_before_parsing():
    with pytest.raises(CaptureFormatError, match="Windows executable"):
        read_all(b"MZ\x90\x00" + b"\0" * 100)


def test_empty_file_is_rejected():
    with pytest.raises(CaptureFormatError):
        read_all(b"")


def test_header_only_file_has_no_packets():
    packets, counters = read_all(pcap_header())
    assert packets == [] and not counters.stopped_early


def test_huge_caplen_stops_without_allocating():
    data = pcap_header() + struct.pack("<IIII", TS0, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"x" * 64
    packets, counters = read_all(data)
    assert packets == []
    assert counters.stopped_early and "limit" in counters.stop_reason


def test_file_cut_inside_packet_keeps_earlier_packets():
    good = build_pcap([frame_udp(1000, 2000, b"hello")] * 3)
    packets, counters = read_all(good[:-5])
    assert [p.frame for p in packets] == [1, 2]
    assert counters.stopped_early
    assert counters.skip_reasons["cut off by end of file"] == 1


def test_file_cut_inside_record_header():
    good = build_pcap([frame_udp(1000, 2000, b"x")] * 2)
    cut = good[: 24 + 16 + len(frame_udp(1000, 2000, b"x")) + 7]
    packets, counters = read_all(cut)
    assert len(packets) == 1 and counters.stopped_early


def test_packet_limit_is_enforced():
    data = build_pcap([frame_udp(1, 2, b"")] * 10)
    packets, counters = read_all(data, Limits(max_packets=4))
    assert len(packets) == 4 and counters.stopped_early


@pytest.mark.parametrize("total", [8, 13, 30 * 1024 * 1024])
def test_pcapng_invalid_block_length_stops(total):
    bad = struct.pack("<II", 6, total) + b"\0" * 32
    packets, counters = read_all(pcapng_shb() + pcapng_idb() + bad)
    assert packets == [] and counters.stopped_early and "invalid length" in counters.stop_reason


def test_pcapng_trailer_mismatch_stops():
    good = pcapng_epb(frame_udp(1, 2, b"a"), TS0 * 10**6)
    bad = pcapng_block(6, good[8:-4], trailer=999)
    packets, counters = read_all(pcapng_shb() + pcapng_idb() + good + bad)
    assert len(packets) == 1 and "mismatched" in counters.stop_reason


def test_pcapng_unknown_interface_is_skipped_and_numbering_continues():
    data = (pcapng_shb() + pcapng_idb()
            + pcapng_epb(frame_udp(1, 2, b""), TS0 * 10**6, if_id=7)
            + pcapng_epb(frame_udp(1, 2, b""), TS0 * 10**6))
    packets, counters = read_all(data)
    assert [p.frame for p in packets] == [2]
    assert counters.skip_reasons["packet refers to an undefined interface"] == 1


def test_pcapng_caplen_past_block_is_skipped():
    data = pcapng_shb() + pcapng_idb() + pcapng_epb(frame_udp(1, 2, b""), 0, caplen=5000)
    packets, counters = read_all(data)
    assert packets == [] and counters.skip_reasons["packet length runs past the end of its block"] == 1


def test_pcapng_cut_inside_section_header_is_rejected():
    with pytest.raises(CaptureFormatError):
        read_all(pcapng_shb()[:6])


# --- packet-level problems -----------------------------------------------

def test_ipv4_header_length_below_minimum():
    packets, counters = read_all(build_pcap([ETH_IP + ipv4(17, b"\0" * 8, ihl=3)]))
    assert packets[0].error == "malformed IPv4 header"
    assert counters.skip_reasons["malformed IPv4 header"] == 1


def test_tcp_data_offset_below_minimum():
    tcp = struct.pack("!HHIIHHHH", 1, 2, 0, 0, 0x2002, 0, 0, 0)  # data offset 2
    packets, _ = read_all(build_pcap([ETH_IP + ipv4(6, tcp)]))
    assert packets[0].error == "malformed TCP header" and packets[0].ip is not None


def test_dns_self_pointer_loop():
    header = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
    question = b"\xc0\x0c" + b"\x00\x01\x00\x01"  # name points at itself
    packets, _ = read_all(build_pcap([frame_udp(53, 5000, header + question)]))
    assert packets[0].error == "malformed DNS message"
    assert "loop" in packets[0].error_detail


def test_dns_two_pointers_pointing_at_each_other():
    header = struct.pack("!HHHHHH", 1, 0x8180, 2, 0, 0, 0)
    q1 = b"\xc0\x12" + b"\x00\x01\x00\x01"   # offset 12 -> 18
    q2 = b"\xc0\x0c" + b"\x00\x01\x00\x01"   # offset 18 -> 12
    packets, _ = read_all(build_pcap([frame_udp(53, 5000, header + q1 + q2)]))
    assert packets[0].error == "malformed DNS message"


def test_dns_huge_record_counts_are_not_trusted():
    header = struct.pack("!HHHHHH", 1, 0x8180, 65535, 65535, 65535, 65535)
    packets, _ = read_all(build_pcap([frame_udp(53, 5000, header)]))
    assert packets[0].error == "malformed DNS message"


def test_dns_name_with_control_bytes_is_escaped():
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    label = b"<script>\x1b[31m\x00"
    question = bytes([len(label)]) + label + b"\x03com\x00" + b"\x00\x01\x00\x01"
    packets, _ = read_all(build_pcap([frame_udp(5000, 53, header + question)]))
    name = packets[0].dns.qname
    assert name == "<script>\\027[31m\\000.com"
    assert "\x1b" not in name and "\x00" not in name


def test_dhcp_hostname_with_script_and_escape_codes():
    bootp = bytearray(236)
    bootp[0], bootp[1], bootp[2] = 1, 1, 6
    hostname = b"<img src=x onerror=alert(1)>\x1b]0;pwned\x07"
    opts = b"\x63\x82\x53\x63" + b"\x35\x01\x01" + bytes([12, len(hostname)]) + hostname + b"\xff"
    packets, _ = read_all(build_pcap([frame_udp(68, 67, bytes(bootp) + opts)]))
    h = packets[0].dhcp.hostname
    assert h.startswith("<img src=x onerror=alert(1)>")
    assert "\x1b" not in h and "\x07" not in h


def test_dhcp_option_length_past_end():
    bootp = bytes(236) + b"\x63\x82\x53\x63" + b"\x0c\xff" + b"short"
    packets, _ = read_all(build_pcap([frame_udp(68, 67, bootp)]))
    assert packets[0].error == "malformed DHCP message"


def test_unsupported_link_type_is_counted():
    packets, counters = read_all(build_pcap([b"\0" * 40], linktype=127))
    assert packets[0].error == "unsupported link type 127"
    assert counters.skipped == 1


# --- sanitiser -----------------------------------------------------------

def test_display_safe_neutralises_bidi_and_controls():
    s = display_safe("evil‮gnp.exe\x1b[2J​")
    assert "‮" not in s and "\x1b" not in s and "​" not in s
    assert "\\u202e" in s


def test_display_safe_caps_length():
    assert len(display_safe("a" * 5000, max_len=100)) == 103


def test_csv_and_ansi_helpers():
    assert csv_safe("=HYPERLINK(\"http://x\")").startswith("'")
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


# --- fuzzing -------------------------------------------------------------

LINKTYPES = [0, 1, 12, 101, 108, 113, 228, 229, 276, 9999]


@settings(max_examples=3000, deadline=None)
@given(data=st.binary(max_size=600), linktype=st.sampled_from(LINKTYPES))
def test_fuzz_decode_never_raises(data, linktype):
    decode(RawPacket(frame=1, ts_ns=0, linktype=linktype, data=data, wire_len=len(data), offset=0))


@settings(max_examples=3000, deadline=None)
@given(prefix=st.sampled_from([ETH_IP, ETH_IP + ipv4(17, b"")[:20], ETH_IP + ipv4(6, b"")[:20]]),
       tail=st.binary(max_size=400), ports=st.sampled_from([(53, 5000), (5353, 5353), (68, 67), (1, 2)]))
def test_fuzz_structured_payloads(prefix, tail, ports):
    data = frame_udp(ports[0], ports[1], tail) if len(prefix) == 14 else prefix + tail
    decode(RawPacket(frame=1, ts_ns=0, linktype=1, data=data, wire_len=len(data), offset=0))


SEED = build_pcap([frame_udp(53, 5000, struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
                             + b"\x01a\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                             + bytes([1, 2, 3, 4]))] * 4)


@settings(max_examples=2000, deadline=None)
@given(flips=st.lists(st.tuples(st.integers(0, len(SEED) - 1), st.integers(0, 255)), max_size=12),
       cut=st.integers(0, len(SEED)))
def test_fuzz_mutated_capture_file(flips, cut):
    data = bytearray(SEED)
    for pos, value in flips:
        data[pos] = value
    data = bytes(data[:cut])
    limits = Limits()
    counters = IngestCounters(limits=limits)
    try:
        for _ in stream_packets(io.BytesIO(data), limits, counters):
            pass
    except CaptureFormatError:
        pass
