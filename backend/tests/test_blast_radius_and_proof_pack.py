"""Blast radius (what an interceptor could see) and Proof Packs (shareable, pseudonymized, tamper-evident)."""

from __future__ import annotations

import io
import ipaddress
import json
import re
import time
import zipfile
from functools import cache
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nettriage.config import Limits, ServerSettings
from nettriage.decode import decode
from nettriage.engine import analyze
from nettriage.evidence.proofpack import Pseudonymizer, build_proof_pack, verify_proof_pack
from nettriage.ingest.capture import IngestCounters, read_capture
from nettriage.main import create_app

SCENARIOS = Path(__file__).resolve().parents[2] / "samples" / "scenarios"
ATTACKER = "08:00:27:3e:5a:11"


@cache
def run(name: str):
    return analyze(SCENARIOS / name, name, Limits())


# --- blast radius ------------------------------------------------------------------------------------------

def test_blast_radius_names_victim_services_and_hijacked_names():
    report = run("mitm_dns_combo.pcap").report
    assert len(report.exposures) == 1
    e = report.exposures[0]
    assert e.attacker == ATTACKER
    assert e.victims == ["192.168.1.12"]
    assert e.hijacked_names == ["mail.example.org", "www.iiitdm.ac.in"]
    services = {(f.service, f.encrypted) for f in e.flows}
    assert ("HTTP", False) in services and ("HTTPS", True) in services and ("DNS", False) in services
    assert e.readable >= 1 and e.metadata_only >= 1
    assert all(f.victim == "192.168.1.12" for f in e.flows)
    # Connections are named with the DNS answers the victim got.
    assert any(f.name == "www.iiitdm.ac.in" and f.encrypted for f in e.flows)
    assert any("password" in s for s in e.fix_steps)
    assert e.relayed_packets == sum(f.packets for f in e.flows)


def test_unencrypted_connections_are_listed_first():
    flows = run("mitm_dns_combo.pcap").report.exposures[0].flows
    order = [f.encrypted for f in flows if f.service in ("HTTP", "HTTPS")]
    assert order == sorted(order)  # False (readable) before True (metadata only)


@pytest.mark.parametrize("name", ["clean_office.pcap", "vrrp_failover.pcap", "nic_swap.pcap", "port_scan_syn.pcap"])
def test_no_blast_radius_without_interception(name):
    assert run(name).report.exposures == []


def test_attack_findings_carry_attack_techniques():
    report = run("mitm_dns_combo.pcap").report
    ids = {f.kind: [t.id for t in f.techniques] for f in report.findings}
    assert ids["arp_spoofing"] == ["T1557.002"]
    assert ids["dns_spoofing"] == ["T1557"]
    assert all(t.url.startswith("https://attack.mitre.org/techniques/T") for f in report.findings for t in f.techniques)
    assert all(not f.techniques for f in report.ruled_out)


# --- pseudonyms ----------------------------------------------------------------------------------------------

def test_pseudonyms_preserve_prefixes_and_address_class():
    ps = Pseudonymizer(b"k" * 32)
    a, b, c = ps.ip("192.168.1.12"), ps.ip("192.168.1.13"), ps.ip("192.168.7.1")
    assert a != "192.168.1.12" and a.startswith("192.168.")
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]          # same /24 in, same /24 out
    assert a.rsplit(".", 2)[0] == c.rsplit(".", 2)[0]          # same /16 in, same /16 out
    for public in ("14.139.181.229", "140.82.112.3", "8.8.8.8"):
        assert ipaddress.ip_address(ps.ip(public)).is_global
    assert ps.ip("255.255.255.255") == "255.255.255.255" and ps.ip("224.0.0.251") == "224.0.0.251"
    assert ps.ip("192.168.1.12") == a                          # deterministic within one pack
    assert Pseudonymizer(b"x" * 32).ip("192.168.1.12") != a    # but not across packs
    assert ps.mac(ATTACKER).startswith("08:00:27:") and ps.mac(ATTACKER) != ATTACKER
    assert ps.mac("ff:ff:ff:ff:ff:ff") == "ff:ff:ff:ff:ff:ff"
    assert ps.mac("00:00:5e:00:01:0a") == "00:00:5e:00:01:0a"  # VRRP virtual MAC keeps its meaning


def test_addresses_in_prose_are_replaced_even_at_a_full_stop():
    ps = Pseudonymizer(b"k" * 32)
    out = ps.text(f"Don't sign in from 192.168.1.1, 192.168.1.12. MAC:{ATTACKER}: relaying.")
    assert "192.168.1.12" not in out and "192.168.1.1," not in out and ATTACKER not in out


# --- the pack ------------------------------------------------------------------------------------------------

def _pack(name="mitm_dns_combo.pcap"):
    result = run(name)
    return result, build_proof_pack(result.report, result.evidence)


@pytest.mark.parametrize("name", ["mitm_dns_combo.pcap", "rogue_dhcp.pcap", "dns_spoof_race.pcap"])
def test_proof_pack_leaks_no_real_address(name):
    result, pack = _pack(name)
    zf = zipfile.ZipFile(io.BytesIO(pack.data))
    text = zf.read("report.json").decode()
    real = {e.value for f in result.report.findings + result.report.ruled_out for e in f.entities
            if e.kind in ("ip", "mac")}
    for addr in real:
        if addr.startswith(("ff:", "255.", "224.", "0.0.0.")):
            continue
        assert not re.search(r"(?<![\w.:])" + re.escape(addr) + r"(?![\w:]|\.\d)", text), addr
    raw = b"".join(zf.read(n) for n in zf.namelist() if n.endswith(".pcap"))
    for addr in real:
        if ":" not in addr and not addr.startswith(("0.", "255.", "224.")):
            assert ipaddress.ip_address(addr).packed not in raw, addr
    doc = json.loads(text)
    assert doc["names"] == [] and doc["device_names"] == []
    assert doc["capture"]["file_name"] == "capture.pcap"
    assert doc["capture"]["sha256"] == result.report.capture.sha256


def test_proof_pack_evidence_still_decodes_without_payloads():
    _, pack = _pack()
    zf = zipfile.ZipFile(io.BytesIO(pack.data))
    pcaps = [n for n in zf.namelist() if n.startswith("evidence/")]
    assert pcaps
    for n in pcaps:
        limits = Limits()
        frames = list(read_capture(io.BytesIO(zf.read(n)), limits, IngestCounters(limits)))
        assert frames
        for raw in frames:
            p = decode(raw)
            assert p.arp or p.ip
            if p.tcp:
                assert len(raw.data) <= 14 + 60 + 60  # headers only
            assert raw.wire_len >= len(raw.data)


def test_proof_pack_verifies_and_reports_its_root():
    _, pack = _pack()
    v = verify_proof_pack(pack.data, pack.root)
    assert v.ok and v.root == pack.root and not v.problems
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(pack.data)).read("manifest.json"))
    assert manifest["root"] == pack.root and manifest["format"] == "nettriage-proof-pack/1"


def _rezip(pack: bytes, change) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(pack))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in src.namelist():
            data = change(name, src.read(name))
            if data is not None:
                out.writestr(name, data)
    return buf.getvalue()


def test_any_change_is_caught():
    _, pack = _pack()
    edited = _rezip(pack.data, lambda n, b: b.replace(b"critical", b"low     ") if n == "report.json" else b)
    assert "Changed since packing: report.json" in verify_proof_pack(edited, pack.root).problems
    removed = _rezip(pack.data, lambda n, b: None if n.startswith("evidence/") else b)
    assert any(p.startswith("Missing file") for p in verify_proof_pack(removed).problems)
    grown = io.BytesIO(pack.data)
    with zipfile.ZipFile(grown, "a") as zf:
        zf.writestr("extra.txt", b"hi")
    assert any(p.startswith("Not in the manifest") for p in verify_proof_pack(grown.getvalue()).problems)
    assert not verify_proof_pack(pack.data, "0" * 64).ok


def test_hostile_zips_are_refused():
    assert not verify_proof_pack(b"not a zip").ok
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../escape.txt", b"x")
    assert "unsafe path" in verify_proof_pack(buf.getvalue()).problems[0]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", b"\0" * 5_000_000)
    assert "zip bomb" in verify_proof_pack(buf.getvalue()).problems[0]


# --- API -----------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    with TestClient(create_app(Limits(), ServerSettings()), base_url="http://127.0.0.1") as c:
        yield c


def test_api_builds_downloads_and_verifies_a_pack(client):
    job_id = client.post("/api/samples/mitm_dns_combo.pcap").json()["id"]
    end = time.time() + 120
    while client.get(f"/api/analyses/{job_id}").json()["status"] in ("queued", "running") and time.time() < end:
        time.sleep(0.2)
    made = client.post(f"/api/analyses/{job_id}/proof-pack")
    assert made.status_code == 201
    root, token = made.json()["root"], made.json()["token"]
    dl = client.get(f"/api/analyses/{job_id}/proof-pack/{token}")
    assert dl.status_code == 200 and dl.headers["content-type"] == "application/zip"
    good = client.post("/api/proof-packs/verify", content=dl.content, headers={"x-expected-root": root}).json()
    assert good["ok"] and good["root"] == root
    bad = client.post("/api/proof-packs/verify", content=dl.content, headers={"x-expected-root": "0" * 64}).json()
    assert not bad["ok"]
    assert client.get(f"/api/analyses/{job_id}/proof-pack/{'0' * 32}").status_code == 404
    report = client.get(f"/api/analyses/{job_id}").json()["report"]
    assert report["exposures"][0]["attacker"] == ATTACKER
