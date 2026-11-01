"""The local web API: input validation, limits, cleanup and security headers."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nettriage.config import Limits, ServerSettings
from nettriage.main import create_app

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "samples" / "scenarios" / "port_scan_syn.pcap"
EXE = ROOT / "samples" / "malicious" / "not_a_pcap.exe.pcap"


@pytest.fixture(scope="module")
def client():
    app = create_app(Limits(max_upload_bytes=5 * 1024 * 1024), ServerSettings())
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c


def wait_done(client: TestClient, job_id: str, timeout: float = 120) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        data = client.get(f"/api/analyses/{job_id}").json()
        if data["status"] not in ("queued", "running"):
            return data
        time.sleep(0.3)
    raise AssertionError("analysis did not finish")


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_foreign_host_header_is_refused(client):
    # A DNS-rebinding page would arrive with its own host name.
    r = client.get("/api/health", headers={"host": "evil.example"})
    assert r.status_code == 400


def test_disguised_executable_is_rejected(client):
    r = client.post("/api/analyses", content=EXE.read_bytes(), headers={"x-filename": "invoice.pcap"})
    assert r.status_code == 415
    assert "Windows executable" in r.json()["detail"]


def test_wrong_extension_is_rejected(client):
    r = client.post("/api/analyses", content=SAMPLE.read_bytes(), headers={"x-filename": "notes.txt"})
    assert r.status_code == 415


def test_oversized_upload_is_rejected(client):
    r = client.post("/api/analyses", content=b"\xd4\xc3\xb2\xa1" + bytes(6 * 1024 * 1024),
                    headers={"x-filename": "big.pcap"})
    assert r.status_code == 413


def test_path_in_filename_is_only_a_label(client):
    r = client.post("/api/analyses", content=SAMPLE.read_bytes(),
                    headers={"x-filename": "..\\..\\windows\\system32\\evil.pcap"})
    assert r.status_code == 202
    data = wait_done(client, r.json()["id"])
    assert data["file_name"] == "evil.pcap"


def test_full_round_trip_and_upload_is_deleted(client):
    r = client.post("/api/analyses", content=SAMPLE.read_bytes(), headers={"x-filename": "scan.pcap"})
    assert r.status_code == 202
    job_id = r.json()["id"]
    data = wait_done(client, job_id)
    assert data["status"] == "done"
    assert data["upload_deleted_at"] is not None
    assert not any(client.app.state.jobs.upload_dir.iterdir()), "upload folder must be empty after analysis"
    kinds = {f["kind"] for f in data["report"]["findings"]}
    assert "port_scan" in kinds
    finding = data["report"]["findings"][0]
    ev = client.get(f"/api/analyses/{job_id}/evidence/{finding['id']}")
    assert ev.status_code == 200 and ev.content[:4] == b"\x4d\x3c\xb2\xa1"
    assert client.get(f"/api/analyses/{job_id}/report").status_code == 200
    assert client.delete(f"/api/analyses/{job_id}").status_code == 204
    assert client.get(f"/api/analyses/{job_id}").status_code == 404


def test_upload_survives_its_temp_folder_being_swept(client):
    # A second `nettriage serve` sweeps idle upload folders at startup, including this instance's.
    upload_dir = client.app.state.jobs.upload_dir
    upload_dir.rmdir()
    r = client.post("/api/analyses", content=SAMPLE.read_bytes(), headers={"x-filename": "after_sweep.pcap"})
    assert r.status_code == 202
    assert wait_done(client, r.json()["id"])["status"] == "done"


def test_malformed_ids_are_rejected(client):
    assert client.get("/api/analyses/not-an-id").status_code == 400
    assert client.get("/api/analyses/" + "0" * 32).status_code == 404
    assert client.get("/api/analyses/" + "0" * 32 + "/evidence/../../x").status_code in (400, 404)


@pytest.mark.parametrize("path", [
    "/api/analyses/../../etc/passwd",
    "/assets/../../nettriage/config.py",
    "/%2e%2e/%2e%2e/nettriage/config.py",
    "/..%2f..%2fnettriage%2fconfig.py",
    "/static/../config.py",
])
def test_path_traversal_never_serves_other_files(client, path):
    r = client.get(path)
    assert r.status_code in (200, 400, 404)
    assert "load_limits" not in r.text and "root:" not in r.text
    if r.status_code == 200:
        assert '<div id="root">' in r.text  # the app shell, nothing else


def test_samples_listing_and_hostile_sample(client):
    names = {s["name"] for s in client.get("/api/samples").json()}
    assert "arp_spoof_mitm.pcap" in names and "not_a_pcap.exe.pcap" in names
    assert client.post("/api/samples/not_a_pcap.exe.pcap").status_code == 415
    assert client.post("/api/samples/no_such_file.pcap").status_code == 404
    r = client.post("/api/samples/dns_spoof_race.pcap")
    data = wait_done(client, r.json()["id"])
    assert any(f["kind"] == "dns_spoofing" for f in data["report"]["findings"])
    assert (ROOT / "samples" / "scenarios" / "dns_spoof_race.pcap").exists(), "bundled samples are never deleted"


def test_deployment_domain_and_port_come_from_the_platform(monkeypatch):
    from nettriage.config import LOCAL_HOSTS, load_server_settings

    monkeypatch.setenv("PORT", "9123")
    monkeypatch.setenv("RAILWAY_PUBLIC_DOMAIN", "nettriage-demo.up.railway.app")
    monkeypatch.delenv("NETTRIAGE_PORT", raising=False)
    s = load_server_settings()
    assert s.port == 9123
    assert "nettriage-demo.up.railway.app" in s.allowed_hosts and set(LOCAL_HOSTS) <= set(s.allowed_hosts)
    app = create_app(Limits(), s)
    with TestClient(app, base_url="https://nettriage-demo.up.railway.app") as c:
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/health", headers={"host": "evil.example"}).status_code == 400


def test_local_defaults_are_unchanged(monkeypatch):
    from nettriage.config import LOCAL_HOSTS, load_server_settings

    for name in ("PORT", "NETTRIAGE_PORT", "RAILWAY_PUBLIC_DOMAIN", "NETTRIAGE_ALLOWED_HOSTS", "NETTRIAGE_HOST",
                 "RAILWAY_ENVIRONMENT", "RAILWAY_ENVIRONMENT_NAME"):
        monkeypatch.delenv(name, raising=False)
    s = load_server_settings()
    assert (s.host, s.port, s.allowed_hosts) == ("127.0.0.1", 8765, LOCAL_HOSTS)


def test_railway_ignores_copied_local_host_and_port(monkeypatch):
    from nettriage.config import load_server_settings

    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.setenv("PORT", "8080")
    monkeypatch.setenv("NETTRIAGE_HOST", "127.0.0.1")
    monkeypatch.setenv("NETTRIAGE_PORT", "8765")
    s = load_server_settings()
    assert (s.host, s.port) == ("0.0.0.0", 8080)  # noqa: S104
    with TestClient(create_app(Limits(), s), base_url="http://healthcheck.railway.app") as c:
        assert c.get("/api/health").status_code == 200
