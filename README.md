# NetTriage

Offline packet-capture diagnoser for small networks. NetTriage reads a `.pcap` or `.pcapng` file,
finds the faults and attacks in it, says which is which, how sure it is, and why, and points to the
exact packets behind each finding.

> Work in progress: built during the IIITDM Kancheepuram 24-hour Cybersecurity Hackathon
> (31 Oct 2026, 21:00 to 1 Nov 2026, 21:00 IST). The full README (features, setup, security, accuracy,
> libraries) is written at the end of the event.

## Quick start (development)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e "backend[dev]"
.venv/Scripts/python -m pytest backend/tests
```
