# NetTriage

**Is your network broken, or is someone breaking it?**

NetTriage reads a packet capture (`.pcap` / `.pcapng`), finds the faults and attacks inside it, and tells them
apart. For each one it shows a confidence score, the reasoning, a plain-language fix and the exact packets behind
it. It runs entirely on your computer, and every byte of the capture is parsed by our own code.

Built solo for the IIITDM Kancheepuram 24-hour Cybersecurity Hackathon, Network Track (31 Oct to 1 Nov 2026).

**Demo video:** _link added at submission_

---

## The problem

- When "the internet is slow" or "nothing loads", the only real evidence is a packet capture. Reading one takes
  an expert.
- A broken network and an attacked network look alike from the outside: timeouts, failures, strange addresses.
  Mistaking an attack for a fault leaves the attacker in place. Mistaking a fault for an attack wastes a day.
- Existing tools either show raw packets (Wireshark) or raise generic alerts with no explanation and many
  false alarms.

## What NetTriage does

| | |
|---|---|
| **Fault vs. attack** | Every issue is scored against competing explanations (attack, fault, normal behaviour), and the UI shows *why not* the runners-up. |
| **Confidence you can trust** | Probabilities come from evidence weights. Too little evidence gives "needs review" (capped at 50%), never a confident guess. |
| **Few false alarms** | Benign look-alikes (router failover, a swapped network card, ad blockers, busy PCs) are explained in a "checked and ruled out" list instead of raising alarms. |
| **Proof** | Wireshark-matching frame numbers, a ready-made display filter, and a downloadable `evidence.pcap` for every finding. |
| **Plain language** | A one-paragraph explanation, the likely cause, and a fix checklist, plus a technical view. |
| **Connected incidents** | Findings with one root cause are linked: an ARP spoofer that also forges DNS is one incident, with one device to unplug. |
| **What the attacker could see** | When an interception is proven, every conversation that passed through the attacker is listed with what it exposed: plain HTTP or FTP readable in full, HTTPS showing only the server, DNS names visible and hijacked. The fix steps name the passwords to change. Nothing is read out of the payloads. |
| **Proof Pack** | One click exports evidence you can send to an ISP or IT team without exposing your network: every address is replaced with a keyed, prefix-preserving pseudonym, packet contents are removed, and a SHA-256 root hash shows any change. `nettriage verify` or the dashboard checks a pack offline. |
| **ATT&CK labels** | Attack findings carry their MITRE ATT&CK technique, for example T1557.002 ARP Cache Poisoning. |
| **Honest about the capture** | One-directional or lossy captures are reported as a capture problem, not blamed on the network. |
| **Safe with hostile files** | Built to be handed broken and booby-trapped captures. See [Security](#security). |

There is a web UI (landing page, dashboard with a sample library, upload, live progress, analysis, Proof Pack
export and check) and a CLI that prints the same findings.

## Quick start

You need **Python 3.11 or newer**. Node is not needed: the built web UI is committed.

```bash
git clone https://github.com/tarun-227/nettriage.git
cd nettriage
python -m venv .venv
```

Activate the environment. On Windows:

```bash
.venv\Scripts\activate
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

Install and start:

```bash
pip install -r backend/requirements.txt
cd backend
python -m nettriage serve
```

Open **http://127.0.0.1:8765**, then **Open dashboard**: drop a capture, or run one from the sample library. Press **U** to upload and **/** to search.

From the command line (still inside `backend/`):

```bash
python -m nettriage analyze ../samples/scenarios/mitm_dns_combo.pcap
```

Add `--all` to also list what was ruled out, `--json` for the full report, or `--evidence-dir out/` to write one
evidence capture per finding.

Make a Proof Pack and check one:

```bash
python -m nettriage proof ../samples/scenarios/mitm_dns_combo.pcap
python -m nettriage verify ../samples/scenarios/mitm_dns_combo.proof.zip --root <root hash it printed>
```

No capture of your own? `samples/scenarios/` has 35 labelled ones and `samples/malicious/` has 8 hostile files.
They all appear as one-click samples in the UI.

## How it decides

**The principle: faults are consistent, attacks have to lie.** A broken network still tells the truth: every layer
agrees, something just doesn't work. An attacker has to deceive someone, and that leaves contradictions between
layers. A DHCP server naming *itself* the gateway, or a DNS answer arriving faster than the server could have sent
it, are examples.

1. **One streaming pass.** Our own decoders read every packet through one bounds-checked reader. Each detector
   keeps bounded state and collects *observations*, each with the frames that support it.
2. **Differential diagnosis.** Each detector has a rule table of `(observation, hypothesis, weight, reason)`.
   Score = prior + sum of weights, then softmax gives probabilities. The same rows produce the "why" text, so the
   explanation can never drift from the score.
3. **Sufficiency gates.** Too few packets, attempts or seconds means "needs review", capped at 50%.
4. **Alert threshold.** An attack or fault at 60% or more becomes an alert. A benign winner goes to "checked and
   ruled out".
5. **Correlation.** Attacks by the same device, and an outage with the DNS failures it causes, become one
   incident with a root finding to fix first.
6. **Blast radius.** Every packet the ARP detector proves was relayed (same IP ID, TTL lowered by one) also
   records its conversation. Conversations are named with the DNS answers the victim received and classed by
   service: encrypted (server visible, contents private), plaintext with logins (everything readable) or DNS
   (names visible, answers forgeable).

The detectors adapt published methods. Each one is described in [docs/research.md](docs/research.md), with
citations and what we changed:

| Detector | Based on |
|---|---|
| Port scans | Threshold Random Walk sequential test (Jung et al., IEEE S&P 2004) |
| DNS spoofing | Hold-On's per-resolver TTL, timing and MAC baseline (Duan et al., 2012) |
| TCP loss and delay | Out-of-sequence segment classification (Jaiswal et al.; Rewaskar et al.) and Sherlock-style fault localisation |
| ARP spoofing | Cross-layer ARP checks, plus our own **forwarding proof**: the same packet seen going to the attacker and coming back out with TTL - 1 |
| MTU black holes | Path MTU Discovery failure signatures (Luckie & Stasiewicz, IMC 2010) |
| Incidents | Attribute- and time-based alert correlation (Valeur et al., IEEE TDSC 2004) |
| Blast radius | Our relay proof, scoped the way MITRE ATT&CK T1557 (Adversary-in-the-Middle) says to: by what crossed the intercepted path |
| Proof Pack pseudonyms | Crypto-PAn prefix-preserving anonymisation (Xu, Fan, Ammar and Moon, 2002), as in the IETF ipcrypt draft's "pfx" mode, built on HMAC-SHA256 |

## What it detects

| Area | Faults | Attacks | Look-alikes it rules out |
|---|---|---|---|
| **ARP** | Duplicate IP address | ARP spoofing / man-in-the-middle, with relaying proof | Router failover (VRRP/HSRP/CARP), a replaced network card, boot-time gratuitous ARP |
| **TCP** | Packet loss (located to a server, one PC's link or the uplink), refused connections, unreachable hosts, internet outage, high latency | none | Keep-alives, reordering, browser resets, packets missing from the capture |
| **Port scans** | none | SYN, connect, FIN/NULL/Xmas and slow scans; vertical and horizontal | Busy clients, retries to one dead service, one-directional captures |
| **DNS** | Server failing or timing out, slow resolver | Forged answers (race), cache-poisoning floods | Ad blockers (Pi-hole), CDN rotation, browser random-name probes |
| **DHCP** | No offer, misplugged home router | Rogue DHCP server hijacking the gateway or DNS | Failover pairs |
| **MTU** | Path MTU black hole, devices ignoring "packet too big" | none | Path MTU Discovery working normally |

## Accuracy

Measured with [eval/run_eval.py](eval/run_eval.py). The weights were tuned on dev seeds 1–3 only. The holdout seeds
101–105 were generated afterwards and scored once. Full tables, a confusion matrix and calibration are in
[eval/results.md](eval/results.md).

| Set | Captures | Problems found with the right verdict | False alarms | Expected incident links | Brier score |
|---|---:|---:|---:|---:|---:|
| **Holdout** (seeds 101–105) | 175 | **135 / 135** | **0** (55 look-alike captures) | 10 / 10 | 0.001 |
| Dev (seeds 1–3) | 105 | 81 / 81 | 0 (33 look-alike captures) | 6 / 6 | 0.001 |
| Curated samples | 35 | 27 / 27 | 0 (11 look-alike captures) | 2 / 2 | 0.001 |

Every one-directional capture was flagged as a capture problem (5 / 5 in the holdout). No finding was left as
"needs review".

**How to read these numbers.** Every capture comes from our own seeded office simulator
(`samples/generate/`), and the same person wrote the simulator and the detectors. The scores show that each
detector does what it was designed to do, stays stable across random seeds and noise, and doesn't fire on the
look-alikes we modelled. They are **not** a measurement of accuracy on real networks. Captures of real attack
tools in an isolated lab are the next test.

## Security

A capture is untrusted input from the network, possibly crafted by an attacker. NetTriage treats it that way.

| Threat | Protection | Proof |
|---|---|---|
| Huge upload filling the disk | Streamed upload with a hard byte cap (500 MB by default) and a 413 response; one analysis at a time | `test_oversized_upload_is_rejected` |
| A disguised file | Extension allow-list, then a **magic-byte check** before any parsing; says what the file really is | `samples/malicious/not_a_pcap.exe.pcap`, `test_disguised_executable_is_rejected` |
| Length fields that lie | Every read goes through one bounds-checked `ByteReader`; record length is capped at min(snaplen, 256 KiB) and pcapng blocks at 16 MiB, multiple of 4, trailer must match; stops cleanly with partial results | `huge_caplen.pcap`, `bad_block_len.pcapng`, `truncated.pcap`, `empty.pcap` |
| Malformed packets | Each packet is decoded in its own guard: a broken one is skipped and counted with its frame number and reason | `corrupt_packets.pcap`, mutation fuzzing in `test_hostile_input.py` and `test_engine_hostile.py` |
| Infinite loops | DNS compression pointers must point strictly backwards (max 32 jumps); name and label length caps; IPv6 extension-header and VLAN tag caps | `dns_pointer_loop.pcap` |
| Memory exhaustion | Bounded flow, DNS and host tables; packet cap; per-analysis timeout in a separate process that is killed if it overruns | `make_malicious.py --large` writes a 100,000-SYN flood |
| XSS or terminal injection from packet text | Hostnames are escaped to printable ASCII at decode time; bidi overrides and control characters neutralised; React renders text only (no raw HTML anywhere); ANSI stripped in CLI output | `xss_payloads.pcap`, `test_hostile_strings_never_carry_control_characters` |
| Path traversal | The uploaded file name is only a label; files on disk get random UUID names in a private temp folder | `test_path_in_filename_is_only_a_label`, `test_path_traversal_never_serves_other_files` |
| Data left behind | The upload is deleted in a `finally` block as soon as parsing ends; stale temp files are swept at startup; reports live in memory for 60 minutes or until **Delete** | `test_full_round_trip_and_upload_is_deleted` |
| Network exposure | Listens on 127.0.0.1 only; Host-header allow-list against DNS rebinding; strict Content-Security-Policy, `nosniff`, frame denial, no referrer; no CORS; no API docs endpoint; random job IDs | `test_health_and_security_headers`, `test_foreign_host_header_is_refused` |
| Phoning home | No outbound connections, no CDN fonts or scripts, no telemetry | `test_analysis_opens_no_network_connections` fails if any socket opens |
| Secrets | None needed. Every setting is optional (see [.env.example](.env.example)) | CI runs gitleaks |
| Supply chain | Few runtime dependencies, pinned in [backend/requirements.txt](backend/requirements.txt); frontend versions pinned exactly | CI runs bandit, pip-audit and gitleaks |
| Shared evidence exposing the network | Proof Pack: every IP and MAC gets a keyed, prefix-preserving pseudonym (random key, discarded; private stays private, public stays public); packets cut after the transport header; transport checksums zeroed, since they would let someone test guesses of the real addresses; file name, lookup history and hostnames left out | `test_proof_pack_leaks_no_real_address` checks the report text and the packet bytes |
| Tampered evidence | SHA-256 of every file in a manifest and one root hash over them; the root travels separately and `nettriage verify` or the dashboard check recomputes it | `test_any_change_is_caught` |
| A hostile zip handed to the checker | Entry count, total size, path and compression-ratio limits enforced before anything is read | `test_hostile_zips_are_refused` |

The **Integrity** tab of every report shows the SHA-256, the checks that ran, the limits in force, every skipped
packet with its reason, and confirmation that the upload was deleted. The hostile files are described in
[samples/malicious/README.md](samples/malicious/README.md) and appear in the UI under *Hostile files*.

## Own detection logic

- Packet reading, decoding (Ethernet, VLAN, Linux cooked, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, DNS, DHCP),
  detection, scoring and explanations are all our own code in `backend/nettriage/`.
- **tshark, Wireshark, Zeek and Suricata are never run.** A test fails the build if the app package imports
  `subprocess` or a network client (`test_no_external_tools_or_network_clients_in_the_app`). Wireshark filters
  are offered only so you can check our findings yourself.
- Scapy is used only in development, to generate the sample captures and to cross-check our decoders
  (`test_decode_vs_scapy.py`). The app never imports it.

## Libraries

**Runtime (Python).** None of these parse packets.

| Library | Purpose | License |
|---|---|---|
| [FastAPI](https://fastapi.tiangolo.com/) | Local web API | MIT |
| [Starlette](https://www.starlette.io/) | ASGI toolkit under FastAPI; Host-header middleware | BSD-3-Clause |
| [Uvicorn](https://www.uvicorn.org/) | Local web server | BSD-3-Clause |
| [Pydantic](https://docs.pydantic.dev/) | Report schema and validation | MIT |
| annotated-doc, annotated-types, anyio, click, h11, idna, opentelemetry-api, typing-extensions, typing-inspection | Installed as dependencies of the above | MIT / BSD-3-Clause / Apache-2.0 / PSF-2.0 |

**Web UI (built once; the output is committed).** No chart, icon or font libraries: charts, icons and the 3D
scenes are hand-written SVG and CSS.

| Library | Purpose | License |
|---|---|---|
| [React](https://react.dev/) 18.3.1 | UI | MIT |
| [TypeScript](https://www.typescriptlang.org/) 5.6.3 | Type checking | Apache-2.0 |
| [Vite](https://vitejs.dev/) 5.4.11, @vitejs/plugin-react 4.3.4 | Build | MIT |
| [Tailwind CSS](https://tailwindcss.com/) 3.4.17, PostCSS, Autoprefixer | Styling | MIT |

**Development only.**

| Tool | Purpose | License |
|---|---|---|
| [pytest](https://pytest.org/) | Tests | MIT |
| [Hypothesis](https://hypothesis.works/) | Property-based fuzzing of the parser | MPL-2.0 |
| [Scapy](https://scapy.net/) | Generating sample captures; cross-checking our decoders | GPL-2.0 |
| [HTTPX](https://www.python-httpx.org/) | API tests | BSD-3-Clause |
| [Ruff](https://docs.astral.sh/ruff/) | Linting | MIT |
| [Bandit](https://bandit.readthedocs.io/), [pip-audit](https://github.com/pypa/pip-audit), [gitleaks](https://github.com/gitleaks/gitleaks) | Security checks in CI | Apache-2.0 / Apache-2.0 / MIT |

No external APIs are used.

## Project layout

```
backend/nettriage/
  ingest/      file validation, bounds-checked reader, streaming pcap and pcapng readers
  decode/      protocol decoders and text escaping
  detectors/   arp, portscan, tcp, dns, dhcp, mtu
  reasoning/   differential diagnosis, finding builder, incident correlation, blast radius, ATT&CK labels
  evidence/    key-packet descriptions, evidence.pcap writer, Proof Pack (pseudonyms, manifest, verifier)
  security/    display-safe text, HTTP security headers
  engine.py    one streaming pass over the capture
  api.py  jobs.py  main.py  cli.py
  static/      built web UI
backend/tests/ decoders vs. Scapy, hostile input and fuzzing, detectors, accuracy regression, API
frontend/      React + TypeScript source of the web UI
samples/       scenarios/ (35 labelled), malicious/ (8 hostile), generate/ (simulator)
eval/          run_eval.py, results.md
docs/          research.md, demo-script.md
```

## Configuration

Nothing needs configuring. To change a limit, set an environment variable (see [.env.example](.env.example)):
`NETTRIAGE_MAX_UPLOAD_MB`, `NETTRIAGE_MAX_PACKETS`, `NETTRIAGE_MAX_ANALYSIS_SECONDS`, `NETTRIAGE_RESULT_TTL_MINUTES`,
`NETTRIAGE_PORT`.

## Development

```bash
pip install -r backend/requirements-dev.txt
pip install --no-deps -e backend
python -m pytest backend/tests
```

Regenerate the samples and measure accuracy (from the repository root):

```bash
python samples/generate/scenarios.py
python samples/generate/scenarios.py --split holdout
python eval/run_eval.py samples/scenarios eval/generated/holdout
```

Rebuild the web UI (needs Node 18 or newer):

```bash
cd frontend
npm ci
npm run build
```

## Limitations

- Accuracy is measured on simulated captures only (see [Accuracy](#accuracy)). No real-tool lab captures yet.
- IPv4 is covered most deeply. ARP and DHCP checks have no IPv6 counterparts yet (NDP spoofing, DHCPv6).
- Supported link types: Ethernet, Linux cooked (SLL, SLL2), raw IP and BSD loopback. Raw 802.11 (radiotap)
  captures are counted as unsupported, not analysed.
- Pure Python: about 20,000 packets per second on a laptop (roughly a minute per million packets), one analysis
  at a time. A capture of several million packets can hit the 5-minute limit; raise
  `NETTRIAGE_MAX_ANALYSIS_SECONDS` for those.

## Responsible use

Only capture and analyse networks you own or have permission to monitor. Captures can contain private
information, which is why NetTriage never sends them anywhere. All sample captures in this repository are
synthetic; none were recorded on a real network.
