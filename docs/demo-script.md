# Demo video script (about 4½ minutes)

Every number on screen comes from the real app and the bundled samples. Nothing is staged.

## Before recording

- Restart the server so it runs the latest code: `cd backend`, then `python -m nettriage serve`.
  Open http://127.0.0.1:8765 in a fresh window, so the dashboard's recent list starts empty.
- Turn Wi-Fi off, and keep the network icon in shot for the first minute.
- Make a tampered copy of a Proof Pack for the integrity moment:

  ```bash
  python -m nettriage proof ../samples/scenarios/mitm_dns_combo.pcap --out good.proof.zip
  python -c "b=bytearray(open('good.proof.zip','rb').read()); b[-400]^=0xFF; open('tampered.proof.zip','wb').write(b)"
  ```

  Note the root hash the first command prints.

## Shots

| Time | Screen | Say (short) |
|---|---|---|
| 0:00–0:25 | Landing page. Scroll slowly through the seven chapters: network, fault vs attack, the impostor (frame 1115's bytes, the lie in red), the evidence bars, the ATTACK stamp. | "A broken network and an attacked one look the same from outside. This is a real capture of an attack. Watch NetTriage catch the lie." |
| 0:25–0:35 | Wi-Fi icon off. Click **Open dashboard**. | "It runs entirely on this laptop. Nothing leaves it." |
| 0:35–1:05 | Dashboard, Library, **Man-in-the-middle with forged DNS**. Progress screen ticks through its checks. Verdict: **2 attacks found**. | "One click. In about a second: two attacks, 100% sure, and one sentence on what's happening." |
| 1:05–1:35 | **What to do** checklist. Then the two finding cards: open **Why we think so** on the first (260 packets relayed with TTL − 1; ruled out: router failover, duplicate IP, swapped card). Point at the ATT&CK chip. | "It doesn't just flag. It weighs every explanation and shows why the others lose. The relayed packets are proof of interception, not a guess." |
| 1:35–2:15 | Scroll to **What the attacker could see**: 3 read in full, 5 contents private, 2 names hijacked. Rows: github.com over HTTP "Fully readable", www.iiitdm.ac.in over HTTPS "Contents private". The steps below. | "And it tells you the damage: for 29 seconds this device could read three plain-HTTP sessions in full, saw only the server for the encrypted ones, and redirected two names. So you know exactly which passwords to change. It never reads the contents itself." |
| 2:15–2:55 | **Export → Proof Pack**. Show the root hash and download. Open the zip: report.json with pseudonymized addresses (192.168.x.x stays private, but not the real one). | "To get help from your ISP you need to share evidence, but not your network. A Proof Pack replaces every address, removes packet contents, and gives a root hash to send separately." |
| 2:55–3:20 | Dashboard, **Check a Proof Pack**. Drop good.proof.zip and paste the root: **VERIFIED**. Drop tampered.proof.zip: **NOT VERIFIED**. | "Change one byte and the check fails." |
| 3:20–3:45 | Library: run **DNS server not answering** (fault), then **Router failover (VRRP)** (look-alike: "No problems found", 1 ruled out). | "Faults get a fault verdict, and the normal look-alikes that fool simple tools are ruled out with reasons, not flagged." |
| 3:45–4:15 | Library, Hostile files: **Disguised executable** is refused before parsing. **Script injection in packet data** shows `<script>` as plain text. Its Integrity tab: signature checked, isolated process, every packet accounted for. | "It's built to be handed hostile files: checked before parsing, isolated, deleted after." |
| 4:15–4:35 | README accuracy table: holdout 135/135, 0 false alarms on 55 look-alikes, with the note that these are simulated captures. Terminal: `pytest` passing. | "Measured on held-out captures: every problem found with the right verdict, no false alarms. All detection logic is our own, with no Wireshark or Zeek underneath." |

## If time is short

Cut the fault and look-alike shot (3:20–3:45) first, then the CLI. Keep the blast radius and the Proof Pack
check: they are what no other tool here does.
