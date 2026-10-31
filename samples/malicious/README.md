# Hostile and broken captures

Each file here attacks the parser in a different way. NetTriage must handle all of
them without crashing, hanging, or rendering attacker-controlled text as markup.
`backend/tests/test_malicious_samples.py` checks every file on each test run.
Regenerate them with `python samples/generate/make_malicious.py`.

| File | What it does | What NetTriage does |
|---|---|---|
| `not_a_pcap.exe.pcap` | A Windows executable renamed to `.pcap` | Rejected by the magic-byte check before any parsing ("looks like a Windows executable") |
| `empty.pcap` | Zero bytes | Rejected: too small to be a capture |
| `truncated.pcap` | Valid capture cut off in the middle of a packet | Keeps the 4 complete packets and reports that the capture was cut short |
| `huge_caplen.pcap` | A packet record claiming a 4 GB length | Refuses to allocate, keeps the packet before it, and reports corruption at that byte offset |
| `bad_block_len.pcapng` | pcapng block with an impossible length (13, not a multiple of 4) | Stops at that block and reports it |
| `corrupt_packets.pcap` | Valid file with an IPv4 header length of 3, a TCP data offset of 2, a DHCP option running past the packet, a 3-byte runt frame and random noise | Skips each broken packet with a reason and frame number, and still analyses the 4 good packets |
| `dns_pointer_loop.pcap` | DNS names whose compression pointers point at themselves or at each other (an infinite-loop attack) | Pointers must point strictly backwards, so the loop is detected at once and the packet is skipped |
| `xss_payloads.pcap` | DNS names and DHCP hostnames containing `<script>`, `onerror=` handlers, ANSI terminal escapes, a right-to-left override and a spreadsheet formula | Bytes are escaped to plain ASCII at decode time, and the UI renders them as inert text |

With `--large`, the script also writes `samples/generated/syn_flood_100k.pcap`: 100,000 SYNs from random
spoofed sources. It shows that the state tables stay bounded. It is not committed because of its size.
