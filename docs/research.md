# Research behind the detectors

NetTriage's detection logic is our own code. Where possible it implements published, peer-reviewed methods
instead of ad-hoc thresholds, adapted to a single offline capture from a small LAN. This page lists each source
and exactly what we take from it.

We favour classic, well-validated methods over recent machine-learning detectors. Most recent ARP and DNS
detection papers train classifiers on labelled datasets. Those need training data we don't have, and they
can't say *why* they flagged something, which is the core of this tool.

## The organising principle: faults are consistent, attacks are not

A fault is a self-consistent failure: every layer agrees about who is who, and something just doesn't work (a
dead server, a lossy link, a broken resolver). An attack has to lie to someone, so it leaves **inconsistencies
between layers or between expected and observed behaviour**. Examples: an ARP sender address that disagrees with
the Ethernet source, a DNS reply that arrives faster than the resolver can answer, a DHCP server whose options
point at itself.

A 2026 preprint ([arXiv 2601.03289](https://arxiv.org/pdf/2601.03289)) separates faults from cyberattacks in
industrial systems the same way, by cross-checking independent data sources. NetTriage applies that idea within
one capture. Each detector collects *consistency* evidence (pointing to a fault or benign cause) and
*inconsistency* evidence (pointing to an attack), and the differential engine weighs the two.

Every piece of evidence is a log-likelihood ratio, so it carries a weight. Port-scan detection is literally a
sequential likelihood-ratio test (TRW, below). The other detectors use the same arithmetic with weights tuned on
our development captures only.

## Port scans: Threshold Random Walk

**Source:** J. Jung, V. Paxson, A. Berger, H. Balakrishnan, *Fast Portscan Detection Using Sequential Hypothesis
Testing*, IEEE S&P 2004 ([PDF](https://people.csail.mit.edu/awberger/papers/fastPortscanDetectionUsingSequentialHypothesisTesting_JungPaxsonBergerBalakrishnan_2004.pdf)).

TRW models each source's first contact with each new destination as success (SYN-ACK) or failure (RST or no
answer). It runs Wald's sequential probability ratio test:
- Benign hosts succeed with probability θ0 = 0.8, scanners with θ1 = 0.2.
- Each failure multiplies the likelihood ratio by (1-θ1)/(1-θ0) = 4; each success by θ1/θ0 = 0.25.
- The source is declared a scanner at Λ ≥ η1 = β/α = 99, and benign at Λ ≤ η0 = (1-β)/(1-α) ≈ 0.0101, using the
  paper's α = 0.01 and β = 0.99.

This gives a *provable* false-alarm bound, and in the paper it detects scanners after 4–5 attempts, against
roughly 14–21 for Snort and Bro.

Our adaptations:
- **Vertical scans.** TRW counts distinct destination *hosts*. We also run it over distinct *(host, port)* pairs,
  which the paper leaves out of scope.
- **Fault versus attack falls out of the method.** Only *first* contacts count, so a client retrying one dead
  or refused service never accumulates evidence. That case stays a fault.
- **Friendly hosts.** We ignore failures towards hosts that had contacted the source first. The paper suggests
  this to remove its IDENT false positives.
- **A floor instead of a final "benign" verdict.** The paper stops tracking a host once it is judged benign.
  We hold the likelihood ratio at the benign threshold instead, in the style of CUSUM. So a PC that browsed
  normally for an hour and then starts scanning is still caught, after about seven failed first contacts
  rather than four.
- **Outage versus scan.** TRW alone cannot tell a scanner from a PC whose internet connection just died: both
  fail first contact after first contact. We weigh the TRW result against an outage explanation. The outage
  wins when the failed targets came from DNS lookups, sit on everyday ports, and other devices fail at the same
  time. The outage is then reported once, as a network fault, and the PCs are listed as "not a scan".
- **Shown to the user.** The likelihood ratio and the count of failed first contacts appear in the reasoning,
  e.g. "11 of 12 new destinations refused or ignored the connection; odds 4,096 to 1 against normal use".
- **Stealth scans.** FIN/NULL/Xmas flag combinations never occur in legitimate TCP, so they are direct evidence,
  as in Snort's packet-oriented scan preprocessor (described in the TRW paper's related work).
- **Tool fingerprints, as extra evidence only.** Fast scanners leave common header-field patterns: H. Griffioen,
  C. Doerr, *Discovering Collaboration: Unveiling Slow, Distributed Scanners based on Common Header Field
  Patterns*, NOMS 2020 ([TU Delft](https://research.tudelft.nl/en/publications/discovering-collaboration-unveiling-slow-distributed-scanners-bas)).
  ZMap has used a fixed IP ID of 54321 ([arXiv 1908.04193](https://ar5iv.labs.arxiv.org/html/1908.04193)),
  though newer builds may randomise it ([zmap#798](https://github.com/zmap/zmap/pull/798)). We report
  fingerprints as "consistent with…", never as proof.

## DNS spoofing: Hold-On's TTL and timing test

**Source:** H. Duan, N. Weaver, Z. Zhao, M. Hu, J. Liang, J. Jiang, K. Li, V. Paxson, *Hold-On: Protecting
Against On-Path DNS Poisoning*, SATIN 2012 ([PDF](https://people.cs.umass.edu/~phillipa/CSE390/holdon.pdf)).

Hold-On learns the IP TTL and round-trip time of a resolver's genuine replies. When more than one reply arrives
for a query, it flags replies whose IP TTL differs (beyond ±1) or that arrive in under 0.5× the expected RTT.
Secondary summaries of the paper report zero false positives and zero false negatives in its evaluation; we have
not checked that figure against the full text.

What we take:
- A per-resolver baseline of IP TTL, median RTT and, on a LAN, the source MAC. It is learned from unambiguous
  replies.
- Every reply is scored against that baseline.
- Two replies to one query that disagree are the strongest signal. A single reply that breaks the baseline is
  weaker evidence.

We add **off-path poisoning** signals:
- A burst of replies whose transaction IDs match no outstanding query, the signature of Kaminsky-style brute
  forcing. A 2009 IEICE paper detects these unmatched answers with Bloom filters
  ([IEICE](https://ken.ieice.org/ken/paper/20090206Da9B/eng/)).
- The SAD DNS researchers list "wrong TxIDs for incoming DNS responses", 50 ms bursts and UDP port scanning as
  detection signals for their 2020 attack (M. Man et al., ACM CCS 2020; summarised by
  [APNIC](https://blog.apnic.net/2021/11/30/modern-oses-dns-cache-poisoning-attacks/) and the
  [Suricata forum](https://forum.suricata.io/t/signatures-to-detect-sad-dns/831)).

Benign look-alikes we rule out:
- Pi-hole style sinkhole answers (0.0.0.0).
- Split-horizon internal names.
- CDN address rotation.
- mDNS and LLMNR.
- Client retries.
- Queries too close to the end of the capture to have seen an answer.

## TCP health: classifying out-of-sequence segments from the middle of the path

**Sources:**
- S. Jaiswal, G. Iannaccone, C. Diot, J. Kurose, D. Towsley, *Measurement and Classification of Out-of-Sequence
  Packets in a Tier-1 IP Backbone*, IEEE/ACM ToN 2007, and *Inferring TCP Connection Characteristics Through
  Passive Measurements*, INFOCOM 2004 ([researchr](https://researchr.org/publication/JaiswalIDT04/bibtex)).
- S. Rewaskar, J. Kaur, F. D. Smith, *A Passive State-Machine Approach for Accurate Analysis of TCP Out-of-Sequence
  Segments*, ACM CCR 2006 ([PDF](https://www.cs.unc.edu/~jasleen/papers/ccr06.pdf)).

Jaiswal et al. classify each out-of-sequence segment using only the packets seen before and after it at one
measurement point, plus knowledge of TCP. The classes are retransmission, network reordering and network
duplication, and the deciding factor is the time gap compared with the RTT. Rewaskar et al. show that accuracy
improves by modelling OS-specific behaviour, such as different minimum retransmission timeouts.

What we take:
- **Each anomaly gets a class.** Segments are labelled *retransmission*, *reordering* (filled within a fraction of
  an RTT), *spurious retransmission* (data already acknowledged) or *capture gap* (data acknowledged but never
  seen, which is a capture problem, not a network one). Only real retransmissions count as loss.
- **The RTT comes from the handshake.** SYN→SYN-ACK and SYN-ACK→ACK split the RTT into the legs on either side of
  the capture point.
- **Loss is placed relative to the capture point.** If we saw the original and the retransmission, the loss
  happened *after* the capture point. If we saw a hole filled later, it happened *before* it. The explanation can
  then say "between this network and github.com" instead of only "packets were lost".

Localisation follows the inference-graph idea of P. Bahl et al., *Towards Highly Reliable Enterprise Network
Services via Inference of Multi-level Dependencies* (Sherlock), SIGCOMM 2007
([PDF](https://microsoft.com/en-us/research/wp-content/uploads/2016/02/sherlock_sigcomm_07.pdf)). We keep a
three-level model, client → gateway → server, and ask which single component best explains the lossy or slow
flows:
- one server, seen from many clients: that server or the path to it;
- one client, towards many servers: that client's cable or Wi-Fi;
- everyone: the shared gateway or uplink.

## TCP resets: don't trust TTL alone

**Source:** N. Weaver, R. Sommer, V. Paxson, *Detecting Forged TCP Reset Packets*, NDSS 2009
([PDF](https://ndss-symposium.org/wp-content/uploads/2017/09/weav.pdf)).

An injected RST cannot stop packets already in flight, so it creates race signatures: data arriving after the
RST at a consistent sequence number. The paper also warns that **28% of normal responder-terminated flows have
RST TTLs that differ from earlier packets**. We therefore never treat an odd RST TTL as evidence on its own.
Browser and server RST-closes are classed as normal. Race signatures are a stretch detector for RST injection.

## ARP integrity

Recent ARP spoofing papers we found are mostly machine-learning classifiers. One example builds features on
packet frequency, opcode and MAC-IP binding patterns
([MDPI Applied Sciences 2025](https://www.mdpi.com/2076-3417/15/22/12147)); another is
[arXiv 2507.21087](https://arxiv.org/html/2507.21087v1). We use the passive, explainable checks they and older
work describe:
- IP-to-MAC binding changes.
- Replies with no matching request (also a rule in
  [Kaspersky's industrial IDS](https://support.kaspersky.com/KICSforNetworks/4.1/en-US/171092.htm)).
- An ARP sender MAC that disagrees with the Ethernet source MAC, the cross-layer check in
  [arXiv 1907.12735](https://arxiv.org/pdf/1907.12735).

We add our own:
- **Forwarding proof.** A man-in-the-middle has to relay traffic. So the same IP packet (same IP ID and
  addresses) shows up twice: once addressed to the attacker's MAC, then again from it with the TTL one lower.
  This upgrades "suspicious" to "confirmed interception". We did not find this check in the sources above.
- **Benign explainers.**
  - VRRP/HSRP/CARP advertisements from the new owner mean a router failover.
  - A DHCP lease to the new MAC means a device swap.
  - A single, stable change means a replaced device; repeated flip-flopping does not.
  - A reply to an RFC 5227 probe (sender IP 0.0.0.0) is the textbook duplicate-address signal.

## Rogue DHCP servers

We found no peer-reviewed passive method; practice is to compare responders with a list of authorised servers.
Examples are a [patent on detecting rogue protocol service providers](https://patents.justia.com/patent/20130318605),
Snort rules with allow-lists, and a small
[Strathmore thesis IDS](https://su-plus.strathmore.edu/items/37fa485a-7053-42dc-bf8e-5697ae78cfe9).

We don't require a list. We *infer* the legitimate server from the capture: the server that most clients take
leases from, and whose offered router actually carries their traffic. Then we weigh:
- **Rogue (attack):** same subnet, but the router or DNS option points back at the offering host. This is a
  stealthy interception setup: clients keep working, but their traffic goes through the attacker.
- **Misconfigured (fault):** a different subnet, typically a home router plugged in backwards. Clients that take
  it lose connectivity, so it is an outage, not an interception.
- **Failover pair (benign):** two servers offering identical router and DNS options.

## MTU black holes (stretch)

**Source:** M. Luckie, B. Stasiewicz, *Measuring Path MTU Discovery Behaviour*, IMC 2010
([DBLP](https://dblp.uni-trier.de/rec/bibtex/conf/imc/LuckieS10)). It found PMTUD failing for 5–18% of popular
websites over IPv4, depending on the MTU of the constraining link.

The signature is a handshake that completes, then a transfer that stalls: full-size segments with the
don't-fragment bit are retransmitted repeatedly while small segments get through. Usually no ICMP "fragmentation
needed" message is seen, because a firewall dropped it.

How we use it (`backend/nettriage/detectors/mtu.py`):
- **Black hole (fault).** For each TCP direction we track full-size segments (over 1000 bytes of payload) and
  small ones separately. The rules weigh: full-size segments resent again and again and never acknowledged; small
  segments on the *same* connections acknowledged (congestion would drop those too, so this argues against plain
  loss); the don't-fragment bit set; no ICMP "packet too big" anywhere in the capture; connections that fall back
  to small segments after the failures (what Windows' black-hole detection does); and several devices showing the
  same pattern. The competing explanation is ordinary packet loss.
- **ICMP present (benign or fault).** When a router *does* send "fragmentation needed" or "packet too big", the
  message alone is not a problem: a smaller link (a VPN or PPPoE uplink) is normal. We check what the senders did
  next. If they shrank their segments below the reported MTU and the data was acknowledged, Path MTU Discovery
  is working, and the finding goes to "checked and ruled out". If they kept sending oversized segments, it is a
  fault.

## Incident correlation (stretch)

Separate findings often share one cause. Security operations tools call this alert correlation. The common
approaches are to group alerts by shared attributes, by time, or with attack-scenario templates; see
F. Valeur, G. Vigna, C. Kruegel, R. Kemmerer, *A Comprehensive Approach to Intrusion Detection Alert
Correlation*, IEEE TDSC 2004 ([DOI](https://doi.org/10.1109/TDSC.2004.21)).

We use the two simplest of those ideas, because each is easy to explain to a user and easy to check
(`backend/nettriage/reasoning/correlate.py`):
- **Same offending device.** Attack findings whose offender (the ARP claimant, the DNS forger, the scanner, the
  rogue DHCP server) is the same MAC or IP become one incident. The root finding is picked by a fixed order: ARP
  spoofing or a rogue DHCP server comes first, because it is what makes a DNS forgery possible.
- **Outage and its symptoms.** An internet outage and the DNS failures that overlap it in time become one fault
  incident. Users then see one cause to fix, not two.

Faults and attacks are never linked to each other. An attacker does not explain a broken uplink, and linking them
would hide one of them.

The simulator labels which findings must be linked, and `eval/run_eval.py` checks both directions: expected links
that were not made, and links made where none was expected.
