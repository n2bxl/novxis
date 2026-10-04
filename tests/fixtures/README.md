# Sanitized Phase 0 Capture Fixtures

`arp_phase0_sanitized.pcap` is a deterministic Ethernet/ARP regression
capture created specifically for NOVXIS tests. It does not contain traffic
captured from a real network.

The fixture uses documentation-only IPv4 addresses from `192.0.2.0/24`
and locally administered synthetic MAC addresses beginning with `02:`.

It contains eight frames covering:

- an ordinary ARP request/reply exchange;
- an unmatched ARP reply;
- a request with sender protocol address `0.0.0.0`;
- a self-directed request where sender and target protocol addresses match;
- repeated requests followed by a reply, exercising newest-request correlation;
- 42-byte frames with no trailing bytes;
- 60-byte frames with 18 trailing zero bytes; and
- 74-byte frames with 32 trailing zero bytes.

The fixture is intentionally behavioral-neutral. The unusual requests are
preserved as evidence for regression testing and are not labeled as probes,
announcements, conflicts, or any other higher-level semantic class.
