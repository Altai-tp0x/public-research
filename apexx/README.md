# APEXX

*Last updated: 2026-11-05*

## Overview

APEXX is a multi-architecture IoT botnet and self-propagating worm first captured from live delivery infrastructure and analyzed in November 2026. The threat operates on the **Milk C2** framework (internal auth key: `milk-c2-K3y-2026`), deploying payloads via an autonomous 4-port spreader targeting Telnet (ports 23/2323), Android Debug Bridge (port 5555), and Web SSL management services (port 8443).

What distinguishes APEXX from standard Mirai forks is its implementation of a custom **LFSR / XorShift stream cipher** driven by the Golden Ratio constant (`0x9E3779B9`) and 64-bit multiplier `0x7F4A7C15`. Wire communication uses newline-delimited hex-encoded ASCII over TCP. The bot enforces single-instance execution via Linux abstract UNIX domain sockets masked with runtime XOR keys, masquerades as kernel threads (`kworker/0:1H`), installs multi-tiered persistence across `/etc/rc.local`, `/etc/cron.d/qv3b`, and `/etc/init.d/qv3b`, actively terminates rival botnet processes, and executes 26 distinct Layer 4/7 denial-of-service attack vectors supported by an embedded army of 990+ public proxy relays.

## Report

See [`report.md`](report.md) for the full technical analysis: LFSR stream cipher mechanics, wire protocol framing, abstract domain socket mutexes, 26-entry attack dispatch table, competitor process killer and listening socket hijacker, autonomous worm propagation, and detection signatures.

## Technical summary

- **Lineage:** Custom IoT botnet / worm framework (Milk C2 architecture), statically linked ELF, musl-libc runtime (static PIE, stripped)
- **C2 transport:** Non-blocking TCP on port 9111 (`wemqmewkqewq.work.gd`, fallback `31.56.209.86`); registration header `REGISTER linux %s %d %lu %lu`. Supports runtime overrides via environment variables `CNC_IP` and `CNC_PORT`
- **Wire encoding:** Hex-encoded ASCII commands over TCP, parsed and decrypted in-place via custom LFSR stream cipher
- **Cryptography:** 64/128-bit LFSR stream cipher with Golden Ratio constant `0x9E3779B9`, multiplier `0x7F4A7C15`, seed states `0xCAFEBABE` and `0xDEADBEEF`, and embedded data seed `0x2E, 0x62616561` at offset `0x2D0C4`
- **Mutex lock:** Linux abstract UNIX domain socket `\0qv3b_guard_a1` and XOR 0x5A masked socket `\0qv3b_lock_9f3a` (no filesystem lock files)
- **Attack vectors:** 26-entry dispatch table spanning 17 Layer 4 vectors (`udp`, `syn`, `ack`, `icmp`, `gre`, `stomp`, `vse`, `ts3`, `raknet`, `discord`, `mc`, `ssh`, etc.) and 9 Layer 7 vectors (`tls`, `cf`, `h2`, `h2c`, `http`, `browser`, etc.)
- **Proxy army:** Embedded pool of 992 public HTTP and SOCKS5 proxy relays in `.rodata` used for anonymized Layer 7 HTTP `CONNECT` tunnel routing
- **Competitor killer:** Scans `/proc/*/comm` and `/proc/*/cmdline` to kill rival malware (`boatnet`, `gafgyt`, `xmrig`, `kinsing`, `kdevtmpfsi`, `mozi`, `mirai`); enumerates `/proc/net/tcp` to resolve socket inodes in `/proc/*/fd` and kill competing processes holding listening ports
- **Persistence:** Deploys hooks in `/etc/rc.local`, cron job in `/etc/cron.d/qv3b`, and SysV init script `/etc/init.d/qv3b` symlinked across active runlevels
- **Spreader:** Multi-port scanner targeting ports 23, 2323, 5555 (ADB), and 8443; fingerprints remote CPU architecture via `cat /proc/cpuinfo` and stages payloads via HTTP (`wget`) or TFTP (`busybox tftp`)

## Indicators

The [`iocs/`](iocs/) directory contains machine-readable indicators in CSV format:

| File | Contents |
|------|----------|
| [domains.csv](iocs/domains.csv) | Primary dynamic C2 domain and HTTP/TFTP staging endpoints |
| [ips.csv](iocs/ips.csv) | Hardcoded C2 fallback server, public DNS resolver, and representative Layer 7 proxy relays |
| [hashes.csv](iocs/hashes.csv) | Sample SHA-256, MD5, and SHA-1 hashes |
| [keys.csv](iocs/keys.csv) | LFSR multipliers, constants, seed words, auth tokens, and socket XOR mask |
