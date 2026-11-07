# Rustbox

*Last updated: 2026-11-07*

## Overview

Rustbox is an advanced, memory-safe multi-architecture botnet and worm written in modern Rust (`rustc 1.99.1-nightly`, October 2026). First captured from live delivery infrastructure and analyzed in November 2026, the threat represents a new generation of IoT malware that replaces conventional unauthenticated plaintext protocols with **Curve25519 (X25519) Diffie-Hellman key exchange**, **HKDF/HMAC-SHA-512 key derivation**, and **ChaCha20-Poly1305 AEAD authenticated wire encryption** over TCP (connecting to `77.239.124.167:29444`).

What distinguishes Rustbox from legacy Mirai and Gafgyt variants is its deep cross-platform weaponization across both enterprise Linux servers and embedded Android operating environments. It incorporates an autonomous **7-CVE spreader** targeting major router and IoT platforms (Huawei, GPON, Realtek, Netgear, Hikvision, DrayTek, and TP-Link), anonymous in-memory execution via Linux `memfd_create`, kernel worker process masquerading (`kworker/u8:2`), an aggressive **competitor killer** terminating 28 rival botnet strains, full **Magisk / KernelSU root module persistence**, an unauthenticated persistent **ADB TCP backdoor on port 12108**, and an advanced Layer 4/7 denial-of-service engine featuring a custom-built **embedded TLS 1.3 stack** and **HTTP/2 Rapid Reset** multiplexing.

## Report

See [`report.md`](report.md) for the complete technical dossier: X25519 cryptographic handshake mechanics, ChaCha20-Poly1305 wire framing, Android Magisk root persistence and ADB backdoor injection, competitor process killer and socket hijacker, autonomous 7-CVE spreader payloads, Layer 4/7 denial-of-service attack engines, YARA hunting signatures, and full IOC lists.

## Technical summary

- **Lineage:** Native 8-architecture multi-target Rust botnet / worm (standard Linux GNU and Android Bionic builds across x86-64, x86, ARMv7, and AArch64) (`service rustbox`, slogan `rustbox: memory safe. system optimized.`). Statically linked ELF PIE compiled with `rustc 1.99.1-nightly`.
- **C2 Transport & Wire Encryption:** Raw TCP on port 29444 (`77.239.124.167:29444`). Custom binary framing using client magic `RBX1` (`0x31584252`) and server magic `RBX2` (`0x32584252`).
- **Cryptography:** Ephemeral X25519 Diffie-Hellman key agreement with scalar clamping, HKDF/HMAC-SHA-512 session key derivation, and ChaCha20-Poly1305 AEAD authenticated stream encryption.
- **Device Fingerprinting:** 16-byte unique identifier token (`rustbox-device-v1`) generated from SHA-256 hashing of `/etc/machine-id`, `/var/lib/dbus/machine-id`, `/proc/sys/kernel/random/boot_id`, and NIC MAC addresses.
- **Android Root Weaponization:** Deploys Magisk / KernelSU root module `/data/adb/modules/rustbox/module.prop`, boot hooks in `/data/adb/service.d/` and `/data/adb/post-fs-data.d/`, Android init service `/system/etc/init/rustbox.rc`, and opens a persistent root ADB shell over TCP on port `12108` (`setprop persist.adb.tcp.port 12108`).
- **Linux Persistence:** Multi-tiered hooks across Systemd (`rustbox.service`), SysV init (`/etc/init.d/rustbox`), `/etc/rc.local`, Cron (`/etc/cron.d/rustbox`, `crontab -l`), `/etc/profile.d/rustbox.sh`, and user shell profiles (`~/.bashrc`, `~/.zshrc`).
- **Mutual Exclusion:** Linux abstract UNIX domain socket `\0rustbox:instance:v<tag>` combined with filesystem advisory lock files (`/dev/shm/.rbx_lock`, `/var/tmp/.rbx_lock`).
- **Stealth & Evasion:** In-memory execution via `memfd_create('worker')` (`RBX_MEMFD=1`, `memfd:(deleted)`). Masquerades process title as `kworker/u8:2` or user-defined `RUSTBOX_HIDE_COMM`. Evades honeypot environments (Cowrie, Kippo, Dionaea, Conpot, Tarpit, Canary, Shadowserver).
- **Competitor Killer:** Audits `/proc/*/comm` and `/proc/*/cmdline` to kill 28 rival botnet families (`xmrig`, `kinsing`, `mirai`, `gafgyt`, `redtail`, `billgates`, etc.), cleans unauthorized binaries in temporary folders, and reclaims listening sockets.
- **Autonomous Spreader:** Scans public IPv4 subnets (filtering private/bogon blocks) and exploits 7 IoT/router CVEs:
  - Huawei HG532 UPnP (CVE-2017-17215, port 37215)
  - DASAN GPON Auth Bypass (CVE-2018-10561 / CVE-2018-10562, ports 80/8080)
  - Realtek miniigd SOAP AddPortMapping (CVE-2014-8361, port 52869)
  - Netgear setup.cgi command injection (CVE-2016-6277 / CVE-2017-6077, ports 80/8080)
  - Hikvision webLanguage blind command injection (CVE-2021-36260, ports 80/8000)
  - DrayTek Vigor keyPath command injection (CVE-2020-8515, ports 80/443)
  - TP-Link LuCI form country injection (CVE-2020-1389, port 80)
- **Denial-of-Service Flood Engine:**
  - **Automated Protocol Routing:** Automatically routes target ports 80, 443, and 8080 to the Layer 7 TLS engine, and all other ports to the Layer 4 UDP engine.
  - **C2 Protection Whitelist:** Automatically aborts attacks targeting ports 29444 and 29596.
  - **Embedded TLS 1.3 Client:** Custom zero-dependency TLS 1.3 stack (`TLS_AES_128_GCM_SHA256` [0x1301] and `TLS_CHACHA20_POLY1305_SHA256` [0x1303]).
  - **HTTP/2 Rapid Reset (`PRI * HTTP/2.0`):** Multiplexed parallel stream flooding with rapid RST_STREAM cancellation frames.
  - **Browser Emulation:** Spoofs modern Chrome 131 headers with `zstd` and Brotli compression.
  - **Layer 4 UDP Flooding:** High-performance user-space `Xoshiro256**` PRNG generating randomized payload bytes at line rate, paired with non-blocking socket buffer tuning (`SO_SNDBUF`, `SO_PRIORITY`).
  - **Real-Time Telemetry:** Monotonic background timer transmits live network output metrics back to C2 (`[BW]|pps=...|mbps=...|active=...`).

## Indicators

The [`iocs/`](iocs/) directory contains machine-readable indicators in CSV format:

| File | Contents |
|---|---|
| [`hashes.csv`](iocs/hashes.csv) | Cryptographic SHA-256, MD5, and SHA-1 sample hashes |
| [`ips.csv`](iocs/ips.csv) | C2 server IP, C2 port, ADB backdoor port, and exploit ports |
| [`keys.csv`](iocs/keys.csv) | Wire magic tokens, Diffie-Hellman parameters, and cipher constants |
| [`exploits.csv`](iocs/exploits.csv) | 7 weaponized router / IoT CVE exploits, paths, and SOAP actions |
| [`paths.csv`](iocs/paths.csv) | Linux and Android persistence paths, lock files, and module manifests |
