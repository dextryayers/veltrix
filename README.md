<p align="center">
  <img src="logo.png" alt="Veltrix Logo" width="220" />
</p>

<h1 align="center">Veltrix</h1>

<p align="center">
  <strong>Multi-Protocol Brute Force and Security Auditing Toolkit</strong><br />
  Fast, modular, and extensible credential testing platform written in Rust.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-blue?style=flat-square" alt="Platform" />
  <img src="https://img.shields.io/badge/protocols-47-success?style=flat-square" alt="Protocols" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/version-2.0.0-red?style=flat-square" alt="Version" />
</p>

> **Authorized testing only. Unauthorized use against systems you do not own or have explicit written permission to test is ILLEGAL.**

---

## Table of Contents

- [1. Description](#1-description)
- [2. Key Points](#2-key-points)
- [3. Features](#3-features)
- [4. Supported Protocols](#4-supported-protocols)
- [5. Architecture and Flowchart](#5-architecture-and-flowchart)
- [6. Installation](#6-installation)
- [7. Quick Start](#7-quick-start)
- [8. Usage](#8-usage)
- [9. Target Specification](#9-target-specification)
- [10. Credential Handling](#10-credential-handling)
- [11. Performance Tuning](#11-performance-tuning)
- [12. Proxy Support](#12-proxy-support)
- [13. Output Formats and Encryption](#13-output-formats-and-encryption)
- [14. Port Scanner](#14-port-scanner)
- [15. Wordlist Generation, Rules, and ML](#15-wordlist-generation-rules-and-ml)
- [16. Configuration File](#16-configuration-file)
- [17. Resume and Session](#17-resume-and-session)
- [18. Distributed Mode and API](#18-distributed-mode-and-api)
- [19. Plugin System](#19-plugin-system)
- [20. Project Structure](#20-project-structure)
- [21. Testing and Development](#21-testing-and-development)
- [22. Practical Examples](#22-practical-examples)
- [23. FAQ](#23-faq)
- [24. Disclaimer and Legal Notice](#24-disclaimer-and-legal-notice)
- [25. License and Credits](#25-license-and-credits)

---

## 1. Description

**Veltrix** is a high performance multi-protocol brute force and security auditing toolkit for security professionals, penetration testers, red teams, system administrators, and researchers.

It is written in 100% Rust and compiled to a single static optimized binary of around 8 MB. It focuses on speed, correctness, modular protocol implementation, safe concurrency, clear output, and audit friendly reporting.

Typical use cases:

- Password strength auditing on your own infrastructure
- Credential exposure assessment after a data leak
- Service hardening verification for SSH, FTP, RDP, databases, web logins, and more
- Lab and CTF practice with repeatable attack configurations
- Integration into larger security pipelines through JSON, CSV, YAML, and HTML reports

Veltrix currently implements **47 protocol modules** behind one unified `Protocol` trait, one CLI interface, one credential engine, one worker pool, one rate limiter, and one output system.

---

## 2. Key Points

1. **47 protocols in one binary:** network services, databases, message brokers, VoIP and media, web apps, remote management, chat and news, version control, and legacy protocols.
2. **Smart credential merger:** `-u` plus `-U` and `--password` plus `-W` are merged automatically, with cartesian expansion, combo file support, deduplication, and optional rule based mutation.
3. **High performance async core:** Tokio multi thread runtime, semaphore bounded workers, batch dispatch, lock free structures with `DashMap` and `DashSet`, memory mapped wordlists, and SIMD accelerated parsing where applicable.
4. **Real time feedback:** live dashboard with spinner, progress bar, rate estimation, success counter, fail and error classification, and verbose levels `-v` and `-vv`.
5. **Operational safety controls:** connection timeout, retries with exponential backoff, delay and jitter, global rate limit, stop on first success, account lockout detection, proxy rotation, and graceful Ctrl+C shutdown.
6. **Audit ready output:** plain text, JSON, CSV, YAML, and styled HTML reports, plus optional AES-256-GCM output encryption with Argon2 key derivation.
7. **More than brute force:** TCP port scanner with banner grabbing, wordlist generator, Markov chain password predictor, TOML and JSON config loader, distributed coordinator and worker mode, minimal HTTP API, plugin loader, and VS Code extension.
8. **Single binary deployment:** release profile uses `opt-level=3`, thin LTO, single codegen unit, and symbol stripping. Docker image is based on Debian slim with only runtime libraries.

---

## 3. Features

### Core attack engine

- Unified target loader with CIDR expansion, IP range expansion, DNS resolution, and TCP health check
- Unified credential loader with deduplication and max password length truncation
- Worker pool based on `Arc`, `Semaphore`, `JoinSet`, and unbounded MPSC result channel
- Per attempt timeout, per protocol default ports, and configurable retries
- Error classification: authentication failure, transient network error, lockout signal, rate limit signal
- Automatic backoff: `500ms * 2^N` capped at 30 seconds
- Skip locked users, rotate proxy on signal, prompt on first hit unless `--stop-on-first` is used
- Session checkpoint file for resume support
- Exit code `0` when at least one valid credential is found, otherwise `1`

### Scanner

- Fast concurrent TCP scanner
- Port specification: list `22,80,443`, range `1-1000`, or keyword `common` for around 1200 ports
- Banner grabbing and service fingerprint database
- Configurable timeout, concurrency rate, and banner toggle

### Credential intelligence

- Direct values, user files, password files, and `user:pass` combo files
- Rule based mutation from `rules/common.rule`
- Target aware wordlist generation from name, company, date of birth, and keywords, including leet variations
- Markov chain training, generation, and scoring for password prediction

### Network and evasion related controls

- HTTP CONNECT proxy with optional auth
- SOCKS4 and SOCKS5 proxy with optional auth
- Proxy rotation from file
- Multi hop proxy chain definition
- TCP keepalive through `socket2`
- TLS support for FTP, SMTP, POP3, IMAP, Postgres, Redis, LDAP, and HTTP layers

### Reporting and automation

- Console live dashboard
- File output with selectable format
- HTML report with dark style summary table
- Cloud style job submission API
- Distributed task protocol with hello, task batch, result report, and heartbeat messages
- VS Code commands for run attack, open results, and stop attack

---

## 4. Supported Protocols

Total: **47 modules**. Use `veltrix --list-protocols` or `veltrix <protocol> --help` to inspect the local build.

### 4.1 Network and authentication services

| Protocol | Default port | Notes |
|---|---|---|
| `ssh` | 22 | libssh2 based auth, blocking isolated with `spawn_blocking` |
| `ftp` | 21 | Explicit TLS support |
| `telnet` | 23 | Telnet negotiation handling |
| `smtp` | 25, 465, 587 | Raw SMTP plus STARTTLS |
| `pop3` | 110, 995 | STLS support |
| `imap` | 143, 993 | STARTTLS support |
| `rdp` | 3389 | NLA and CredSSP with NTLMv2, optional `--rdp-domain` |
| `ldap` | 389, 636 | LDAP and LDAPS bind |
| `smb` | 445 | NTLMv1 and NTLMv2 |
| `snmp` | 161 | Community string enumeration |
| `vnc` | 5900, 5901 | VNC authentication |
| `squid` | 3128 | Proxy authentication |
| `http` | 80, 443, 8080, 8443 | Basic, Digest, and form login with `--http-userfield`, `--http-passfield`, `--http-success` |

### 4.2 Databases

| Protocol | Default port | Notes |
|---|---|---|
| `mysql` | 3306 | Native MySQL auth |
| `postgres` | 5432 | SSL capable auth, alias `postgresql` |
| `mongodb` | 27017 | SCRAM auth |
| `mssql` | 1433 | SQL Server auth |
| `redis` | 6379, 6380 | Password auth plus TLS mode |
| `oracle` | 1521 | Oracle database auth |
| `cassandra` | 9042 | Cassandra auth |
| `couchdb` | 5984 | CouchDB auth |
| `elasticsearch` | 9200 | Elasticsearch auth |
| `firebird` | 3050 | Firebird auth |
| `memcached` | 11211 | Memcached auth check |

### 4.3 Message brokers

| Protocol | Default port | Notes |
|---|---|---|
| `rabbitmq` | 5672 | AMQP auth |
| `activemq` | 61616 | ActiveMQ auth |
| `kafka` | 9092 | Kafka auth |

### 4.4 VoIP and media

| Protocol | Default port | Notes |
|---|---|---|
| `sip` | 5060 | SIP Digest auth |
| `rtsp` | 554 | RTSP auth |

### 4.5 Web applications and DevOps

| Protocol | Notes |
|---|---|
| `tomcat` | Tomcat manager auth |
| `jenkins` | Jenkins login |
| `gitlab` | GitLab login |
| `sonarqube` | SonarQube login |
| `docker` | Docker registry auth |
| `kubernetes` | Kubernetes API auth |
| `vault` | HashiCorp Vault auth |
| `consul` | HashiCorp Consul auth |

### 4.6 Remote management

| Protocol | Notes |
|---|---|
| `vmware` | vSphere auth |
| `ilo` | HP iLO auth |
| `ipmi` | IPMI auth |

### 4.7 Chat and news

| Protocol | Notes |
|---|---|
| `xmpp` | XMPP auth |
| `irc` | IRC auth |
| `nntp` | NNTP auth |

### 4.8 Version control

| Protocol | Notes |
|---|---|
| `cvs` | CVS auth |
| `svn` | Subversion auth |

### 4.9 Legacy remote access

| Protocol | Notes |
|---|---|
| `rexec` | Remote execution auth |
| `rlogin` | Remote login auth |

---

## 5. Architecture and Flowchart

### 5.1 Layered architecture

```text
CLI Layer
  clap Parser, Commands, ProtocolArgs, CreateArgs, ScanPortsArgs
        |
        v
Configuration Layer
  AttackConfig, validation, TOML loader, JSON loader
        |
        v
Orchestration Layer
  AttackOrchestrator, target expansion, credential expansion,
  proxy loading, dashboard init, batch loop, session save
        |
        v
Execution Layer
  WorkerPool, Semaphore, JoinSet, rate limiter,
  Protocol trait dispatch, retries, backoff
        |
        v
Protocol Layer
  47 authenticate() implementations
  TCP connect, TLS upgrade, proxy connect, protocol handshake
        |
        v
Result Layer
  AuthResult channel, pattern classifier, dashboard update,
  file output, HTML report, encrypted output, resume state
```

Supporting subsystems run beside this flow: port scanner, API server, cloud scheduler, distributed coordinator and worker, wordlist generator, ML predictor, encryption helper, and plugin loader.

### 5.2 Main attack flowchart

```mermaid
flowchart TD
    A[Start: veltrix COMMAND] --> B[Parse CLI with clap]
    B --> C{Early exit command?}
    C -->|list-protocols, list-plugin, gen-wordlist, ml-train, decrypt, man| Z[Execute utility and exit]
    C -->|attack or scan| D[Build AttackConfig and validate]
    D --> E[Expand targets: CIDR, range, file, DNS]
    E --> F[TCP health check if target count is large]
    F --> G[Load credentials: users x passwords, combo, rules]
    G --> H[Deduplicate targets and credentials]
    H --> I[Load proxies: single, file, chain]
    I --> J[Init live dashboard and session state]
    J --> K[Batch loop: 256 tasks per batch]
    K --> L[Rate limiter wait plus jitter delay]
    L --> M[Submit WorkerTask to pool]
    M --> N[Protocol authenticate with timeout]
    N --> O{Result?}
    O -->|Success| P[Record success, update dashboard, prompt or stop]
    O -->|Auth fail| Q[Increment fail counter]
    O -->|Transient or lockout| R[Backoff, skip user or rotate proxy, retry]
    R --> N
    Q --> S{More combinations?}
    P --> S
    S -->|Yes| K
    S -->|No| T[Wait for workers, save session]
    T --> U[Write output file and HTML report]
    U --> V{Any success?}
    V -->|Yes| W[Exit 0]
    V -->|No| X[Exit 1]
```

### 5.3 Worker flowchart

```mermaid
flowchart TD
    A[WorkerTask: Target plus Credential] --> B[Check locked user set]
    B -->|Locked| C[Skip task]
    B -->|Allowed| D[Resolve protocol module]
    D --> E[Acquire semaphore slot]
    E --> F[Attempt 0 to N retries]
    F --> G[Connect through proxy if configured]
    G --> H[Optional TLS upgrade]
    H --> I[Send protocol auth exchange]
    I --> J[Read and parse response]
    J --> K[Classify with patterns module]
    K --> L{Class?}
    L -->|Success| M[Send success result]
    L -->|Hard fail| N[Send fail result]
    L -->|Transient| O[Sleep backoff and retry]
    L -->|Lockout| P[Mark user skipped and send result]
    L -->|Rate limited| Q[Rotate proxy and retry]
```

---

## 6. Installation

### 6.1 Requirements

- Rust toolchain 1.77 or newer for source builds
- Linux recommended, macOS supported
- OpenSSL development libraries for some TLS paths
- Docker optional, required only for integration tests
- Around 1 GB free disk for Rust build artifacts

### 6.2 Build from source

```bash
git clone https://github.com/aniippxploit/veltrix.git
cd veltrix

# Release build, recommended
cargo build --release

# Debug build, faster compile
cargo build

# Result
./target/release/veltrix --help
./target/release/veltrix --list-protocols
```

### 6.3 Install with Makefile

```bash
make build-release
sudo make install

# Verify
veltrix --help

# Remove later if needed
sudo make uninstall
```

Available make targets include:

```text
build, build-release, build-debug
test, test-unit, test-integration
lint, fmt, check
clean, clean-all
install, uninstall
run ARGS="ssh -t 127.0.0.1 -u root --password toor"
docker-build, docker-test, docker-down
```

### 6.4 Install script

```bash
chmod +x install.sh
./install.sh

# Useful environment overrides
VELTRIX_REPO_DIR=/path/to/repo ./install.sh
INSTALL_DIR=/usr/local/bin ./install.sh
SKIP_BUILD=1 ./install.sh
```

Uninstall:

```bash
chmod +x uninstall.sh
./uninstall.sh
```

### 6.5 Docker

```bash
# Build image
docker build -t veltrix .

# Run help
docker run --rm veltrix --help

# Run attack from container
docker run --rm veltrix ssh -t 192.168.1.1 -u admin -W /wordlists/passwords.txt

# Start local test services
docker compose -f docker/docker-compose.test.yml up -d
docker compose -f docker/docker-compose.test.yml down
```

The test compose file provides isolated SSH, FTP, MySQL, Telnet, SMTP, and HTTP services on the `10.10.0.0/16` test subnet.

### 6.6 VS Code extension

Source is available in `vscode-extension/`.

It contributes:

- `veltrix.runAttack`
- `veltrix.openResults`
- `veltrix.stopAttack`

Configuration:

```json
{
  "veltrix.binaryPath": "veltrix",
  "veltrix.apiEndpoint": "http://127.0.0.1:8080"
}
```

---

## 7. Quick Start

```bash
# 1. Show help
veltrix --help
veltrix ssh --help

# 2. List protocols
veltrix --list-protocols

# 3. Basic SSH audit with one user and one password file
veltrix ssh -t 192.168.1.1 -u admin -W config/wordlists/passwords.txt

# 4. Scan common ports first, then attack only open services
veltrix scan-ports -t 192.168.1.1 --ports common -o scan.txt
veltrix ftp -t 192.168.1.1 -U config/wordlists/users.txt -W config/wordlists/passwords.txt

# 5. Save structured JSON output
veltrix ssh -t 192.168.1.1 -U users.txt -W passwords.txt -o result.json -f json

# 6. Show full manual
veltrix man
veltrix how
```

---

## 8. Usage

### 8.1 Command pattern

```text
veltrix <COMMAND> [TARGET OPTIONS] [CREDENTIAL OPTIONS] [PERFORMANCE OPTIONS] [PROXY OPTIONS] [OUTPUT OPTIONS]
```

Examples:

```bash
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt
veltrix ftp -t 10.0.0.5 -p 2121 -U users.txt -W passwords.txt -x 20
veltrix rdp -t 10.0.0.10 --rdp-domain CORP -U users.txt -W passwords.txt
veltrix http -t 10.0.0.20:8080 --http-userfield username --http-passfield password --http-success Dashboard -u admin -W passwords.txt
```

### 8.2 Global target options

| Option | Description | Example |
|---|---|---|
| `-t, --target HOST[:PORT]` | Repeatable target, supports IP, domain, CIDR, and range | `-t 192.168.1.1 -t 10.0.0.5:2222` |
| `-l, --list FILE` | Target list file, one host per line | `-l targets.txt` |
| `-p, --port PORT` | Repeatable port override | `-p 22 -p 2222` |
| `-L, --list-protocols` | List protocols and exit | `veltrix -L` |

### 8.3 Global credential options

| Option | Description | Example |
|---|---|---|
| `-u, --user USER` | Repeatable single username | `-u admin -u root` |
| `-U, --user-file FILE` | Username wordlist | `-U users.txt` |
| `-w, --password PASS` | Repeatable single password, alias `--pwd` | `--password admin123` |
| `-W, --password-list FILE` | Password wordlist, alias `--pl` | `-W passwords.txt` |
| `-C, --combo FILE` | Combo file with `user:pass` per line | `-C combos.txt` |
| `--max-password-len N` | Truncate passwords longer than N | `--max-password-len 64` |

### 8.4 Global performance options

| Option | Default | Description |
|---|---|---|
| `-x, --threads N` | `10` | Concurrent workers |
| `--timeout SEC` | `10` | Connection and read timeout in seconds |
| `--delay MS` | `0` | Fixed delay between attempts in milliseconds |
| `--rate-limit N` | unlimited | Maximum attempts per second when set |
| `--retries N` | `2` | Additional connection retries |
| `--stop-on-first` | false | Stop target after first valid credential |
| `--spray` | false | Spray mode: one password across all users first |
| `--single-user` | false | Only first username tested with all passwords |
| `--spray-interval DUR` | `0` | Pause between spray rounds, e.g. 30s, 30m, 2h |
| `--spray-jitter PCT` | `20` | Symmetric jitter percent on spray interval |
| `--target-rate-limit N` | none | Max attempts/sec per target |
| `--user-cooldown DUR` | `0` | Min interval per username, e.g. 500ms, 5s |
| `--lockout-cooldown SEC` | `600` | Cooldown after account-lockout signal |
| `--rate-cooldown SEC` | `60` | Cooldown after rate-limit signal on a target |
| `--lockout-pause` | false | Pause for cooldown then retry instead of skipping user |
| `--user-agent STR` | rotate | Override HTTP User-Agent pool |
| `--safe-profile` | false | Conservative preset for production-like targets |
| `--aggressive-lab` | false | Aggressive preset, lab networks only |
| `--i-understand-risk` | false | Acknowledge aggressive run against non-lab targets |
| `--only-open FILE` | none | Restrict targets to open ports in scan output file |
| `--resume FILE` | none | Resume session file |
| `--config FILE` | none | Base TOML/JSON config, CLI flags override file |
| `--rule FILE` | none | Password mutation rule file |
| `--max-mutations N` | `500` | Max rule mutations per password |
| `--checkpoint N` | `100` | Session checkpoint interval |
| `--api-bind ADDR` | none | REST API bind, local only recommended |
| `--fp-check` | false | Re-verify successes to cut false positives |
| `--dry-run` | false | Show plan without network traffic |
| `-v, -vv` | off | Verbose level 1 or 2 |

### 8.5 Protocol specific options

| Option | Applies to | Description |
|---|---|---|
| `--rdp-domain DOMAIN` | `rdp` | Domain prepended to username |
| `--http-userfield FIELD` | `http` | Form username field name |
| `--http-passfield FIELD` | `http` | Form password field name |
| `--http-success TEXT` | `http` | Success marker searched in HTTP response |

### 8.6 Utility commands

```bash
# Port scanner
veltrix scan-ports -t 10.0.0.1 --ports 22,80,443
veltrix scan-ports -t 10.0.0.1 --ports 1-1000 --scan-timeout 3 --rate 500
veltrix scan-ports -t 10.0.0.1 --ports common --no-banner

# Wordlist generator
veltrix create -n "John Smith" -c "Acme Corp" -d "1990-05-12" -k admin -k qwerty -o ./wordlists/custom.txt

# Manual
veltrix man
veltrix how

# Plugin list
veltrix --list-plugin

# Decrypt previous encrypted output
veltrix --decrypt result.json.enc --decrypt-output result.json

# Validate config without attacking (exit 0 valid, 2 invalid)
veltrix validate ./config/veltrix.toml
veltrix validate ./my-run.json

# Shell completion
veltrix completion bash
veltrix completion zsh
veltrix completion fish
veltrix completion powershell

# Config file + CLI override + dry run
veltrix ssh --config ./my-run.json --dry-run
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --spray --delay 1000 --dry-run
```

### 8.7 Stealth, spray cadence, and cooldown (Fase 4)

Three limiter levels stack: global `--rate-limit`, per-target `--target-rate-limit`,
and per-username `--user-cooldown` (e.g. `500ms`, `5s`), on top of `--delay` + jitter.

```bash
# Spray one password across all users, 30s +/- 20% between rounds
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --spray \
  --spray-interval 30m --spray-jitter 20 --target-rate-limit 5 \
  --user-cooldown 2s --lockout-cooldown 600 --rate-cooldown 60

# Pause (instead of skip) on lockout, then retry after cooldown
veltrix smb -t 10.0.0.5 -U users.txt -W passwords.txt --spray --lockout-pause

# Conservative preset for production-like targets
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --safe-profile

# Aggressive preset, lab networks only (RFC1918/loopback or --i-understand-risk)
veltrix ssh -t 192.168.1.0/24 -U users.txt -W top1000.txt --aggressive-lab

# Custom HTTP User-Agent (default rotates a realistic pool + cookie store)
veltrix http -t 10.0.0.1 -u admin -W passwords.txt \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"
```

Lockout and rate-limit signals are counted live on the dashboard (first-seen
warning) and shown in the final summary. Exit codes: `0` found or dry-run/validate
ok, `1` no findings or runtime fail, `2` config invalid, `130` forced interrupt.

### 8.8 Auto scan-to-attack (Fase 5)

```bash
# Scan, fingerprint, attack only open attackable services
veltrix auto -t 10.0.0.1 --ports common -U users.txt -W passwords.txt

# With policy guardrails + combined JSON report
veltrix auto -t 10.0.0.0/24 --ports 22,80,443,3306,3389 \
  -U users.txt -W passwords.txt --policy config/auto-policy.example.toml \
  --min-confidence 50 -o auto-report.json -f json

# Attack subcommand gated by a previous scan output
veltrix scan-ports -t 10.0.0.1 --ports common -o scan.txt
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --only-open scan.txt
```

Auto groups open ports by `(protocol, port)` using banner/product fingerprint
with confidence 0-100 (product 90, banner rule 75, port-only 50) and skips
services without an attack module. See `docs/protocols-v2.md` for port defaults,
TLS modes, proxy chain limits, and fingerprint notes.

---

## 9. Target Specification

Veltrix accepts flexible target syntax:

```bash
# Single host, default protocol port
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt

# Host with explicit port
veltrix ssh -t 192.168.1.1:2222 -u admin -W passwords.txt

# Domain
veltrix http -t example.local:8080 -u admin -W passwords.txt

# CIDR block
veltrix ssh -t 192.168.1.0/24 -U users.txt -W passwords.txt

# IP range
veltrix ssh -t 10.0.0.1-10.0.0.20 -U users.txt -W passwords.txt

# Multiple targets and ports
veltrix ssh -t 10.0.0.1 -t 10.0.0.2 -p 22 -p 2222 -U users.txt -W passwords.txt

# Target file
veltrix ssh -l targets.txt -U users.txt -W passwords.txt

# IPv6
veltrix ssh -t "[::1]:22" -u root -W passwords.txt
```

Behavior:

1. Targets are expanded from CIDR and range syntax.
2. Duplicates by host, port, and protocol are removed.
3. Hostnames are resolved concurrently with bounded parallelism.
4. Unresolvable hosts are skipped with a warning.
5. For larger target sets, a short TCP health check filters closed ports before credential testing.

---

## 10. Credential Handling

### 10.1 Merge behavior

You can mix direct values and files. Veltrix merges them automatically.

```bash
# One user against password file
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt

# Multiple users and passwords
veltrix ssh -t 192.168.1.1 -u admin -u root --password toor -W passwords.txt

# User file plus password file
veltrix ssh -t 192.168.1.1 -U users.txt -W passwords.txt

# Combo file
veltrix ssh -t 192.168.1.1 -C combos.txt
```

Expansion order is deterministic and deduplicated. Password truncation with `--max-password-len` is applied before testing.

Example combo file:

```text
admin:admin123
root:toor
user:password
```

### 10.2 Bundled wordlists

Repository includes starter files:

```text
config/wordlists/users.txt
config/wordlists/passwords.txt
config/wordlists/combos.txt
```

Replace them with project specific lists for real engagements. Do not commit real client credentials to version control.

---

## 11. Performance Tuning

### 11.1 Recommended starting points

```bash
# Conservative, low noise, safer for production like systems
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -x 5 --timeout 10 --delay 500 --retries 1

# Balanced lab speed
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -x 20 --timeout 8 --retries 2

# Aggressive local lab only
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -x 50 --timeout 5 --rate-limit 100
```

### 11.2 Guidance

- Increase `-x` for throughput, decrease it to reduce service load and lockout risk.
- Use `--delay` and `--rate-limit` when testing systems with throttling or lockout policies.
- Use `--timeout` higher on slow or remote networks, lower on local labs.
- Use `--retries` to tolerate unstable networks, but avoid high retries against lockout sensitive logins.
- Use `--stop-on-first` when only one valid credential per host is needed.
- Prefer `scan-ports` first so brute force runs only against open services.
- Monitor server logs during authorized tests and stop immediately if the service degrades.

---

## 12. Proxy Support

### 12.1 Single proxy

```bash
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --proxy socks5://127.0.0.1:9050
veltrix http -t 10.0.0.1 -u admin -W passwords.txt --proxy http://127.0.0.1:8080
```

Supported schemes:

- `http://`
- `https://`
- `socks4://`
- `socks5://`

Credentials can be embedded when required:

```text
socks5://user:pass@127.0.0.1:1080
http://user:pass@proxy.example:8080
```

### 12.2 Rotation and chaining

```bash
# Rotate proxies from file
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --proxy-file proxies.txt

# Chain multiple proxies
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt --proxy-chain "socks5://127.0.0.1:1080,http://127.0.0.1:8080"
```

Proxy file format, one proxy per line:

```text
socks5://127.0.0.1:1080
http://127.0.0.1:8080
http://user:pass@192.168.1.10:3128
```

---

## 13. Output Formats and Encryption

### 13.1 Formats

```bash
veltrix ssh -t 10.0.0.1 -u admin -W passwords.txt -o result.txt -f plain
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o result.json -f json
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o result.csv -f csv
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o result.yaml -f yaml
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o result.html -f html
```

- `plain`: human readable console style log
- `json`: JSONL, one `veltrix-finding/v2` object per line (run_id, credential_ref, severity, evidence, no plaintext password)
- `csv`: spreadsheet friendly rows (password masked unless `--show-secrets`)
- `yaml`: configuration pipeline friendly output (password masked unless `--show-secrets`)
- `html`: v2 report with executive summary, findings, remediation, and evidence appendix

HTML mode automatically writes a report beside the selected output path.

Passwords are masked (`a***`) in console, HTML, CSV, YAML, plain files, auto
reports, and API responses by default. Use `--show-secrets` to reveal full
values. JSON findings never contain plaintext (only `credential_ref`
`user@host:port#hash8`).

### 13.2 Encrypted output

```bash
# Encrypt output, passphrase will be prompted securely
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o secret.json -f json --encrypt

# Provide passphrase non interactively, careful with shell history
veltrix ssh -t 10.0.0.1 -U users.txt -W passwords.txt -o secret.json -f json --encrypt --encrypt-passphrase "correct horse battery staple"

# Decrypt later
veltrix --decrypt secret.json.enc --decrypt-output secret.json
```

Encryption uses AES-256-GCM with Argon2 key derivation, random salt, and random nonce.

---

## 14. Port Scanner

```bash
# Scan common ports
veltrix scan-ports -t 10.0.0.1 --ports common -o scan.txt

# Explicit list
veltrix scan-ports -t 10.0.0.1 --ports 22,80,443,3306,3389

# Range
veltrix scan-ports -t 10.0.0.1 --ports 1-1000 --scan-timeout 2 --rate 500

# Without banner grabbing
veltrix scan-ports -t 10.0.0.1 --ports common --no-banner
```

Scanner output includes host, port, open state, guessed service, banner fragment, and latency. Use it to reduce unnecessary brute force traffic.

---

## 15. Wordlist Generation, Rules, and ML

### 15.1 Target based wordlist

```bash
veltrix create -n "John Smith" -c "Acme" -d "1990-05-12" -k football -k admin --min-len 6 --max-len 24 -o ./wordlists/john.txt

# Global flag alternative
veltrix --gen-wordlist --wl-name "John Smith" --wl-company "Acme" --wl-dob "1990-05-12" --wl-keyword admin --wl-output custom.txt
```

The generator combines names, company tokens, dates, years, separators, and leet substitutions such as `a to 4`, `e to 3`, `i to 1`, `o to 0`, and `s to 5`.

### 15.2 Mutation rules

Example `rules/common.rule`:

```text
$1990
$123
@123
!2024
^admin
```

Apply rules through configuration or credential preprocessing depending on the active CLI wiring. Rules are useful for year suffixes, symbol suffixes, case changes, and common substitutions.

### 15.3 ML password prediction

```bash
# Train Markov model
veltrix --ml-train passwords.txt --ml-order 3

# Generate candidates
veltrix --ml-train passwords.txt --ml-generate 5000 --ml-output predicted.txt --ml-max-len 24

# Score existing list
veltrix --ml-train passwords.txt --ml-score candidates.txt
```

Higher order models capture longer character context but need larger training data. Always review generated candidates before use in an engagement.

---

## 16. Configuration File

Example `config/veltrix.toml`:

```toml
[veltrix]
version = "1.0"
mode = "dictionary"

[targets]
hosts = []
host_file = ""
ports = []
protocols = ["ssh", "ftp", "telnet", "smtp", "pop3", "rdp", "mysql", "http"]

[credentials]
users = []
user_file = ""
passwords = []
password_file = ""
combo_file = ""
single_user = false
spray = false

[attack]
threads = 10
timeout_sec = 10
delay_ms = 0
rate_limit = 0
retries = 1
stop_on_first = false

[proxy]
proxy_string = ""
proxy_file = ""

[output]
format = "plain"
file = ""
verbose = false
quiet = false
no_banner = false

[resume]
file = ""

[rules]
rule_file = ""
max_mutations = 100
```

JSON configuration is also supported by the config loader with strict unknown field rejection. TOML is recommended for readability.

---

## 17. Resume and Session

Attack sessions store tested combinations, successes, and checkpoint metadata.

Typical workflow:

1. Start a long attack with output and session persistence configured.
2. Press `Ctrl+C` once for graceful shutdown. Press twice to force exit.
3. Session state is written to the resume file.
4. Restart the same attack to continue from the saved checkpoint.

This is especially useful for large CIDR ranges and large password files.

---

## 18. Distributed Mode and API

### 18.1 Distributed design

```text
Coordinator
  splits target x credential space into deterministic chunks
  (chunk_id, checksum, resume_offset)
  assigns chunks, requeues on timeout/worker death, dedups by task_id
  tracks heartbeats with per-worker throughput

Worker nodes
  send Hello with run token + checkpoint hint
  request chunks, verify checksum, execute, report, checkpoint acked tasks
  send periodic heartbeats, drain active batch gracefully on stop
```

Protocol version identifier: `veltrix-dist-v2`.

```bash
# Terminal 1: coordinator (targets/creds dari flag global)
veltrix dist-coordinator --bind 127.0.0.1:5555 --dist-token SECRET \
  --chunk-size 100 -t 10.0.0.0/24 -U users.txt -W passwords.txt \
  --protocol ssh -o dist.json -f json

# Terminal 2+: workers (tiap mesin lab)
VELTRIX_DIST_TOKEN=SECRET veltrix dist-worker \
  --connect 10.0.0.100:5555 --name lab-node-1 --threads 20 \
  --checkpoint-file /tmp/vw-checkpoint.json
```

Token kadaluarsa otomatis (`--dist-token-ttl`, default 6 jam). Transport wajib
di jaringan tepercaya, idealnya WireGuard/VPN atau mTLS reverse proxy, karena
protokol JSON-lines tidak terenkripsi sendiri. Lihat status cluster di log
coordinator berkala.

Use distributed mode to scale password spraying across lab machines while keeping result aggregation centralized.

### 18.2 REST API v2 + Web UI

```bash
veltrix serve --bind 127.0.0.1:8080 --api-token SECRET
# Web UI: http://127.0.0.1:8080/ (login, jobs, live progress, stop, report, audit)
```

Auth JWT HS256: `POST /api/v2/login {"token","actor"}` lalu header
`Authorization: Bearer <JWT>` (atau `?token=` untuk websocket browser).
Rate limit 120 req/menit/IP, audit log semua login/submit/stop/akses secrets.

```bash
JWT=$(curl -s -X POST 127.0.0.1:8080/api/v2/login \
  -H 'Content-Type: application/json' \
  -d '{"token":"SECRET","actor":"alice"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Non-blocking submit -> 202 {job_id}; progres live via WS /api/v2/jobs/{id}/events
curl -s -X POST 127.0.0.1:8080/api/v2/jobs -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.5","port":22,"protocol":"ssh",
       "usernames":["admin"],"passwords":["admin123"]}'
```

Hasil masked default (`?show_secrets=1` dicatat di audit). Report JSON envelope
`veltrix-report/v2` atau HTML v2 di `/api/v2/jobs/{id}/report?format=json|html`.
Detail lengkap: `docs/api-v2.md`.

The API server has authentication and rate limiting but no TLS by default. Bind it only to localhost or a trusted management network, or place it behind a reverse proxy with TLS.

---

## 19. Plugin System

External protocol helpers can be registered as plugin binaries:

```bash
veltrix ssh -t 10.0.0.1 -u admin -W passwords.txt --plugin ./my-protocol-plugin
veltrix --list-plugin
```

Plugin behavior:

- Binary must be executable
- Plugin is validated before attack start
- Plugin protocol name is registered dynamically
- Failed validation aborts the run to avoid silent misconfiguration

To add a native protocol instead, implement the shared `Protocol` trait:

```rust
#[async_trait]
pub trait Protocol: Send + Sync {
    fn name() -> &'static str;
    fn default_port() -> u16;
    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        timeout: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult;
}
```

Then register the module in `src/protocols/mod.rs`.

---

## 20. Project Structure

```text
veltrix/
  src/
    main.rs
    cli.rs
    core/
      attack.rs
      config.rs
      config_loader.rs
      config_toml.rs
      target.rs
      cidr.rs
      credential.rs
      wordlist.rs
      rules.rs
      worker.rs
      engine.rs
      buffer.rs
      plugin.rs
      result.rs
      error.rs
    protocols/
      mod.rs
      ssh.rs, ftp.rs, telnet.rs, smtp.rs, pop3.rs, imap.rs
      rdp/, mysql/, ldap/, http_auth.rs, and 30 plus more modules
      conn.rs, tcp.rs, parser.rs
    proxy/
      mod.rs
    scanner/
      scanner.rs, banner.rs, service_db.rs
    api/
      server.rs, cloud.rs, web_ui.rs
    distributed/
      coordinator.rs, worker.rs, protocol.rs
    utils/
      output.rs, report.rs, resume.rs, ratelimit.rs,
      patterns.rs, encrypt.rs, ml_predict.rs,
      wordlist_gen.rs, crypto.rs, hash.rs
  config/
    veltrix.toml
    wordlists/
    rules/
  rules/
    common.rule
  docker/
    docker-compose.test.yml
  scripts/
    build.sh
    test.sh
  tests/
    bench.rs
  vscode-extension/
  Makefile
  Dockerfile
  install.sh
  uninstall.sh
  Cargo.toml
  PRD.md
  logo.png
```

---

## 21. Testing and Development

```bash
# Unit tests
cargo test
make test-unit

# Integration tests, requires Docker
make test-integration

# Full script: unit plus docs plus build plus integration
chmod +x scripts/test.sh
./scripts/test.sh

# Lint
make lint
cargo clippy -- -D warnings

# Format
make fmt
cargo fmt

# Benchmark
cargo bench
```

Test lab services are defined in `docker/docker-compose.test.yml`. Start them before integration testing and stop them after testing to keep the environment clean.

---

## 22. Practical Examples

```bash
# SSH audit
veltrix ssh -t 192.168.1.10 -U users.txt -W passwords.txt -x 20 -o ssh.json -f json

# FTP with custom port
veltrix ftp -t 192.168.1.11 -p 2121 -u admin -W passwords.txt

# RDP with domain
veltrix rdp -t 192.168.1.20 --rdp-domain CORP -U users.txt -W passwords.txt --stop-on-first

# MySQL
veltrix mysql -t 192.168.1.30:3306 -u root -W passwords.txt --timeout 8

# Postgres
veltrix postgres -t 192.168.1.31 -U users.txt -W passwords.txt

# HTTP form login
veltrix http -t 192.168.1.40:8080/login \
  --http-userfield username \
  --http-passfield password \
  --http-success Welcome \
  -u admin -W passwords.txt

# SMB
veltrix smb -t 192.168.1.50 -U users.txt -W passwords.txt -x 10 --delay 200

# SNMP community strings
veltrix snmp -t 192.168.1.60 -W community.txt

# Entire subnet, careful with size
veltrix ssh -t 192.168.1.0/24 -U users.txt -W top1000.txt -x 30 --rate-limit 50 -o subnet.json -f json

# Verbose debugging
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt -vv
```

---

## 23. FAQ

**Is Veltrix similar to Hydra or Medusa?**
Yes in purpose, but Veltrix is a single Rust binary with async execution, unified reporting, scanner integration, wordlist and ML helpers, proxy chaining, encryption, API mode, and distributed mode in one repository.

**Does it support resume?**
Yes, session checkpoints allow long attacks to continue after interruption.

**Can I add a new protocol?**
Yes. Implement the `Protocol` trait, add default port handling, register it in the protocol registry, add CLI wiring, and add unit tests.

**Why is my attack slow?**
Common causes are low thread count, high delay, strict rate limit, high timeout on filtered ports, DNS failures, or proxy latency. Scan ports first and tune the three main knobs: threads, timeout, and rate limit.

**Why do I get lockouts?**
The target may enforce account lockout. Reduce threads, add delay, enable rate limiting, test fewer accounts, use `--stop-on-first`, and obtain explicit permission for lockout sensitive systems.

**Is the API secure?**
The built in API is minimal and intended for local automation. Do not expose it directly to untrusted networks without authentication and TLS termination in front of it.

---

## 24. Disclaimer and Legal Notice

### 24.1 Authorized use only

Veltrix is designed for:

- Testing systems you own
- Testing systems you administer
- Contracted penetration testing with written authorization
- Academic research in isolated labs
- CTF competitions and training environments

Do **not** use Veltrix against systems without explicit permission. Unauthorized access, credential guessing, network scanning, and service disruption may violate criminal law, computer misuse law, employment agreements, and service provider terms.

### 24.2 Responsibility

- You are solely responsible for how you use this software.
- You must obtain written authorization before testing third party systems.
- You must respect scope, time windows, rate limits, and data handling rules defined by the asset owner.
- You must stop testing immediately if you cause unexpected degradation, lockouts, or data exposure.
- The authors and contributors provide this software without warranty and accept no liability for misuse, damage, or legal consequences.

### 24.3 Operational recommendations

- Prefer test and staging environments before production.
- Coordinate with system owners and SOC teams when applicable.
- Use conservative threads, delay, and rate limits on production like assets.
- Protect output files because they may contain valid credentials.
- Encrypt reports, limit distribution, rotate exposed credentials after testing, and delete sensitive artifacts when no longer needed.
- Do not commit real passwords, combo files, customer data, tokens, or private keys to version control.

If you are unsure whether an action is permitted, assume it is **not permitted** until you receive clear written approval.

---

## 25. License and Credits

- Package name: `veltrix`
- Current version: `2.0.0` (single source: `Cargo.toml`; CLI/banner/man mengikuti otomatis)
- Author: `aniippxploit`
- Description: Multi-protocol brute force toolkit for security professionals

Check the repository for license files and contribution guidelines. If no separate license file is present, contact the author before commercial redistribution.

Included logo file:

```text
logo.png
```

Use it for documentation, presentation, and project pages. Keep its aspect ratio and avoid stretching or recoloring it in official materials.

---

<p align="center">
  Built with Rust for speed, safety, and extensibility.<br />
  Use responsibly and only with authorization.
</p>
