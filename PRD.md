# Veltrix — Product Requirements Document (PRD)

> **Versi:** 3.0  
> **Status:** Final (Updated with actual implementation audit)  
> **Penulis:** aniippxploit  
> **Tech Stack:** Rust (100%) — Async, Multi-threaded, Modular Architecture  
> **Target Rilis:** v1.1 (Hardening) → v1.2 (Advanced) → v2.0 (Enterprise)

---

## Daftar Isi

1. [Executive Summary](#1-executive-summary)
2. [Fitur & Spesifikasi](#2-fitur--spesifikasi)
3. [Arsitektur Sistem](#3-arsitektur-sistem)
4. [Module Reference & Implementation Status](#4-module-reference--implementation-status)
5. [Protocol Implementation Guide](#5-protocol-implementation-guide)
6. [CLI Specification](#6-cli-specification)
7. [Error Handling & Edge Cases](#7-error-handling--edge-cases)
8. [Performance Targets & Benchmarks](#8-performance-targets--benchmarks)
9. [Testing Strategy](#9-testing-strategy)
10. [Development Workflow](#10-development-workflow)
11. [Security & Compliance](#11-security--compliance)
12. [Roadmap & Milestones](#12-roadmap--milestones)
13. [Code Audit: Known Issues & Technical Debt](#13-code-audit-known-issues--technical-debt)
14. [Appendix](#14-appendix)

---

## 1. Executive Summary

### 1.1 Vision

**Veltrix** adalah *multi-protocol brute force toolkit* generasi baru yang ditulis 100% dalam **Rust**. Dirancang untuk menjadi standar industri dalam pengujian kredensial — menggabungkan performa native, keamanan memory Rust, kemudahan distribusi single-binary, dan arsitektur modular yang ekstensibel.

### 1.2 Positioning

| Aspek | Veltrix | Hydra | Medusa | Crowbar | Ncrack |
|-------|---------|-------|--------|---------|--------|
| Bahasa | Rust | C | C | Python | C |
| Memory Safety | ✅ (compile-time) | ❌ | ❌ | ❌ | ❌ |
| Async I/O | ✅ Tokio | ❌ blocking | ❌ blocking | ❌ blocking | ❌ blocking |
| Single Binary | ✅ (~8MB) | ❌ | ❌ | ❌ (script) | ❌ |
| Cross-platform | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ekosistem Modern | ✅ crate.io | ❌ | ❌ | ❌ | ❌ |

### 1.3 Target Persona

| Persona | Use Case | Pain Point | Veltrix Solution |
|---------|----------|------------|------------------|
| Penetration Tester | Validasi kredensial client | Tools lambat, instalasi ribet | Single binary, async perf |
| Red Team | Credential spraying skala besar | Sumber daya terbatas | Multi-threaded, memori efisien |
| Security Auditor | Assessment kebijakan password | Report tidak terstruktur | JSON/CSV/HTML output, audit trail |
| SysAdmin | Test password internal | Tool terlalu agresif | Rate limiting, delay config |
| Security Researcher | Riset brute force methods | Sulit ekstensi | Trait-based plugin system |

---

## 2. Fitur & Spesifikasi

### 2.1 Protocol Support Matrix

| # | Protocol | Port Default | Auth Methods | Library | TLS/SSL | Proxy | Priority | Status |
|---|----------|-------------|--------------|---------|---------|-------|----------|--------|
| 1 | SSH | 22 | password, key-based | `ssh2` | - | ❌ | P0 | ✅ Done |
| 2 | FTP | 21 | plain | `suppaftp` | ❌ FTPS | ❌ | P0 | ✅ Done |
| 3 | Telnet | 23 | plaintext | raw TCP | - | ✅ | P0 | ✅ Done |
| 4 | SMTP | 25, 465, 587 | LOGIN, PLAIN, CRAM-MD5 | `lettre` | ✅ STARTTLS | ❌ | P0 | ✅ Done |
| 5 | POP3 | 110, 995 | USER/PASS | raw TCP | ❌ STLS | ✅ | P0 | ✅ Done |
| 6 | RDP | 3389 | NLA (CredSSP/NTLMv2) | raw TCP + TLS | - | ✅ | P0 | ✅ Done (Full) |
| 7 | MySQL | 3306 | mysql_native_password | `mysql_async` | ✅ TLS | ❌ | P0 | ✅ Done |
| 8 | HTTP | 80, 443 | Basic, Form | `reqwest` | ✅ HTTPS | ✅ | P0 | ✅ Done |
| 9 | PostgreSQL | 5432 | md5, password | `tokio-postgres` | ✅ TLS | - | P1 | ⏳ Planned |
| 10 | LDAP | 389, 636 | Simple, SASL | `ldap3` | ✅ STARTTLS | - | P1 | ⏳ Planned |
| 11 | Redis | 6379 | AUTH | `redis` | - | - | P1 | ⏳ Planned |
| 12 | SMB | 445 | NTLMv1/v2 | TBD | - | - | P2 | ⏳ Planned |
| 13 | SNMP | 161 | community strings | TBD | - | - | P2 | ⏳ Planned |
| 14 | VNC | 5900 | VNC Auth | TBD | - | - | P2 | ⏳ Planned |
| 15 | MSSQL | 1433 | SQL Server Auth | `tiberius` | ✅ TLS | - | P2 | ⏳ Planned |
| 16 | MongoDB | 27017 | SCRAM-SHA-1 | `mongodb` | ✅ TLS | - | P2 | ⏳ Planned |
| 17 | IMAP | 143, 993 | LOGIN, PLAIN | `async-imap` | ✅ STARTTLS | - | P2 | ⏳ Planned |

> **Catatan Proxy:** SSH, FTP, SMTP, dan MySQL belum mendukung proxy — parameter `_proxy` diabaikan di implementasi. Ini adalah PRIORITAS TINGGI untuk diperbaiki.

> **Catatan RDP:** Implementasi RDP saat ini SUDAH FULL NLA/CredSSP — bukan hanya connection check. Termasuk NTLM hash (MD4), NTLMv2 hash (HMAC-SHA256), NTLMSSP Negotiate/Challenge/Authenticate, CredSSP TSRequest ASN.1 encoding, TLS tunneling.

### 2.2 Attack Modes Detail

#### Mode A: Dictionary Attack (Cartesian Product)
```
User file: [admin, root, user1]
Pass file: [123456, password, admin]

Combinations:
  admin:123456   admin:password   admin:admin
  root:123456    root:password    root:admin
  user1:123456   user1:password   user1:admin
```

#### Mode B: Single User Mode
```
User file: [admin]
Pass file: [123456, password, admin, qwerty]

Combinations:
  admin:123456   admin:password   admin:admin   admin:qwerty
```

#### Mode C: Combo List
```
File combo.txt:
  admin:123456
  root:password
  user1:admin123
```

#### Mode D: Credential Spraying (Optimasi anti-lockout)
```
Password: "Welcome2024!"
Users: [admin, root, user1, operator]

Attempt order:
  admin:Welcome2024! → root:Welcome2024! → user1:Welcome2024! → operator:Welcome2024!
  admin:Spring2024! → root:Spring2024! → ...

Mode ini mencegah account lockout dengan rotasi user per password.
```

#### Mode E: Hybrid Attack (Rule-Based Mutation) — ✅ Implemented
```
Rule: append tahun umum
  password → password2023, password2024, password2025

Rule: capitalize
  admin → Admin, ADMIN

Rule: leet speak
  password → p@ssword, p@$$w0rd

Rule operations implemented:
  $N     → Append number (e.g., $2024 → "password2024")
  ^N     → Prepend number (e.g., ^2024 → "2024password")
  @str   → Append string (e.g., @! → "password!")
  !str   → Prepend string (e.g., !admin → "adminpassword")
  ~N     → Capitalize (0=lowercase, 1=UPPERCASE, 2=Title Case)
  &a:b   → Leet speak substitution (e.g., &a:@ → "p@ssword")
```

### 2.3 Target Input Format

| Format | Contoh | Deskripsi | Status |
|--------|--------|-----------|--------|
| `host:port` | `192.168.1.1:22` | Explicit port untuk protocol | ✅ Done |
| `host` | `10.0.0.5` | Auto-detect port berdasarkan protocol | ✅ Done |
| `host:port:protocol` | `10.0.0.5:3389:rdp` | Override protocol | ✅ Done |
| CIDR | `192.168.1.0/24` | Range IP (network/broadcast excluded for </31) | ✅ Done |
| Range | `192.168.1.1-100` | Sequential IP | ✅ Done |
| IPv6 | `[::1]:8080` | IPv6 dengan port | ✅ Done |

### 2.4 Output Format Specification

#### JSON Output Schema
```json
{
  "veltrix_version": "1.0.0",
  "attack_id": "uuid-v4",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-01T01:00:00Z",
  "config": {
    "targets_count": 5,
    "credentials_count": 1000,
    "protocols": ["ssh", "ftp"],
    "threads": 20,
    "timeout_sec": 10
  },
  "summary": {
    "total_attempts": 5000,
    "successes": 3,
    "failures": 4997,
    "errors": 0
  },
  "results": [
    {
      "target": "192.168.1.1",
      "port": 22,
      "protocol": "ssh",
      "username": "admin",
      "password": "123456",
      "success": true,
      "timestamp": "2024-01-01T00:05:23Z",
      "duration_ms": 1250,
      "error": null
    }
  ]
}
```

#### CSV Output Format
```csv
target,port,protocol,username,password,success,timestamp,duration_ms,error
192.168.1.1,22,ssh,admin,123456,true,2024-01-01T00:05:23Z,1250,
192.168.1.1,22,ssh,admin,password,false,2024-01-01T00:05:24Z,1100,
```

#### HTML Report — ✅ Code exists but NOT WIRED into orchestrator
HTML report generator dengan dark theme (GitHub-style), summary stats grid, tabel successes/failures, metadata footer. Perlu diintegrasikan ke AttackOrchestrator.

#### Session/Resume JSON
```json
{
  "version": 1,
  "attack_id": "uuid",
  "targets": ["192.168.1.1:22"],
  "protocols": ["ssh"],
  "combos_tested": ["admin:123456", "admin:password"],
  "successes": [
    {"target": "192.168.1.1:22", "protocol": "ssh", "username": "admin", "password": "123456"}
  ],
  "total_attempts": 250,
  "checkpoint_interval": 100
}
```

### 2.5 Proxy Configuration

#### Format Syntax
```
# Single proxy
--proxy socks5://127.0.0.1:9050
--proxy http://user:pass@proxy.example.com:8080

# Proxy file (rotation otomatis)
--proxy-file proxies.txt
```

#### Proxy File Format
```
# Format: type://[user:pass@]host:port
socks5://127.0.0.1:9050
socks4://10.0.0.1:1080
http://user1:pass1@proxy.example.com:8080
http://proxy2.example.com:3128
```

#### Rotasi Strategy
```
Worker 0 → proxy[0]
Worker 1 → proxy[1]
Worker 2 → proxy[2]
Worker 3 → proxy[0]  (wrap around)
Worker 4 → proxy[1]
...
```

#### Proxy Support per Protocol
| Protocol | Proxy Support | Implementation |
|----------|--------------|----------------|
| Telnet | ✅ | Raw TCP through proxy tunnel |
| POP3 | ✅ | Raw TCP through proxy tunnel |
| RDP | ✅ | TCP + TLS through proxy tunnel |
| HTTP | ✅ | reqwest proxy adapter |
| SSH | ❌ | Connects directly via TcpStream |
| FTP | ❌ | Connects directly via suppaftp |
| SMTP | ❌ | Connects directly via lettre |
| MySQL | ❌ | Connects directly via mysql_async |

### 2.6 Configuration File (veltrix.json)

Veltrix mendukung JSON config file dengan merge priority:
```
1. CLI arguments (highest priority)
2. Config file (medium priority)
3. Built-in defaults (lowest priority)

CLI arguments ALWAYS override config file values.
Config file is specified via --config <path>.
```

#### JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft-07/schema",
  "$id": "https://veltrix.dev/config-schema.json",
  "title": "Veltrix Configuration",
  "type": "object",
  "properties": {
    "attack": {
      "type": "object",
      "properties": {
        "targets": { "type": "array", "items": { "type": "string" } },
        "target_file": { "type": "string" },
        "protocols": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
        "ports": { "type": "array", "items": { "type": "integer", "minimum": 1, "maximum": 65535 } }
      },
      "required": ["protocols"]
    },
    "credentials": {
      "type": "object",
      "oneOf": [
        { "required": ["user_file", "password_file"] },
        { "required": ["combo_file"] },
        { "required": ["users", "passwords"] }
      ],
      "properties": {
        "users": { "type": "array", "items": { "type": "string" } },
        "passwords": { "type": "array", "items": { "type": "string" } },
        "user_file": { "type": "string" },
        "password_file": { "type": "string" },
        "combo_file": { "type": "string" },
        "single_user": { "type": "boolean", "default": false },
        "spray": { "type": "boolean", "default": false }
      }
    },
    "hybrid": {
      "type": "object",
      "properties": {
        "rules": { "type": "string", "description": "Path to rules file" },
        "max_mutations": { "type": "integer", "minimum": 1, "default": 5 }
      }
    },
    "performance": {
      "type": "object",
      "properties": {
        "threads": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 10 },
        "timeout": { "type": "integer", "minimum": 1, "default": 10 },
        "delay": { "type": "integer", "minimum": 0, "default": 0 },
        "rate_limit": { "type": "integer", "minimum": 0 },
        "retries": { "type": "integer", "minimum": 0, "maximum": 10, "default": 1 }
      }
    },
    "proxy": {
      "type": "object",
      "properties": {
        "proxy": { "type": "string" },
        "proxy_file": { "type": "string" }
      }
    },
    "output": {
      "type": "object",
      "properties": {
        "file": { "type": "string" },
        "format": { "type": "string", "enum": ["plain", "json", "csv", "html"], "default": "plain" },
        "resume": { "type": "string" }
      }
    },
    "behavior": {
      "type": "object",
      "properties": {
        "stop_on_first": { "type": "boolean", "default": false },
        "verbose": { "type": "boolean", "default": false },
        "quiet": { "type": "boolean", "default": false },
        "no_banner": { "type": "boolean", "default": false }
      }
    }
  },
  "required": ["attack", "credentials"]
}
```

> **Catatan:** `config/veltrix.toml` yang ada saat ini adalah TOML tapi `config_loader.rs` hanya support JSON. Perlu dikonversi atau ditambahkan parser TOML.

---

## 3. Arsitektur Sistem

### 3.1 Layer Architecture (Layered View)

```
┌──────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                       CLI (clap)                         │   │
│  │  Arguments Parsing │ Validation │ Help │ Banner │ Color  │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│                         APPLICATION LAYER                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Attack Orchestrator                    │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│  │  │ Target   │ │Credential│ │   Rate   │ │  Resume  │   │   │
│  │  │ Manager  │ │ Manager  │ │ Limiter  │ │ Manager  │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│                         DOMAIN LAYER                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Protocol Registry                      │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ │   │
│  │  │ SSH  │ │ FTP  │ │Telnet│ │ SMTP │ │ POP3 │ │ RDP  │ │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐          │   │
│  │  │MySQL │ │ HTTP │ │  PG  │ │ LDAP │ │ SMB  │ ...      │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘          │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────┐
│                        INFRASTRUCTURE LAYER                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐  │
│  │  Proxy   │ │  Output  │ │Progress  │ │  Logger  │ │ DNS  │  │
│  │ Manager  │ │Formatter │ │  Bar     │ │          │ │Resolver│  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────┘  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │             Tokio Async Runtime (multi-threaded)          │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Dependency Graph

```
main.rs
  ├── cli.rs → config::AttackConfig
  ├── core/
  │   ├── config.rs           (no deps on other modules)
  │   ├── config_loader.rs    (JSON config deserialization)
  │   ├── target.rs           (no deps on other modules)
  │   ├── credential.rs       (no deps on other modules)
  │   ├── result.rs           (no deps on other modules)
  │   ├── wordlist.rs         (no deps on other modules)
  │   ├── cidr.rs             (no deps on other modules)
  │   ├── rules.rs            (no deps on other modules)
  │   ├── error.rs            (DEAD CODE — never used)
  │   ├── worker.rs           (depends on protocols, utils/patterns, proxy)
  │   └── attack.rs →         (depends on all core + protocols + utils + proxy)
  │       ├── target.rs, credential.rs, result.rs, wordlist.rs
  │       ├── config.rs, cidr.rs, rules.rs
  │       ├── protocols/      (trait + implementations)
  │       ├── proxy/
  │       └── utils/
  ├── protocols/
  │   ├── mod.rs →            (Protocol trait, factory registry)
  │   ├── ssh.rs →            (impl Protocol — NO proxy)
  │   ├── ftp.rs →            (impl Protocol — NO proxy, NO TLS)
  │   ├── telnet.rs →         (impl Protocol — FULL)
  │   ├── smtp.rs →           (impl Protocol — NO proxy)
  │   ├── pop3.rs →           (impl Protocol — PROXY OK, NO TLS)
  │   ├── rdp.rs →            (impl Protocol — FULL NLA/CredSSP)
  │   ├── mysql.rs →          (impl Protocol — NO proxy)
  │   └── http.rs →           (impl Protocol — FULL)
  ├── proxy/
  │   └── mod.rs              (full SOCKS4/5, HTTP CONNECT)
  └── utils/
      ├── ratelimit.rs        (token bucket + jitter)
      ├── resume.rs           (session save/load)
      ├── output.rs           (JSON/CSV/plain + progress bar)
      ├── patterns.rs         (error classification + backoff)
      └── report.rs           (HTML report generator — DEAD CODE)
```

### 3.3 Data Flow — Attack Lifecycle State Machine

```
                    ┌─────────┐
                    │  START  │
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │  Parse  │
                    │  CLI    │
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │Validate │
                    │ Config  │
                    └────┬────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         ┌────▼────┐          ┌────▼────┐
         │  Load   │          │  List   │
         │Wordlists│          │Protocols│
         └────┬────┘          └────┬────┘
              │   ┌─────────┐      │
              │   │  Load   │     EXIT
              │   │ Targets │
              │   └────┬────┘
              │        │
              │   ┌────▼────┐
              │   │ Resolve │
              │   │   DNS   │
              │   └────┬────┘
              │        │
         ┌────▼─────────▼────┐
         │  Initialize       │
         │  Orchestrator     │
         └────┬──────────┬───┘
              │          │
         ┌────▼────┐ ┌───▼──────┐
         │   No   │ │   Yes    │
         │ Resume │ │  Resume  │
         └────┬────┘ │  State   │
              │      └───┬──────┘
              │          │
         ┌────▼──────────▼───┐
         │  Create Task Queue │
         │  (target × cred)   │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  Launch Worker Pool│
         │  (tokio tasks)     │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  ┌──────────────┐  │
         │  │   Worker 1   │  │
         │  │ Authenticate │  │
         │  └──────┬───────┘  │
         │  ┌──────────────┐  │
         │  │   Worker 2   │  │
         │  │ Authenticate │  │
         │  └──────┬───────┘  │
         │  ┌──────────────┐  │
         │  │   Worker N   │  │
         │  │ Authenticate │  │
         │  └──────┬───────┘  │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  Process Results   │
         │  Display + Save    │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  Checkpoint Save   │
         │  (configurable N)  │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  Generate Summary  │
         │  + HTML Report     │
         └────────┬───────────┘
                  │
              ┌───▼────┐
              │  EXIT  │
              └────────┘
```

### 3.4 Concurrency Model Detail

```
                     ┌──────────────────┐
                     │  Task Generator  │
                     │  target×cred     │
                     └────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Channel (mpsc)  │
                    │   buffer: 10000   │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
        │  Worker 1 │  │  Worker 2 │  │  Worker N │
        │  tokio    │  │  tokio    │  │  tokio    │
        │  task     │  │  task     │  │  task     │
        │           │  │           │  │           │
        │  Semaphore│  │  Semaphore│  │  Semaphore│
        │  acquire  │  │  acquire  │  │  acquire  │
        │           │  │           │  │           │
        │  Rate     │  │  Rate     │  │  Rate     │
        │  Limiter  │  │  Limiter  │  │  Limiter  │
        │           │  │           │  │           │
        │  Auth()   │  │  Auth()   │  │  Auth()   │
        │  Retry    │  │  Retry    │  │  Retry    │
        │  Backoff  │  │  Backoff  │  │  Backoff  │
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │               │               │
              └───────┬───────┴───────┬───────┘
                      │               │
                ┌─────▼─────┐   ┌─────▼─────┐
                │  Result   │   │  Result   │
                │  Stream   │   │  Handler  │
                │(Futures   │   │(Display+  │
                │Unordered) │   │  Save)    │
                └───────────┘   └───────────┘
```

### 3.5 Module Interface Contracts

#### Protocol Trait (Contract)
```rust
#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult;
}
```

#### AuthResult Contract
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub r#type: String,  // ⚠️ Currently always empty — needs population
}
```

#### AttackConfig Contract
```rust
pub struct AttackConfig {
    pub targets: Vec<String>,
    pub target_file: Option<PathBuf>,
    pub users: Vec<String>,
    pub passwords: Vec<String>,
    pub user_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub combo_file: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub threads: usize,
    pub timeout: Duration,
    pub delay: Duration,
    pub rate_limit: Option<u64>,
    pub retries: u32,
    pub single_user_mode: bool,
    pub spray_mode: bool,
    pub rule_file: Option<PathBuf>,
    pub max_mutations: usize,
    pub proxy: Option<String>,
    pub proxy_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub resume_file: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub stop_on_first: bool,
    pub verbose: bool,
    pub quiet: bool,
    pub no_banner: bool,
    pub checkpoint_interval: u64,
}
```

---

## 4. Module Reference & Implementation Status

### 4.1 `src/main.rs` — Entry Point (64 LOC) ✅ 100%
```
Flow:
1. Initialize env_logger
2. Parse CLI args via clap
3. If --list-protocols, print & exit
4. Print banner (unless --no-banner)
5. Convert args → AttackConfig (with optional config file merge)
6. SIGINT handler: first Ctrl+C = graceful stop, second = force exit
7. Create AttackOrchestrator::new(config)
8. Run orchestrator.run()
9. Exit with status 0 if any success, 1 otherwise
```

### 4.2 `src/cli.rs` — CLI Argument Parser (296 LOC) ✅ 95%
- **Library**: `clap` v4 (derive API)
- **All flags implemented**: `-t/-T`, `-p`, `-P/-L`, `-u/-U`, `-w/-W`, `-C`, `--single-user`, `--spray`, `--rules`, `--max-mutations`, `-x`, `--timeout`, `--delay`, `--rate-limit`, `--retries`, `--proxy`, `--proxy-file`, `-o`, `-f`, `--resume`, `--config`, `--stop-on-first`, `-v`, `-q`, `--no-banner`, `-h`
- **Missing**: `-V/--version` flag
- **Validation**: `into_config()` validates targets, protocols, credentials, combo exclusivity

### 4.3 `src/core/attack.rs` — Attack Orchestrator (365 LOC) ✅ 100%
```
State: config, targets, credentials, proxies, results, session, output, rate_limit, jitter

Methods:
  new(config)           → Load all resources, init state
  run()                 → Main loop: queue → workers → results
  load_targets()        → Parse + CIDR expand + DNS resolve (concurrent via join_all)
  load_credentials()    → Load wordlists + combos + apply rules mutations
  load_proxies()        → Load proxy configs from CLI arg or file
  get_proxy_for(index)  → Round-robin proxy selection
```

### 4.4 `src/core/config.rs` — Configuration (86 LOC) ✅ 100%
`AttackConfig` struct with all fields. `OutputFormat` enum (Json/Csv/Plain) with `from_str()`. `validate()` checks for missing targets, protocols, credentials.

### 4.5 `src/core/config_loader.rs` — JSON Config Loader (266 LOC) ✅ 100%
Full serde deserialization with `#[serde(deny_unknown_fields)]`. Sections: Attack, Credentials, Hybrid, Performance, Proxy, Output, Behavior. `merge_into()` applies config values over CLI defaults.

### 4.6 `src/core/cidr.rs` — CIDR/IP Range Parser (217 LOC) ✅ 100%
`TargetSpec` enum (Single, Cidr, Range). Parses CIDR (`192.168.1.0/24`), ranges (`10.0.0.1-10`), single hosts with port. `expand_cidr()` handles /31 and /32 correctly. **9 unit tests.**

### 4.7 `src/core/credential.rs` — Credential Struct (88 LOC) ✅ 100%
`Credential` struct, `parse_combo_line()` for `user:pass` parsing (handles colons in passwords). **8 unit tests.**

### 4.8 `src/core/result.rs` — AuthResult + AttackSummary (155 LOC) ✅ 100%
`AuthResult` with all fields, `AttackSummary` with counts. Colored display formatting. **5 unit tests.**

### 4.9 `src/core/error.rs` — AttackError Enum (49 LOC) ❌ DEAD CODE
`AttackError` enum with 10 variants (Config, Io, Dns, Protocol, Auth, Lockout, RateLimited, Timeout, Wordlist, Session, Internal). Full `Display` + `Error` impl. **NEVER USED** — seluruh aplikasi masih menggunakan `Result<_, String>`.

### 4.10 `src/core/wordlist.rs` — Wordlist Loader (129 LOC) ⚠️ 90%
Async wordlist loader via `tokio::io::AsyncBufReadExt`. `load_wordlist()` skips empty/comment lines. `load_combo_list()` for user:pass pairs. `StreamingWordlist` exists but `load_chunk()` loads everything at once — not truly streaming. **3 tokio tests.**

### 4.11 `src/core/worker.rs` — Worker Pool (172 LOC) ✅ 100%
Tokio `Semaphore`-based concurrency control. Each task: acquire permit → check skip list → lookup protocol → retry with exponential backoff (from `patterns::compute_backoff`) → account lockout detection (skip user) → proxy rotation on rate limit → `FuturesUnordered` collection with early stop.

### 4.12 `src/core/rules.rs` — Password Mutation Engine (234 LOC) ✅ 100%
`RuleOp` enum: AppendNumber, PrependNumber, AppendString, PrependString, Capitalize (0=lower, 1=upper, 2=title), LeetSpeak. Rule parsing from file (token format documented in §2.2 Mode E). `apply_rules()` with max_mutations truncation. **11 unit tests.**

### 4.13 `src/protocols/mod.rs` — Protocol Registry (137 LOC) ✅ 100%
`Protocol` trait definition. Factory function `get_protocol()` with 8 protocols. `default_ports_for_protocols()` with dedup. `list_protocols()`. **12 unit tests.**

### 4.14 `src/proxy/mod.rs` — Proxy Manager (539 LOC) ✅ 100%
`ProxyConfig` enum: Http/Http CONNECT (HTTPS), Socks4, Socks5, None. Full TCP tunnel implementations: HTTP CONNECT with Proxy-Authorization, SOCKS5 with optional username/password auth, SOCKS4 with optional userid. Custom base64 encoder. `to_reqwest_proxy()` for HTTP protocol. Proxy list loader. **11 unit tests.**

### 4.15 Protocol Implementations

| File | LOC | Status | Proxy | TLS | Notes |
|------|-----|--------|-------|-----|-------|
| `ssh.rs` | 100 | ✅ 95% | ❌ | - | `_proxy` unused; via `spawn_blocking` + libssh2 |
| `ftp.rs` | 91 | ✅ 90% | ❌ | ❌ | `_proxy` unused; suppaftp sync |
| `telnet.rs` | 133 | ✅ 100% | ✅ | - | IAC negotiation, login/password prompt |
| `smtp.rs` | 113 | ✅ 90% | ❌ | ✅ | `_proxy` unused; lettre STARTTLS |
| `pop3.rs` | 97 | ✅ 95% | ✅ | ❌ | USER/PASS raw TCP; STLS missing |
| `rdp.rs` | 539 | ✅ 100% | ✅ | ✅ | **Full NLA/CredSSP**: NTLMv2, CredSSP TSRequest, ASN.1 |
| `mysql.rs` | 75 | ✅ 95% | ❌ | ✅ | `_proxy` unused; mysql_async |
| `http.rs` | 156 | ✅ 100% | ✅ | ✅ | Basic + Form auth; reqwest proxy-aware |

### 4.16 Utility Modules

| File | LOC | Status | Tests | Notes |
|------|-----|--------|-------|-------|
| `ratelimit.rs` | 108 | ✅ 100% | 6 | Token-bucket algorithm + jitter |
| `resume.rs` | 153 | ✅ 100% | 3 | Session save/load, checkpoint tracking |
| `output.rs` | 149 | ✅ 100% | 0 | JSON/CSV/plain + indicatif progress bar |
| `patterns.rs` | 253 | ✅ 100% | 13 | Error classification, backoff computation |
| `report.rs` | 106 | ❌ DEAD CODE | 0 | HTML report generator — never called |

---

## 5. Protocol Implementation Guide

### 5.1 SSH Protocol (`src/protocols/ssh.rs`)

```rust
pub struct SshProtocol;

impl Protocol for SshProtocol {
    fn name(&self) -> &'static str { "ssh" }
    fn default_port(&self) -> u16 { 22 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ⚠️ proxy parameter is UNUSED — needs fix
        // 1. TCP connect ke target:port dengan timeout (TcpStream::connect_timeout)
        // 2. Buat SSH session via libssh2 (blocking dalam spawn_blocking)
        // 3. Session handshake
        // 4. userauth_password()
        // 5. Return AuthResult
        // Note: ssh2 library adalah C binding, jalankan di spawn_blocking
    }
}
```

**Error Handling:**
- Connection refused → `AuthResult { success: false, error: "Connection refused" }`
- Auth failed → `AuthResult { success: false, error: None }` (normal fail)
- Timeout → `AuthResult { success: false, error: "Timeout" }`
- SSH protocol error → `AuthResult { success: false, error: "SSH error: ..." }`

**Proxy Implementation Plan:** Gunakan proxy tunnel untuk TCP connection sebelum diserahkan ke ssh2 session.

### 5.2 FTP Protocol (`src/protocols/ftp.rs`)

```rust
pub struct FtpProtocol;

impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str { "ftp" }
    fn default_port(&self) -> u16 { 21 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ⚠️ proxy parameter UNUSED, TLS/SSL NOT IMPLEMENTED
        // 1. Connect via suppaftp FtpStream
        // 2. Login dengan credentials
        // 3. QUIT jika success
        // Note: suppaftp sync, jalankan di spawn_blocking
    }
}
```

### 5.3 Telnet Protocol (`src/protocols/telnet.rs`)

```rust
pub struct TelnetProtocol;

impl Protocol for TelnetProtocol {
    fn name(&self) -> &'static str { "telnet" }
    fn default_port(&self) -> u16 { 23 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ✅ Full implementation with proxy support
        // 1. TCP connect (via proxy tunnel if configured)
        // 2. Handle telnet negotiation (IAC WILL/WONT/DO/DONT)
        //    - Respond WONT to all DO requests
        //    - Respond DONT to all WILL requests
        // 3. Wait for login: prompt
        // 4. Send username + \r\n
        // 5. Wait for password: prompt
        // 6. Send password + \r\n
        // 7. Check response for success/failure keywords
    }
}
```

**Telnet Negotiation Matrix:**
| Received | Response | Meaning |
|----------|----------|---------|
| IAC DO ECHO | IAC WONT ECHO | Refuse echo |
| IAC DO SUPRESS_GA | IAC WONT SUPRESS_GA | Refuse |
| IAC WILL ECHO | IAC DONT ECHO | Don't allow |
| IAC WILL TERMINAL_TYPE | IAC DONT | Don't care |

### 5.4 SMTP Protocol (`src/protocols/smtp.rs`)

```rust
pub struct SmtpProtocol;

impl Protocol for SmtpProtocol {
    fn name(&self) -> &'static str { "smtp" }
    fn default_port(&self) -> u16 { 25 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ⚠️ proxy parameter UNUSED
        // 1. Build dummy email message via lettre
        // 2. Choose transport:
        //    - port 465 → starttls_relay()
        //    - port 25  → relay()
        //    - port 587 → starttls_relay()
        // 3. Set credentials, port, timeout
        // 4. transport.send(&email)
        // 5. Check result for auth failure
    }
}
```

### 5.5 POP3 Protocol (`src/protocols/pop3.rs`)

```rust
pub struct Pop3Protocol;

impl Protocol for Pop3Protocol {
    fn name(&self) -> &'static str { "pop3" }
    fn default_port(&self) -> u16 { 110 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ✅ Proxy supported, but STLS/TLS NOT implemented
        // 1. TCP connect (via proxy tunnel if configured)
        // 2. Read banner (must start with +OK)
        // 3. Send: USER <username>\r\n
        // 4. Read response (must be +OK)
        // 5. Send: PASS <password>\r\n
        // 6. Read response: +OK → success, -ERR → failure
        // 7. Send QUIT
    }
}
```

### 5.6 RDP Protocol (`src/protocols/rdp.rs`) — 539 LOC Full Implementation

```rust
pub struct RdpProtocol;

impl Protocol for RdpProtocol {
    fn name(&self) -> &'static str { "rdp" }
    fn default_port(&self) -> u16 { 3389 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ✅ FULL NLA/CredSSP IMPLEMENTATION
        //
        // RDP Authentication Flow:
        // 1. TCP connect (via proxy tunnel if configured)
        // 2. RDP Negotiation Request/Response (connection init)
        // 3. TLS handshake (tokio-native-tls, accept invalid certs)
        // 4. NTLMSSP Negotiate → server Challenge → NTLMv2 Authenticate
        //    - NTLM hash: MD4(password)
        //    - NTLMv2 hash: HMAC-MD5(MD4(password), user + domain)
        //    - Challenge: 8 bytes from server
        //    - Authenticate: HMAC-SHA256 with client nonce, timestamp
        // 5. CredSSP TSRequest wrapping:
        //    - ASN.1 encoding (sequence, octet string, context tags)
        //    - Encrypt with TLS session
        // 6. Parse server response for success/failure
    }
}
```

**Implementation Details:**
- Uses `md4`, `hmac`, `sha2`, `rand` crates for cryptographic operations
- Custom ASN.1 encoder for CredSSP TSRequest (no external dep)
- Empty domain used for authentication
- Success detection via server response analysis

### 5.7 MySQL Protocol (`src/protocols/mysql.rs`)

```rust
pub struct MySqlProtocol;

impl Protocol for MySqlProtocol {
    fn name(&self) -> &'static str { "mysql" }
    fn default_port(&self) -> u16 { 3306 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ⚠️ proxy parameter UNUSED
        // 1. Buat OptsBuilder dengan host, port, user, pass
        // 2. SSL opts with domain validation bypass
        // 3. Create Pool, get_conn()
        // 4. If success → query "SELECT 1" → auth success
        // 5. Error "Access denied"/"1045" → auth fail
        // 6. Disconnect pool
    }
}
```

### 5.8 HTTP Protocol (`src/protocols/http.rs`)

```rust
pub struct HttpProtocol;

impl Protocol for HttpProtocol {
    fn name(&self) -> &'static str { "http" }
    fn default_port(&self) -> u16 { 80 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // ✅ Full implementation with proxy support
        //
        // Two modes:
        // 1. http-basic: GET with Basic Auth header
        //    - Success: 200, 204, 301, 302, 304
        //    - Failure: 401, 403
        //
        // 2. http-form: POST with form data
        //    - Username/password fields sent as form params
        //    - Success: body contains success keywords or no error keywords
        //    - Failure: body contains "invalid", "incorrect", etc.
        //
        // Features:
        // - reqwest Client with proxy support
        // - SSL cert bypass
        // - Custom User-Agent
        // - Cookie support
        // - Redirect following
    }
}
```

---

## 6. CLI Specification

### 6.1 Full CLI Reference

```
VELTRIX(1)                    User Commands                    VELTRIX(1)

NAME
    veltrix - Multi-protocol brute force toolkit

SYNOPSIS
    veltrix [OPTIONS]

TARGET OPTIONS
    -t, --target <HOST:PORT>
        Target host and port (repeatable)

    -T, --target-file <FILE>
        File containing list of targets (one per line)

    -p, --port <PORT>
        Port number(s) - defaults per protocol

PROTOCOL OPTIONS
    -P, --protocol <PROTO>
        Protocol(s): ssh, ftp, telnet, smtp, pop3, rdp, mysql, http

    -L, --list-protocols
        List supported protocols and exit

CREDENTIAL OPTIONS
    -u, --user <USER>
        Single username (repeatable)

    -U, --user-file <FILE>
        File with usernames (one per line)

    -w, --password <PASS>
        Single password (repeatable)

    -W, --password-file <FILE>
        File with passwords (one per line)

    -C, --combo <FILE>
        Combo list: user:pass per line

    --single-user
        Use first user only against all passwords

    --spray
        Credential spraying mode (rotate password across users)

HYBRID ATTACK OPTIONS
    --rules <FILE>
        Rule-based password mutation rules file

    --max-mutations <N>       [default: 5]
        Maximum mutations per base password

PERFORMANCE OPTIONS
    -x, --threads <N>         [default: 10]
        Concurrent workers

    --timeout <SEC>           [default: 10]
        Connection timeout

    --delay <MS>              [default: 0]
        Delay between attempts

    --rate-limit <N>
        Max attempts per second (0=unlimited)

    --retries <N>             [default: 1]
        Connection retry count

    --checkpoint <N>          [default: 100]
        Session save checkpoint interval

CONFIG OPTIONS
    --config <FILE>
        JSON config file (arguments override config)

PROXY OPTIONS
    --proxy <PROXY>
        Single proxy: type://[user:pass@]host:port

    --proxy-file <FILE>
        Proxy rotation list

OUTPUT OPTIONS
    -o, --output <FILE>
        Write results to file

    -f, --format <FMT>        [default: plain]
        Output format: plain, json, csv, html

    --resume <FILE>
        Resume from session file

BEHAVIOR OPTIONS
    --stop-on-first
        Stop after first success per target

    -v, --verbose
        Verbose output

    -q, --quiet
        Successes only

    --no-banner
        Hide startup banner

    -h, --help
        Print help

    -V, --version
        Print version

EXAMPLES
    veltrix -t 192.168.1.1 -P ssh -U users.txt -W passwords.txt
    veltrix -T targets.txt -P ssh,ftp -U users.txt -W passes.txt -x 20
    veltrix -t 10.0.0.5:3389 -P rdp -C combos.txt -o results.json -f json
    veltrix --resume session.json -W more-passwords.txt
    veltrix --config attack.json --spray --rate-limit 5
    veltrix -t 10.0.0.0/24 -P ssh -U users.txt -W passes.txt --rules common.rule
```

### 6.2 Validation Rules

| Condition | Error Message |
|-----------|---------------|
| No target & no target-file | "No targets specified. Use --target or --target-file." |
| No protocol | "No protocols specified. Use --protocol." |
| No credentials (no user, user-file, combo) | "No users specified. Use --user, --user-file, or --combo." |
| Invalid port in target | "Invalid port number" |
| Invalid proxy format | "Invalid proxy format. Use type://host:port" |
| Unsupported proxy type | "Unsupported proxy type: {x}. Use http, socks4, or socks5." |
| File not found | "Failed to open {file}: {os_error}" |
| Combo + user/pass conflict | "--combo is mutually exclusive with --user/--password" |

### 6.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Attack completed with at least one success |
| 1 | Attack completed with no successes, or error |

---

## 7. Error Handling & Edge Cases

### 7.1 Error Classification Matrix

| Category | Error | Detection | Action | Log Level |
|----------|-------|-----------|--------|-----------|
| Connection | Connection refused | TCP connect fail | Skip target permanently | WARN |
| Connection | DNS resolution fail | Resolver timeout/error | Skip target | WARN |
| Connection | Connection timeout | Timer expired | Retry (configurable), then skip | WARN |
| Connection | Connection reset by peer | Socket error | Retry with backoff | WARN |
| Auth | Wrong credentials | Auth protocol response | Mark as failed, continue | DEBUG |
| Auth | Account locked | Pattern match (8 patterns) | Skip user permanently, log to report | INFO |
| Auth | Too many attempts | Pattern match (9 patterns) | Backoff + rotate proxy | WARN |
| Protocol | Unsupported protocol | Not in registry | Skip target for that protocol | WARN |
| Protocol | Protocol error | Unexpected response | Skip target, log error | ERROR |
| I/O | File not found | OS error | Exit with error | ERROR |
| I/O | Invalid format | Parse error | Skip line, warn | WARN |
| Runtime | Task panic | JoinError | Log and continue | ERROR |

### 7.2 Backoff Strategy

```
Retry 0:  wait 500ms
Retry 1:  wait 1000ms
Retry 2:  wait 2000ms
Retry N:  wait 500ms × 2^N (exponential backoff)
Max:      configurable via --retries (default: 1), capped at 30s
```

### 7.3 Response Pattern Detection Rules

```rust
// Authentication failure patterns (case-insensitive partial match — 15 patterns)
AUTH_FAIL_PATTERNS = [
    "access denied",
    "authentication failed",
    "login incorrect",
    "invalid credentials",
    "permission denied",
    "not authenticated",
    "authorization failed",
    "login failed",
    "username or password",
    "incorrect password",
    "invalid username",
    "wrong password",
    "bad password",
    "authenticate failed",
    "login invalid",
]

// Account lockout patterns (8 patterns)
LOCKOUT_PATTERNS = [
    "account locked",
    "account disabled",
    "account blocked",
    "too many failed",
    "account temporarily",
    "account suspended",
    "account is locked",
    "maximum login attempts",
]

// Rate limiting patterns (9 patterns)
RATE_LIMIT_PATTERNS = [
    "rate limit",
    "too many requests",
    "slow down",
    "try again later",
    "exceeded",
    "too many attempts",
    "blocked due to",
    "temporarily unavailable",
    "please wait",
]
```

### 7.4 Edge Cases

| Edge Case | Handling | Status |
|-----------|----------|--------|
| Empty wordlist file | Return empty vec, warn user | ✅ Done |
| Duplicate targets | De-duplicate by host:port:protocol | ❌ Missing |
| Unicode in credentials | Pass as-is (UTF-8) | ✅ Done |
| Very long password (>1KB) | Truncate to 1024 chars | ❌ Missing |
| Target with IPv6 | Support `[::1]:port` format | ✅ Done |
| Self-signed SSL cert | Accept by default | ✅ Done |
| Non-standard port | Explicit port in target overrides default | ✅ Done |
| SIGINT (Ctrl+C) | Graceful shutdown: first press = finish current, second = force | ✅ Done |
| Memory exhaustion | Streaming wordlist loading | ⚠️ Partial (struct exists but doesn't stream) |
| Zero targets after resolve | Exit with error message | ✅ Done |

---

## 8. Performance Targets & Benchmarks

### 8.1 Target Metrics

| Metric | Target | Current Estimate | Measurement |
|--------|--------|-----------------|-------------|
| Max concurrent targets | 100+ | 100+ | Simultaneous target count |
| Credentials per second (SSH) | 500+/s | ~200-300/s | Local network, 10 threads |
| Credentials per second (FTP) | 1000+/s | ~500/s | Local network, 10 threads |
| Credentials per second (HTTP) | 2000+/s | ~1000/s | Local network, 20 threads |
| Memory per connection | < 1MB | < 1MB | RSS measurement |
| Startup time | < 100ms | < 50ms | Binary execution to first attempt |
| Binary size (stripped) | < 10MB | ~8MB | `strip` + `ls` |
| Binary size (compressed) | < 3MB | - | `upx --best` |
| Max wordlist size | Unlimited | Memory-bound | Streaming file read (needs fix) |

### 8.2 Profiling Points

```
[main]          → parse args: < 5ms
[load_targets]  → file I/O + CIDR expand: depends (100k targets ≈ 50ms)
[load_creds]    → file I/O: depends (1M combos ≈ 500ms)
[resolve_dns]   → network: 1-100ms per target (concurrent via join_all)
[worker_pool]   → spawn: < 1ms per task
[auth]          → protocol-specific (100ms-5s per attempt)
[output]        → write: < 1ms per result
```

### 8.3 Bottleneck Analysis

| Bottleneck | Impact | Mitigation | Status |
|------------|--------|------------|--------|
| DNS resolution | High latency per target | Async concurrent resolution (join_all) | ✅ Done |
| TCP handshake | ~50ms per connection | Connection reuse (keepalive) | ❌ Planned |
| TLS handshake | ~100-500ms per connection | Session resumption | ❌ Planned |
| SSH key exchange | ~200-1000ms per connection | None (protocol requirement) | - |
| File I/O (wordlist) | Slow for huge files | Streaming + buffered reader | ⚠️ Partial |
| Lock contention | Worker sync overhead | Lock-free data structures | ✅ Done |

---

## 9. Testing Strategy

### 9.1 Unit Test Coverage — Current (~90 tests)

| Module | Tests | Priority | Status |
|--------|-------|----------|--------|
| `core/cidr.rs` | 9 | P0 | ✅ |
| `core/credential.rs` | 8 | P0 | ✅ |
| `core/result.rs` | 5 | P1 | ✅ |
| `core/rules.rs` | 11 | P1 | ✅ |
| `core/target.rs` | 9 | P0 | ✅ |
| `core/wordlist.rs` | 3 | P0 | ✅ |
| `protocols/mod.rs` | 12 | P0 | ✅ |
| `proxy/mod.rs` | 11 | P0 | ✅ |
| `utils/patterns.rs` | 13 | P1 | ✅ |
| `utils/ratelimit.rs` | 6 | P1 | ✅ |
| `utils/resume.rs` | 3 | P0 | ✅ |

### 9.2 Unit Test Coverage — Missing

| Module | Priority | Current | Target |
|--------|----------|---------|--------|
| `core/config.rs` | P0 | 0 | 10+ |
| `core/config_loader.rs` | P0 | 0 | 10+ |
| `core/attack.rs` | P0 | 0 | 15+ |
| `core/error.rs` | P1 | 0 | 5+ |
| `core/worker.rs` | P0 | 0 | 10+ |
| `cli.rs` | P0 | 0 | 15+ |
| `protocols/ssh.rs` | P0 | 0 | 5+ |
| `protocols/ftp.rs` | P0 | 0 | 5+ |
| `protocols/telnet.rs` | P0 | 0 | 5+ |
| `protocols/smtp.rs` | P0 | 0 | 5+ |
| `protocols/pop3.rs` | P0 | 0 | 5+ |
| `protocols/rdp.rs` | P0 | 0 | 10+ |
| `protocols/mysql.rs` | P0 | 0 | 5+ |
| `protocols/http.rs` | P0 | 0 | 5+ |
| `utils/output.rs` | P1 | 0 | 8+ |
| `utils/report.rs` | P2 | 0 | 3+ |

**Target total:** 200+ unit tests

### 9.3 Integration Tests — ❌ NONE (NEEDED)

| Test | Setup | Expected |
|------|-------|----------|
| SSH auth valid | Docker SSH container with test user | AuthResult.success = true |
| SSH auth invalid | Same container, wrong pass | AuthResult.success = false |
| FTP auth valid | Docker FTP container | Success |
| Telnet auth valid | Docker telnet container | Success |
| SMTP auth valid | Docker SMTP container | Success |
| POP3 auth valid | Docker POP3 container | Success |
| MySQL auth valid | Docker MySQL container | Success |
| HTTP auth valid | Docker HTTP server with Basic Auth | Success |
| RDP auth | Windows/RDP container (if available) | Success |
| Full pipeline | Mock target + wordlists | Summary with correct counts |
| Resume session | Run partial, save, resume | Skip already-tested combos |
| Proxy usage | SOCKS5 proxy container | Auth via proxy |
| Multi-protocol | Targets with different protocols | All protocols work |
| Spray mode | Multiple users, single password | Rotation order correct |
| Rules engine | Base passwords + rules file | Mutated credentials generated |

### 9.4 Docker Test Infrastructure — ✅ Files exist but need verification

```yaml
# docker/docker-compose.test.yml
services:
  ssh-server:
    image: linuxserver/openssh-server
    environment:
      - USER_NAME=testuser
      - PASSWORD=testpass

  ftp-server:
    image: stilliard/pure-ftpd
    environment:
      - FTP_USER_NAME=testuser
      - FTP_USER_PASS=testpass

  mysql-server:
    image: mysql:8
    environment:
      - MYSQL_ROOT_PASSWORD=testpass
```

### 9.5 CI Pipeline (GitHub Actions)

```yaml
name: Veltrix CI
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Check formatting
        run: cargo fmt --check
      - name: Lint
        run: cargo clippy -- -D warnings
      - name: Security audit
        run: cargo audit

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Unit tests
        run: cargo test --lib
      - name: Integration tests
        run: docker compose -f docker/docker-compose.test.yml up -d && cargo test --test integration && docker compose down
      - name: Build release
        run: cargo build --release

  benchmark:
    runs-on: ubuntu-latest
    needs: [lint, test]
    steps:
      - uses: actions/checkout@v4
      - name: Build release
        run: cargo build --release
      - name: Benchmark
        run: cargo bench

  release:
    runs-on: ubuntu-latest
    needs: [benchmark]
    if: startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/checkout@v4
      - name: Build & strip
        run: |
          cargo build --release
          strip target/release/veltrix
      - name: Create release
        uses: softprops/action-gh-release@v1
        with:
          files: target/release/veltrix
```

---

## 10. Development Workflow

### 10.1 Branch Strategy

```
main          → Production-ready code
├── develop   → Integration branch
│   ├── feat/*     → New features
│   ├── fix/*      → Bug fixes
│   ├── refactor/* → Code improvements
│   ├── test/*     → Test additions
│   └── docs/*     → Documentation
```

### 10.2 Commit Convention

```
type(scope): description

Types:
  feat     → New feature
  fix      → Bug fix
  refactor → Code change (no feature/fix)
  docs     → Documentation
  test     → Tests
  chore    → Build/config

Examples:
  feat(ssh): add proxy tunnel support
  fix(core): deduplicate targets before attack
  refactor(error): integrate AttackError enum across codebase
  test(cli): add --version and validation test cases
```

### 10.3 Code Review Checklist

- [ ] Compiles without errors/warnings
- [ ] Clippy passes (no warnings)
- [ ] Tests pass
- [ ] Error handling covers all edge cases
- [ ] No unsafe code
- [ ] Protocol implementations handle timeout correctly
- [ ] Protocol implementations use proxy when configured
- [ ] No secrets/hardcoded credentials
- [ ] Log messages are informative
- [ ] CLI --help output is accurate
- [ ] PRD is updated if behavior changed
- [ ] New feature has unit tests (minimum 5 cases)

### 10.4 Adding a New Protocol

1. Create file `src/protocols/<name>.rs`
2. Implement `Protocol` trait for the struct (with proxy support)
3. Register in `src/protocols/mod.rs`:
   - Add `pub mod <name>;`
   - Add to `get_protocol()` match
   - Add to `list_protocols()` vec
4. Add dependency in `Cargo.toml` if needed
5. Add unit tests (minimum 5)
6. Test with Docker container
7. Add to PRD protocol matrix
8. Run `cargo build && cargo clippy && cargo test`

---

## 11. Security & Compliance

### 11.1 Ethical Use Guidelines
```
⚠  WARNING: Veltrix is a security auditing tool.
   Use ONLY on systems you own or have explicit written permission to test.
   Unauthorized use is illegal and unethical.
```

### 11.2 Built-in Safeguards

| Safeguard | Implementation |
|-----------|----------------|
| Default threads | 10 (not aggressive) |
| Default timeout | 10s (prevents hanging) |
| No persistence | No auto-install, no backdoor |
| No shell exec | 100% safe Rust |
| Audit trail | Every result has timestamp |
| Input sanitization | File paths validated |
| Rate limiting | Configurable token-bucket |
| Exponential backoff | Prevents aggressive hammering |
| Spray mode | Avoids account lockout |
| SIGINT handler | Graceful shutdown on interrupt |

### 11.3 Code Security

- **Zero unsafe code**: Purely safe Rust (no `unsafe` blocks)
- **No command injection**: All parameters are arguments, not shell commands
- **Memory safety**: Rust's ownership system prevents buffer overflows
- **Type safety**: Strong typing prevents injection attacks
- **Dependency audit**: Regular `cargo audit` runs

### 11.4 Compliance Frameworks

| Framework | Relevance | How Veltrix Helps |
|-----------|-----------|-------------------|
| PCI DSS 8.3.1 | Require password strength testing | Password auditing |
| HIPAA §164.312 | Access control validation | Credential testing |
| ISO 27001 A.9 | Access control review | Identity audit |
| NIST SP 800-53 | AC-7: Unsuccessful login attempts | Lockout policy testing |
| OWASP WSTG | AUTH-002: Testing credentials | Weak password detection |

---

## 12. Roadmap & Milestones

### Phase 1: Foundation — v1.0.0 (Current — ✅ Complete)

| Task | Status | Priority |
|------|--------|----------|
| Project structure & module architecture | ✅ Done | P0 |
| Core engine: config, target, credential, wordlist | ✅ Done | P0 |
| Protocol trait & registry with factory pattern | ✅ Done | P0 |
| SSH implementation (password auth, spawn_blocking) | ✅ Done | P0 |
| FTP implementation (suppaftp, spawn_blocking) | ✅ Done | P0 |
| Telnet implementation (IAC negotiation, raw TCP) | ✅ Done | P0 |
| SMTP implementation (lettre, STARTTLS) | ✅ Done | P0 |
| POP3 implementation (raw TCP, USER/PASS) | ✅ Done | P0 |
| RDP implementation (FULL NLA/CredSSP with NTLMv2) | ✅ Done | P0 |
| MySQL implementation (mysql_async, SELECT 1 check) | ✅ Done | P0 |
| HTTP implementation (Basic + Form auth, reqwest) | ✅ Done | P0 |
| Attack orchestrator (async worker pool, FuturesUnordered) | ✅ Done | P0 |
| Output formatters (plain, JSON, CSV) | ✅ Done | P0 |
| Wordlist loader (async, buffered, comment skip) | ✅ Done | P0 |
| CLI argument parser (clap derive, all flags) | ✅ Done | P0 |
| CIDR & IP range target expansion | ✅ Done | P0 |
| Proxy module (SOCKS4, SOCKS5, HTTP CONNECT) | ✅ Done | P0 |
| Token-bucket rate limiter + jitter delay | ✅ Done | P0 |
| Session resume (save/load, checkpoint, skip tested) | ✅ Done | P0 |
| Error classification engine (patterns.rs, 32+ patterns) | ✅ Done | P1 |
| Exponential backoff retry (500ms × 2^N, cap 30s) | ✅ Done | P1 |
| Credential spraying mode (--spray) | ✅ Done | P1 |
| Rule-based password mutation engine (rules.rs) | ✅ Done | P2 |
| Graceful SIGINT handler (dual-press) | ✅ Done | P1 |
| JSON config file loader (config_loader.rs) | ✅ Done | P1 |
| `--single-user` mode | ✅ Done | P1 |
| `--stop-on-first` mode | ✅ Done | P1 |
| Unit tests (~90 tests across 11 modules) | ✅ Done | P0 |

---

### Phase 2: Hardening — v1.1.0 (NEXT — HIGH PRIORITY)

| # | Task | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 2.1 | **Integrate AttackError enum across codebase** | P0 | 3 days | Ganti semua `Result<_, String>` dengan `Result<_, AttackError>` di core, protocols, utils. Error.rs sudah 100% siap tapi tidak dipakai. |
| 2.2 | **Wire HTML report into orchestrator** | P0 | 1 day | Panggil `generate_html_report()` di akhir `attack.rs::run()`. Report.rs sudah 100% siap tapi dead code. |
| 2.3 | **Add proxy support to SSH protocol** | P0 | 2 days | Gunakan proxy tunnel untuk TCP connection sebelum ssh2 session. Implementasi proxy tunnel sudah ada di proxy/mod.rs. |
| 2.4 | **Add proxy support to FTP protocol** | P0 | 2 days | Sama seperti SSH — gunakan proxy tunnel untuk FTP connection via suppaftp. |
| 2.5 | **Add proxy support to SMTP protocol** | P0 | 2 days | Lettre transport melalui proxy tunnel. |
| 2.6 | **Add proxy support to MySQL protocol** | P0 | 2 days | mysql_async connection melalui proxy tunnel. |
| 2.7 | **Duplicate target deduplication** | P0 | 1 day | Filter duplicate `host:port:protocol` di `load_targets()`. |
| 2.8 | **Password truncation > 1KB** | P0 | 1 day | Truncate password yang lebih dari 1024 chars di credential loading. |
| 2.9 | **Populate AuthResult.r#type field** | P0 | 1 day | Isi `r#type` dengan kategori hasil: "success", "auth_failure", "connection_error", "timeout", dll. |
| 2.10 | **Fix spray mode credential ordering** | P0 | 1 day | Pastikan spray mode menghasilkan: pass1→all users, pass2→all users (bukan user×pass). |
| 2.11 | **Add `--version` flag** | P1 | 1 hour | Implement `-V/--version` via clap. |
| 2.12 | **Fix `--quiet` mode** | P1 | 1 day | Pastikan quiet mode hanya menampilkan successes, bukan semua output. |
| 2.13 | **Clean up `#[allow(dead_code)]` annotations** | P1 | 1 day | Hapus semua dead_code yang sudah diintegrasikan. |
| 2.14 | **Make StreamingWordlist actually stream** | P1 | 2 days | Implementasi `load_chunk()` yang benar-benar streaming dari disk, bukan load semua ke memory. |
| 2.15 | **Add TLS/SSL to FTP protocol (FTPS)** | P1 | 2 days | suppaftp sudah support FTPS via `async-secure` feature — tinggal aktivasi. |
| 2.16 | **Add TLS/SSL to POP3 protocol (STLS)** | P1 | 2 days | Implementasi STLS command setelah koneksi POP3. |
| 2.17 | **Unit tests — cli.rs** | P0 | 2 days | 15+ test cases untuk argument parsing, validation, error messages. |
| 2.18 | **Unit tests — core/config.rs** | P0 | 1 day | 10+ test cases untuk config validation, edge cases. |
| 2.19 | **Unit tests — core/config_loader.rs** | P0 | 1 day | 10+ test cases untuk JSON parsing, merge priority. |
| 2.20 | **Unit tests — core/attack.rs** | P0 | 3 days | 15+ test cases untuk orchestrator logic, mock-based. |
| 2.21 | **Unit tests — core/error.rs** | P1 | 1 day | 5+ test cases untuk error variants, Display, From impls. |
| 2.22 | **Unit tests — core/worker.rs** | P0 | 2 days | 10+ test cases untuk semaphore, backoff, proxy rotation. |
| 2.23 | **Unit tests — all protocol modules** | P0 | 5 days | 5+ test cases per protocol (ssh, ftp, telnet, smtp, pop3, rdp, mysql, http) = 40+ tests. |
| 2.24 | **Unit tests — utils/output.rs** | P1 | 1 day | 8+ test cases untuk JSON/CSV/plain formatting. |
| 2.25 | **Unit tests — utils/report.rs** | P2 | 1 day | 3+ test cases untuk HTML generation. |

---

### Phase 3: Advanced — v1.2.0

| # | Task | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 3.1 | **PostgreSQL protocol** | P1 | 3 days | Implementasi via `tokio-postgres`. Auth: md5, password. Support TLS. Register di protocol registry. Proxy support via tunnel. |
| 3.2 | **LDAP protocol** | P1 | 3 days | Implementasi via `ldap3`. Auth: Simple bind, SASL. Support STARTTLS. |
| 3.3 | **Redis protocol** | P1 | 2 days | Implementasi via `redis`. Auth: AUTH command. Support cluster mode. |
| 3.4 | **HTTP Form auth field configuration** | P1 | 2 days | Tambahkan `--http-form-user-field` dan `--http-form-pass-field` untuk kustomisasi field name form login. |
| 3.5 | **HTTP Digest auth** | P2 | 2 days | Implementasi HTTP Digest Access Authentication selain Basic Auth. |
| 3.6 | **RDP domain configuration** | P1 | 1 day | Tambahkan `--rdp-domain` untuk kustomisasi domain di NTLMv2 auth (saat ini hardcoded empty). |
| 3.7 | **Connection reuse / TCP keepalive** | P1 | 3 days | Pool koneksi per target untuk reuse TCP connection, mengurangi overhead handshake. |
| 3.8 | **Concurrent DNS resolution (perf)** | P1 | 1 day | Already partially done via `join_all` — verify and optimize batch size. |
| 3.9 | **Real streaming wordlist** | P1 | 3 days | Implementasi `StreamingWordlist` yang benar — baca file per-chunk, yield secara async. |
| 3.10 | **Proxy chain (multi-hop)** | P2 | 5 days | Dukungan multiple proxy berantai: `proxy1 → proxy2 → target`. |
| 3.11 | **Config file wiring** | P1 | 2 days | Fix `--config` flag untuk merge CLI args + JSON config. Perbaiki format (TOML vs JSON). |
| 3.12 | **Duplicate target detection in CIDR** | P1 | 1 day | Jika CIDR `192.168.1.0/24` dan `192.168.1.1` sama-sama di-input, jangan duplikasi. |
| 3.13 | **Target health check before attack** | P2 | 2 days | Pre-scan targets untuk memastikan reachable sebelum attack dimulai, simpan waktu. |
| 3.14 | **Docker integration tests (setup)** | P1 | 5 days | Setup Docker Compose dengan SSH, FTP, MySQL, Telnet, SMTP, HTTP containers. Integration test untuk setiap protocol. |
| 3.15 | **Unit tests — complete coverage target** | P1 | 5 days | Capai minimum 200 unit tests total. Coverage > 70%. |

---

### Phase 4: Enterprise — v2.0.0

| # | Task | Priority | Effort | Description |
|---|------|----------|--------|-------------|
| 4.1 | **SMB protocol** | P1 | 5 days | Implementasi via library atau raw TCP. Auth: NTLMv1/v2. Challenge-response. |
| 4.2 | **MSSQL protocol** | P2 | 3 days | Implementasi via `tiberius`. Auth: SQL Server Authentication. TLS support. |
| 4.3 | **MongoDB protocol** | P2 | 3 days | Implementasi via `mongodb`. Auth: SCRAM-SHA-1, SCRAM-SHA-256. |
| 4.4 | **IMAP protocol** | P2 | 3 days | Implementasi via `async-imap`. Auth: LOGIN, PLAIN. STARTTLS support. |
| 4.5 | **VNC protocol** | P2 | 3 days | Implementasi VNC Authentication handshake (challenge-response). |
| 4.6 | **SNMP protocol** | P2 | 2 days | Implementasi SNMP v1/v2c community string brute force. |
| 4.7 | **Distributed attack mode** | P2 | 3 weeks | Client/server architecture: coordinator distribusi tasks ke multiple worker nodes. |
| 4.8 | **Plugin system for custom protocols** | P2 | 4 weeks | WASM-based plugin system untuk menambah protocol tanpa compile ulang. |
| 4.9 | **REST API mode** | P3 | 3 weeks | HTTP server (actix-web) untuk kontrol attack via REST API. |
| 4.10 | **Web UI (Tauri)** | P3 | 6 weeks | Desktop GUI application menggunakan Tauri untuk visual management. |
| 4.11 | **Encrypted output** | P2 | 2 days | Enkripsi file output (AES-256-GCM) untuk proteksi credentials. |
| 4.12 | **Session file integrity check** | P2 | 1 day | Checksum/hash pada session file untuk detect tampering. |
| 4.13 | **Full CI/CD with release automation** | P1 | 3 days | GitHub Actions auto-build, strip, compress, upload ke releases. |
| 4.14 | **Benchmark gate in CI** | P1 | 2 days | Automated benchmark setiap PR, fail jika performance turun > 20%. |

---

### Phase 5: Ecosystem — v2.1.0+

| # | Task | Priority | Description |
|---|------|----------|-------------|
| 5.1 | **Wordlist generation mode** | P3 | Generate wordlist based on target info (name, company, dates) |
| 2 | **Machine learning password prediction** | P3 | Neural network-based password generation |
| 3 | **Cloud API integrations** | P3 | Hashcat-like API untuk cloud GPU/CPU |
| 4 | **VSCode extension** | P3 | Run attacks from VSCode |
| 5 | **Burp Suite plugin** | P3 | Integrasi dengan Burp Suite untuk web app testing |

---

## 13. Code Audit: Known Issues & Technical Debt

### 13.1 Critical Issues (Harus Diperbaiki di Phase 2)

| # | Issue | File(s) | Impact | Fix |
|---|-------|---------|--------|-----|
| CRIT-1 | `AttackError` enum never used | `core/error.rs` | All error handling uses `String` — no type safety, no pattern matching on errors | Replace all `Result<_, String>` with `Result<_, AttackError>` |
| CRIT-2 | HTML report never called | `utils/report.rs` | User cannot get HTML output despite code being complete | Call `generate_html_report()` in orchestrator |
| CRIT-3 | TOML config file incompatible | `config/veltrix.toml` vs `config_loader.rs` | Config file at `config/veltrix.toml` is TOML but loader expects JSON | Convert to JSON or add TOML parser |
| CRIT-4 | Proxy not used by SSH/FTP/SMTP/MySQL | `protocols/ssh.rs`, `ftp.rs`, `smtp.rs`, `mysql.rs` | Users behind proxy cannot use these protocols | Implement proxy tunnel for each |
| CRIT-5 | `AuthResult.r#type` always empty | `core/result.rs` | Field exists but never populated — loses classification data | Set type based on error category |

### 13.2 High Priority Issues

| # | Issue | File(s) | Impact | Fix |
|---|-------|---------|--------|-----|
| HIGH-1 | No duplicate target dedup | `core/attack.rs` | Same target attacked multiple times | Add HashSet-based dedup in `load_targets()` |
| HIGH-2 | No password truncation | `core/credential.rs` | >1KB passwords not handled | Truncate to 1024 chars in credential loading |
| HIGH-3 | `StreamingWordlist` not streaming | `core/wordlist.rs` | Memory exhaustion with large files | Implement real chunked file reading |
| HIGH-4 | No unit tests for 16 modules | Various | ~16 modules have 0 tests | Add tests per plan in §9.2 |
| HIGH-5 | No integration tests | `tests/` | No end-to-end verification | Setup Docker + integration test suite |
| HIGH-6 | FTP missing TLS (FTPS) | `protocols/ftp.rs` | Cannot test secure FTP servers | Activate suppaftp `async-secure` feature |
| HIGH-7 | POP3 missing TLS (STLS) | `protocols/pop3.rs` | Cannot test secure POP3 servers | Implement STLS command after connect |

### 13.3 Medium Priority Issues

| # | Issue | File(s) | Impact | Fix |
|---|-------|---------|--------|-----|
| MED-1 | `--version` flag missing | `cli.rs` | Cannot check binary version | Add to clap args |
| MED-2 | `--quiet` mode not fully implemented | `attack.rs` + `output.rs` | Quiet mode may show more than successes | Filter output based on quiet flag |
| MED-3 | Dead code annotations | Multiple files | Code clutter, potential confusion | Remove dead code or integrate it |
| MED-4 | Spray mode ordering verification | `attack.rs` | Need to verify correct password-rotation order | Audit and test spray mode logic |
| MED-5 | RDP domain hardcoded empty | `protocols/rdp.rs` | Cannot specify custom domain for NTLMv2 | Add `--rdp-domain` CLI flag |
| MED-6 | Checkpoint interval hardcoded | `attack.rs` | Resume save interval not configurable | Already has `checkpoint_interval` field — verify usage |

### 13.4 Technical Debt Items

| # | Item | Severity | Effort | Reason | Created |
|---|------|----------|--------|--------|---------|
| TD1 | ssh2 uses C library (libssh2-sys) | Medium | 2 weeks | Pure Rust SSH unavailable at start | v1.0 |
| TD2 | FTP/SMTP use blocking calls via spawn_blocking | Low | 2 days | Libraries have no async API | v1.0 |
| TD3 | No proper error types (all String) | Medium | 1 week | Quick prototyping | v1.0 |
| TD4 | AttackOrchestrator.run() too long | Medium | 3 days | All logic in single method | v1.0 |
| TD5 | No integration tests | High | 2 weeks | Test infra not set up | v1.0 |
| TD6 | Hardcoded `#[allow(dead_code)]` | Low | 1 hour | Future-proofing | v1.0 |
| TD7 | AuthResult.r#type field unused | Low | 1 hour | Field exists but never populated | v1.0 |

### 13.5 Refactoring Roadmap

```
Phase 2 (v1.1):
  ✅ CRIT-1: Integrate AttackError enum
  ✅ CRIT-2: Wire HTML report
  ✅ CRIT-4: Add proxy support to SSH, FTP, SMTP, MySQL
  ✅ CRIT-5: Populate AuthResult.r#type
  ✅ HIGH-1: Duplicate target dedup
  ✅ HIGH-2: Password truncation
  ✅ TD3: Custom error types (AttackError enum)
  ✅ TD4: Extract worker pool into separate struct (already done as worker.rs)
  ✅ TD7: Populate AuthResult.r#type

Phase 3 (v1.2):
  ✅ CRIT-3: Config file format fix (JSON vs TOML)
  ✅ HIGH-3: Real streaming wordlist
  ✅ HIGH-6: FTP FTPS support
  ✅ HIGH-7: POP3 STLS support
  ✅ TD1: Evaluate pure Rust SSH alternatives
  ✅ TD5: Set up Docker test infrastructure
  ✅ MED-1: Add --version flag
  ✅ MED-5: RDP domain configuration

Phase 4 (v2.0):
  ✅ TD2: Evaluate async alternatives for FTP/SMTP
  ✅ Architecture: Extract coordinator from orchestrator
  ✅ Performance optimization queue (see §8.3)
```

---

## 14. Appendix

### 14.1 Comparison Matrix — Veltrix vs Competition

| Feature | Veltrix | THC-Hydra | Medusa | Crowbar | Ncrack |
|---------|---------|-----------|--------|---------|--------|
| Language | Rust | C | C | Python | C |
| Async I/O | ✅ Tokio | ❌ | ❌ | ❌ | ❌ |
| Memory Safety | ✅ (compile) | ❌ | ❌ | ❌ | ❌ |
| Single Binary | ✅ (~8MB) | ❌ | ❌ | ❌ (script) | ❌ |
| Cross-platform | ✅ | ✅ | ✅ | ✅ | ✅ |
| Protocol Count | 8 (17 planned) | 50+ | 11 | 3 | 12 |
| SSH | ✅ | ✅ | ✅ | ✅ | ✅ |
| FTP | ✅ | ✅ | ✅ | ❌ | ✅ |
| Telnet | ✅ | ✅ | ✅ | ✅ | ✅ |
| SMTP | ✅ | ✅ | ✅ | ❌ | ✅ |
| POP3 | ✅ | ✅ | ✅ | ❌ | ✅ |
| RDP | ✅ (FULL NLA) | ✅ | ❌ | ❌ | ✅ |
| MySQL | ✅ | ✅ | ✅ | ❌ | ❌ |
| HTTP | ✅ (Basic+Form) | ✅ | ✅ | ❌ | ✅ |
| Proxy Support | ✅ SOCKS4/5/HTTP | ✅ | ❌ | ❌ | ❌ |
| CIDR Target | ✅ | ❌ | ❌ | ❌ | ❌ |
| Rule Mutation | ✅ | ✅ | ❌ | ❌ | ❌ |
| Rate Limiting | ✅ Token-Bucket | ✅ | ❌ | ❌ | ✅ |
| Resume Support | ✅ Checkpoint | ❌ | ❌ | ❌ | ❌ |
| HTML Report | ✅ (needs wiring) | ❌ | ❌ | ❌ | ❌ |
| JSON Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| CSV Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Progress Bar | ✅ indicatif | ❌ | ❌ | ❌ | ❌ |
| Colored Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Verbose Levels | 3 levels | 2 levels | 1 level | 1 level | 2 levels |

### 14.2 Dependencies & Justification

```toml
[dependencies]
# CLI Framework — clap v4
# Alasan: Derive API, auto-generate help/version, subcommand support,
# type-safe parsing, widespread adoption (35M+ downloads)
clap = { version = "4", features = ["derive", "env"] }

# Async Runtime — tokio v1
# Alasan: Industry standard, multi-threaded work-stealing scheduler,
# broad ecosystem, first-class async I/O
tokio = { version = "1", features = ["full"] }

# Async Streams — futures v0.3
# Alasan: FuturesUnordered, StreamExt for concurrent task processing
futures = "0.3"

# Serialization — serde v1
# Alasan: Zero-cost abstraction, derive macros, JSON/CSV support
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1"

# Time — chrono v0.4
chrono = { version = "0.4", features = ["serde"] }

# Terminal — colored v2 + indicatif v0.17
colored = "2"
indicatif = { version = "0.17", features = ["tokio"] }

# Protocols
ssh2 = "0.9"           # libssh2 binding — mature, stable
suppaftp = { version = "5", features = ["async-secure"] }  # Pure Rust FTP + TLS
lettre = { version = "0.11", features = ["tokio1-native-tls"] }  # SMTP + TLS
mysql_async = "0.34"   # Pure Rust MySQL
reqwest = { version = "0.12", features = ["socks", "cookies", "json"] }  # HTTP client

# Future protocols (add when implementing)
# tokio-postgres = { version = "0.7", features = ["with-serde", "with-chrono-0_4"] }
# ldap3 = { version = "0.11", features = ["tokio"] }
# redis = { version = "0.27", features = ["tokio-comp"] }
# tiberius = { version = "0.12", features = ["tokio"] }
# mongodb = { version = "3", features = ["tokio-runtime"] }
# async-imap = { version = "0.10", features = ["tokio1"] }

# DNS
trust-dns-resolver = "0.23"
trust-dns-proto = "0.23"

# Crypto (for RDP NTLMv2/CredSSP)
md4 = "0.11"
hmac = "0.13"
sha2 = "0.11"
rand = "0.8"

# TLS
tokio-native-tls = "0.7"
native-tls = "0.2"

# Async trait support
async-trait = "0.1"

# Misc
regex = "1"
uuid = { version = "1", features = ["v4"] }
rpassword = "7"
tokio-util = "0.7"
log = "0.4"
env_logger = "0.11"
ctrlc = "3.4"
```

### 14.3 Glossary

| Term | Definition |
|------|------------|
| **Brute Force** | Mencoba semua kombinasi credential secara sistematis |
| **Dictionary Attack** | Menggunakan wordlist berisi kemungkinan password |
| **Credential Spraying** | Satu password dicoba ke banyak akun untuk hindari lockout |
| **Combo List** | File berisi pasangan `username:password` |
| **NLA** | Network Level Authentication (RDP) — pre-login auth |
| **CredSSP** | Credential Security Support Provider — RDP NLA protocol |
| **NTLMv2** | NT LAN Manager versi 2 — challenge-response auth protocol |
| **SOCKS** | Protokol proxy untuk tunneling traffic (firewall bypass) |
| **Jitter** | Variasi acak pada timing untuk hindari deteksi |
| **Token Bucket** | Algoritma rate limiting dengan burst capacity |
| **Cartesian Product** | Setiap user × setiap password (kombinasi penuh) |
| **Work-stealing** | Scheduler yang mendistribusikan task ke idle workers |
| **Backoff** | Penundaan eksponensial setelah failure untuk hindari ban |
| **CIDR** | Classless Inter-Domain Routing — format subnet `192.168.1.0/24` |
| **ASN.1** | Abstract Syntax Notation One — encoding format untuk protocol data |

### 14.4 License & Attribution

**Veltrix** dirilis di bawah **MIT License**.

```
MIT License

Copyright (c) 2024 aniippxploit

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

> **Disclaimer:** Veltrix dibuat untuk tujuan pengujian keamanan yang etis. Penyalahgunaan alat ini sepenuhnya menjadi tanggung jawab pengguna. Selalu dapatkan izin tertulis sebelum menguji sistem yang bukan milik Anda.

> **Version History:**
> - v3.0 — Updated with actual code audit results, fixed inaccuracies, added detailed phase plans, documented dead code and technical debt
> - v2.0 — Original comprehensive PRD
> - v1.0 — Initial draft
