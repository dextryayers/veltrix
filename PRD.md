# Veltrix — Product Requirements Document (PRD)

> **Versi:** 2.0  
> **Status:** Final  
> **Penulis:** aniippxploit  
> **Tech Stack:** Rust (100%) — Async, Multi-threaded, Modular Architecture  
> **Target Rilis:** v1.0 (Core) → v2.0 (Enterprise)

---

## Daftar Isi

1. [Executive Summary](#1-executive-summary)
2. [Fitur & Spesifikasi](#2-fitur--spesifikasi)
3. [Arsitektur Sistem](#3-arsitektur-sistem)
4. [Module Reference](#4-module-reference)
5. [Protocol Implementation Guide](#5-protocol-implementation-guide)
6. [CLI Specification](#6-cli-specification)
7. [Error Handling & Edge Cases](#7-error-handling--edge-cases)
8. [Performance Targets & Benchmarks](#8-performance-targets--benchmarks)
9. [Testing Strategy](#9-testing-strategy)
10. [Development Workflow](#10-development-workflow)
11. [Security & Compliance](#11-security--compliance)
12. [Roadmap & Milestones](#12-roadmap--milestones)
13. [Appendix](#13-appendix)

---

## 1. Executive Summary

### 1.1 Vision

**Veltrix** adalah *multi-protocol brute force toolkit* generasi baru yang ditulis 100% dalam **Rust**. Dirancang untuk menjadi standar industri dalam pengujian kredensial — menggabungkan performa native, keamanan memory Rust, kemudahan distribusi single-binary, dan arsitektur modular yang ekstensibel.

### 1.2 Positioning

| Aspek | Veltrix | Hydra | Medusa | Crowbar | Ncrack |
|-------|---------|-------|--------|---------|--------|
| Bahasa | Rust 🦀 | C | C | Python | C |
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
| Security Auditor | Assessment kebijakan password | Report tidak terstruktur | JSON/CSV output, audit trail |
| SysAdmin | Test password internal | Tool terlalu agresif | Rate limiting, delay config |
| Security Researcher | Riset brute force methods | Sulit ekstensi | Trait-based plugin system |

---

## 2. Fitur & Spesifikasi

### 2.1 Protocol Support Matrix

| # | Protocol | Port Default | Auth Methods | Library | TLS/SSL | Priority | Status |
|---|----------|-------------|--------------|---------|---------|----------|--------|
| 1 | SSH | 22 | password, key-based | `ssh2` | - | P0 | ✅ Done |
| 2 | FTP | 21 | plain, TLS/SSL | `suppaftp` | FTPS | P0 | ✅ Done |
| 3 | Telnet | 23 | plaintext | raw TCP | - | P0 | ✅ Done |
| 4 | SMTP | 25, 465, 587 | LOGIN, PLAIN, CRAM-MD5 | `lettre` | STARTTLS | P0 | ✅ Done |
| 5 | POP3 | 110, 995 | USER/PASS | raw TCP | STLS | P0 | ✅ Done |
| 6 | RDP | 3389 | NLA, RDP Standard | raw TCP | - | P0 | ✅ Done |
| 7 | MySQL | 3306 | mysql_native_password | `mysql_async` | TLS | P0 | ✅ Done |
| 8 | HTTP | 80, 443 | Basic, Digest, Form | `reqwest` | HTTPS | P0 | ✅ Done |
| 9 | PostgreSQL | 5432 | md5, password | `tokio-postgres` | TLS | P1 | ⏳ Future |
| 10 | LDAP | 389, 636 | Simple, SASL | `ldap3` | STARTTLS | P1 | ⏳ Future |
| 11 | Redis | 6379 | AUTH | `redis` | - | P1 | ⏳ Future |
| 12 | SMB | 445 | NTLMv1/v2 | TBD | - | P2 | ⏳ Future |
| 13 | SNMP | 161 | community strings | TBD | - | P2 | ⏳ Future |
| 14 | VNC | 5900 | VNC Auth | TBD | - | P2 | ⏳ Future |
| 15 | MSSQL | 1433 | SQL Server Auth | `tiberius` | TLS | P2 | ⏳ Future |
| 16 | MongoDB | 27017 | SCRAM-SHA-1 | `mongodb` | TLS | P2 | ⏳ Future |
| 17 | IMAP | 143, 993 | LOGIN, PLAIN | `async-imap` | STARTTLS | P2 | ⏳ Future |

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

#### Mode E: Hybrid Attack (Future)
```
Rule: append tahun umum
  password → password2023, password2024, password2025

Rule: capitalize
  admin → Admin, ADMIN

Rule: leet speak
  password → p@ssword, p@$$w0rd
```

### 2.3 Target Input Format

| Format | Contoh | Deskripsi |
|--------|--------|-----------|
| `host:port` | `192.168.1.1:22` | Explicit port untuk protocol |
| `host` | `10.0.0.5` | Auto-detect port berdasarkan protocol |
| `host:port:protocol` | `10.0.0.5:3389:rdp` | Override protocol |
| CIDR (future) | `192.168.1.0/24` | Range IP |
| Range (future) | `192.168.1.1-100` | Sequential IP |

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
  │   ├── config.rs          (no deps on other modules)
  │   ├── target.rs           (no deps on other modules)
  │   ├── credential.rs       (no deps on other modules)
  │   ├── result.rs           (no deps on other modules)
  │   ├── wordlist.rs         (no deps on other modules)
  │   └── attack.rs →         (depends on all core + protocols + utils + proxy)
  │       ├── target.rs
  │       ├── credential.rs
  │       ├── result.rs
  │       ├── wordlist.rs
  │       ├── config.rs
  │       ├── protocols/      (trait + implementations)
  │       ├── proxy/
  │       └── utils/
  ├── protocols/
  │   ├── mod.rs →            (Protocol trait)
  │   ├── ssh.rs →            (impl Protocol)
  │   ├── ftp.rs →            (impl Protocol)
  │   └── ...                  (impl Protocol)
  ├── proxy/
  │   └── mod.rs               (no deps on other modules)
  └── utils/
      ├── ratelimit.rs         (no deps on other modules)
      ├── resume.rs            (no deps on other modules)
      └── output.rs →          (depends on result.rs)
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
         │  (every N att.)    │
         └────────┬───────────┘
                  │
         ┌────────▼───────────┐
         │  Generate Summary  │
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
    /// Nama protocol (harus unique, lowercase)
    fn name(&self) -> &'static str;

    /// Port default untuk protocol ini
    fn default_port(&self) -> u16;

    /// Attempt authentication terhadap target
    ///
    /// # Arguments
    /// * `target` - Target host + port
    /// * `credential` - Username + password pair
    /// * `timeout` - Connection timeout
    /// * `proxy` - Optional proxy config
    ///
    /// # Returns
    /// * `AuthResult` - Hasil autentikasi dengan metadata
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
    pub target_host: String,     // Target IP/hostname
    pub target_port: u16,        // Port target
    pub protocol: String,        // Nama protocol
    pub username: String,        // Username
    pub password: String,        // Password
    pub success: bool,           // true = auth berhasil
    pub timestamp: DateTime<Utc>,// Waktu eksekusi
    pub duration_ms: u64,        // Durasi dalam ms
    pub error: Option<String>,   // Error message (None jika success)
}
```

#### AttackConfig Contract
```rust
pub struct AttackConfig {
    pub targets: Vec<String>,         // Daftar target CLI
    pub target_file: Option<PathBuf>, // File target
    pub users: Vec<String>,           // Username list
    pub passwords: Vec<String>,       // Password list
    pub user_file: Option<PathBuf>,   // File usernames
    pub password_file: Option<PathBuf>,// File passwords
    pub combo_file: Option<PathBuf>,  // Combo list file
    pub protocols: Vec<String>,       // Protocol names
    pub ports: Vec<u16>,             // Custom ports
    pub threads: usize,               // Concurrency level
    pub timeout: Duration,           // Per-connection timeout
    pub delay: Duration,              // Inter-attempt delay
    pub rate_limit: Option<u64>,     // Max att/s
    pub proxy_file: Option<PathBuf>, // Proxy file
    pub output_file: Option<PathBuf>, // Output file
    pub output_format: OutputFormat,  // json/csv/plain
    pub resume_file: Option<PathBuf>, // Resume session
    pub verbose: bool,               // Verbose logging
    pub single_user_mode: bool,      // 1 user mode
    pub stop_on_first: bool,         // Stop at first success
    pub retries: u32,                // Connection retries
}
```

---

## 4. Module Reference

### 4.1 `src/main.rs` — Entry Point
```rust
// Flow:
// 1. Initialize env_logger
// 2. Parse CLI args via clap
// 3. If --list-protocols, print & exit
// 4. Print banner (unless --no-banner)
// 5. Convert args → AttackConfig
// 6. Create AttackOrchestrator::new(config)
// 7. Run orchestrator.run()
// 8. Exit with status 0 if any success, 1 otherwise
```

### 4.2 `src/cli.rs` — CLI Argument Parser
- **Library**: `clap` v4 (derive API)
- **Arg Groups**: Manual validation via `into_config()`
- **Validation rules**:
  - Requires either `--target` or `--target-file`
  - Requires either `--protocol` or `--list-protocols`
  - Requires credentials via `--user`/`--user-file`/`--combo`
  - Port: custom or protocol default

### 4.3 `src/core/attack.rs` — Attack Orchestrator (Critical)
```
State:
  config     → AttackConfig
  targets    → Vec<Target> (resolved)
  credentials → Vec<Credential>
  proxies    → Vec<ProxyConfig>
  results   → Vec<AuthResult>
  session   → Option<SessionState>
  output    → OutputHandler
  rate_limit → RateLimiter
  jitter    → JitterDelay

Methods:
  new(config)      → Load all resources, init state
  run()            → Main loop: queue → workers → results
  load_targets()   → Parse + resolve
  load_credentials()  → Load wordlists + combos
  load_proxies()   → Load proxy configs
  get_proxy_for(index) → Round-robin proxy selection
```

### 4.4 `src/protocols/mod.rs` — Protocol Registry
```
Registry:
  get_protocol("ssh")    → Some(Box<SshProtocol>)
  get_protocol("ftp")    → Some(Box<FtpProtocol>)
  get_protocol("telnet") → Some(Box<TelnetProtocol>)
  ...
  get_protocol("unknown") → None

Factory Pattern:
  match name {
    "ssh"  → Box::new(SshProtocol),
    "ftp"  → Box::new(FtpProtocol),
    ...
  }
```

### 4.5 `src/proxy/mod.rs` — Proxy Manager
```
ProxyConfig enum:
  Http { host, port, username, password }
  Socks4 { host, port, username }
  Socks5 { host, port, username, password }
  None

Parsing:
  Input: "socks5://user:pass@127.0.0.1:9050"
  Output: ProxyConfig::Socks5 {
    host: "127.0.0.1", port: 9050,
    username: Some("user"), password: Some("pass")
  }
```

### 4.6 `src/utils/ratelimit.rs` — Rate Limiter
```
Token Bucket Algorithm:
  1. tokens = max_per_second
  2. Every tick: tokens += elapsed * rate
  3. tokens = min(tokens, max_per_second)
  4. if tokens < 1: wait( (1 - tokens) / rate )
  5. tokens -= 1

Jitter:
  delay = base_delay + random(0, jitter_ms)
```

### 4.7 `src/utils/resume.rs` — Session Manager
```
SessionState:
  tracks combos_tested (HashSet)
  tracks successes list
  save(path) → serializes to JSON
  load(path) → deserializes from JSON
  is_tested(user, pass) → checks HashSet

Checkpoint: auto-save every 100 attempts
```

### 4.8 `src/utils/output.rs` — Output Handler
```
OutputHandler:
  format: OutputFormat (Json, Csv, Plain)
  file: Option<File>
  progress: Option<ProgressBar>

Methods:
  write_result(result)    → write single result
  write_summary(summary)  → write final summary
  init_progress(total)    → start progress bar
  inc_progress()          → increment progress
  finish_progress()       → stop progress bar
```

---

## 5. Protocol Implementation Guide

### 5.1 SSH Protocol (`src/protocols/ssh.rs`)

```rust
pub struct SshProtocol;

impl Protocol for SshProtocol {
    fn name(&self) -> &'static str { "ssh" }
    fn default_port(&self) -> u16 { 22 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // 1. TCP connect ke target:port dengan timeout
        // 2. Handle proxy jika ada
        // 3. Buat SSH session via libssh2 (blocking dalam spawn_blocking)
        // 4. Session handshake
        // 5. userauth_password()
        // 6. Return AuthResult
        // Note: ssh2 library adalah C binding, jalankan di spawn_blocking
    }
}
```

**Error Handling:**
- Connection refused → `AuthResult { success: false, error: "Connection refused" }`
- Auth failed → `AuthResult { success: false, error: None }` (normal fail)
- Timeout → `AuthResult { success: false, error: "Timeout" }`
- SSH protocol error → `AuthResult { success: false, error: "SSH error: ..." }`

### 5.2 FTP Protocol (`src/protocols/ftp.rs`)

```rust
pub struct FtpProtocol;

impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str { "ftp" }
    fn default_port(&self) -> u16 { 21 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
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
        // 1. TCP connect
        // 2. Handle telnet negotiation (IAC WILL/WONT/DO/DONT)
        //    - Respond WONT to all DO requests
        //    - Respond DONT to all WILL requests
        // 3. Wait for login: prompt
        // 4. Send username + \r\n
        // 5. Wait for password: prompt
        // 6. Send password + \r\n
        // 7. Check response for success/failure keywords
        //    - Success: no "incorrect", "invalid", "failed", "denied", "wrong"
        //    - Failure: contains any of those keywords
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
        // 1. Build dummy email message via lettre
        // 2. Choose transport:
        //    - port 465 → starttls_relay()
        //    - port 25  → relay()
        //    - port 587 → starttls_relay()
        // 3. Set credentials, port, timeout
        // 4. transport.send(&email)
        // 5. Check result:
        //    - Ok → success
        //    - Err containing "auth"|"535" → auth fail
        //    - Other error → connection error
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
        // 1. TCP connect
        // 2. Read banner (must start with +OK)
        // 3. Send: USER <username>\r\n
        // 4. Read response (must be +OK)
        // 5. Send: PASS <password>\r\n
        // 6. Read response:
        //    - +OK → auth success
        //    - -ERR → auth failure
        // 7. Send QUIT
    }
}
```

### 5.6 RDP Protocol (`src/protocols/rdp.rs`)

```rust
pub struct RdpProtocol;

impl Protocol for RdpProtocol {
    fn name(&self) -> &'static str { "rdp" }
    fn default_port(&self) -> u16 { 3389 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // Note: RDP brute force penuh memerlukan implementasi CredSSP/NLA
        // Implementasi saat ini: Connection check + banner grab
        //
        // 1. TCP connect + send RDP Negotiation Request
        // 2. Read RDP Negotiation Response
        // 3. Cek apakah response valid RDP (starts with 0x03)
        // 4. Jika RDP reachable → success (marked as "weak" verification)
        // 5. Jika tidak → failed
        //
        // TODO: Full NLA/CredSSP implementation untuk auth verification
    }
}
```

### 5.7 MySQL Protocol (`src/protocols/mysql.rs`)

```rust
pub struct MySqlProtocol;

impl Protocol for MySqlProtocol {
    fn name(&self) -> &'static str { "mysql" }
    fn default_port(&self) -> u16 { 3306 }

    async fn authenticate(&self, target, credential, timeout, proxy) -> AuthResult {
        // 1. Buat OptsBuilder dengan host, port, user, pass
        // 2. Create Pool, get_conn()
        // 3. If success → query "SELECT 1" → auth success
        // 4. If error:
        //    - "Access denied" atau "1045" → auth fail
        //    - Error lain → connection error
        // 5. Disconnect pool
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
        // 1. Pilih protocol (http/https) based on port
        // 2. Build reqwest Client:
        //    - timeout
        //    - ignore invalid SSL certs
        //    - proxy config (if any)
        // 3. GET request dengan Basic Auth header
        // 4. Check status code:
        //    - 200, 204, 302 → Success
        //    - 401, 403 → Auth failed
        //    - Other → undefined
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

PROXY OPTIONS
    --proxy <PROXY>
        Single proxy: type://[user:pass@]host:port

    --proxy-file <FILE>
        Proxy rotation list

OUTPUT OPTIONS
    -o, --output <FILE>
        Write results to file

    -f, --format <FMT>        [default: plain]
        Output format: plain, json, csv

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
| Auth | Account locked | "account locked" in response | Skip user, log to report | INFO |
| Auth | Too many attempts | "too many auth failures" | Backoff + rotate proxy | WARN |
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
Max:      configurable via --retries (default: 1)
```

### 7.3 Response Pattern Detection Rules

```rust
// Authentication failure patterns (case-insensitive partial match)
AUTH_FAIL_PATTERNS = [
    "access denied",
    "authentication failed",
    "login incorrect",
    "invalid credentials",
    "permission denied",
    "not authenticated",
    "authorization failed",
]

// Account lockout patterns
LOCKOUT_PATTERNS = [
    "account locked",
    "account disabled",
    "account blocked",
    "too many failed",
    "account temporarily",
]

// Rate limiting patterns
RATE_LIMIT_PATTERNS = [
    "rate limit",
    "too many requests",
    "slow down",
    "try again later",
    "exceeded",
]
```

### 7.4 Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Empty wordlist file | Return empty vec, warn user |
| Duplicate targets | De-duplicate by host:port:protocol |
| Unicode in credentials | Pass as-is (UTF-8) |
| Very long password (>1KB) | Truncate to 1024 chars |
| Target with IPv6 | Support `[::1]:port` format |
| Self-signed SSL cert | Accept by default (--danger-accept-invalid-certs) |
| Non-standard port | Explicit port in target overrides default |
| SIGINT (Ctrl+C) | Graceful shutdown, save session |
| Memory exhaustion | Streaming wordlist loading (future) |
| Zero targets after resolve | Exit with error message |

---

## 8. Performance Targets & Benchmarks

### 8.1 Target Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Max concurrent targets | 100+ | Simultaneous target count |
| Credentials per second (SSH) | 500+/s | Local network, 10 threads |
| Credentials per second (FTP) | 1000+/s | Local network, 10 threads |
| Credentials per second (HTTP) | 2000+/s | Local network, 20 threads |
| Memory per connection | < 1MB | RSS measurement |
| Startup time | < 100ms | Binary execution to first attempt |
| Binary size (stripped) | < 10MB | `strip` + `ls` |
| Binary size (compressed) | < 3MB | `upx --best` |
| Max wordlist size | Unlimited | Streaming file read |

### 8.2 Profiling Points

```
[main]          → parse args: < 5ms
[load_targets]  → file I/O: depends (100k targets ≈ 50ms)
[load_creds]    → file I/O: depends (1M combos ≈ 500ms)
[resolve_dns]   → network: 1-100ms per target
[worker_pool]   → spawn: < 1ms per task
[auth]          → protocol-specific (100ms-5s per attempt)
[output]        → write: < 1ms per result
```

### 8.3 Bottleneck Analysis

| Bottleneck | Impact | Mitigation |
|------------|--------|------------|
| DNS resolution | High latency per target | Async concurrent resolution |
| TCP handshake | ~50ms per connection | Connection reuse (keepalive) |
| TLS handshake | ~100-500ms per connection | Session resumption |
| SSH key exchange | ~200-1000ms per connection | None (protocol requirement) |
| File I/O (wordlist) | Slow for huge files | Streaming + buffered reader |
| Lock contention | Worker sync overhead | Lock-free data structures |

---

## 9. Testing Strategy

### 9.1 Unit Test Coverage

| Module | Test Cases | Priority |
|--------|------------|----------|
| `core/config.rs` | Validate config: missing fields, invalid values | P0 |
| `core/target.rs` | Parse target: host:port, IPv6, invalid | P0 |
| `core/credential.rs` | Parse combo line, edge cases | P0 |
| `core/result.rs` | Constructor, display format | P1 |
| `core/wordlist.rs` | Load file, skip comments/empty | P0 |
| `protocols/mod.rs` | Registry lookup, get_protocol() | P0 |
| `proxy/mod.rs` | Parse proxy URL, all formats | P0 |
| `utils/ratelimit.rs` | Token bucket, wait timing | P1 |
| `utils/resume.rs` | Save/load, mark_tested, is_tested | P0 |
| `utils/output.rs` | JSON/CSV/plain formatting | P1 |
| `cli.rs` | Arg parsing, validation, flags | P0 |

### 9.2 Integration Tests

| Test | Setup | Expected |
|------|-------|----------|
| SSH auth valid | Docker SSH container with test user | AuthResult.success = true |
| SSH auth invalid | Same container, wrong pass | AuthResult.success = false |
| FTP auth valid | Docker FTP container | Success |
| Full pipeline | Mock target + wordlists | Summary with correct counts |
| Resume session | Run partial, save, resume | Skip already-tested combos |
| Proxy usage | SOCKS5 proxy container | Auth via proxy |
| Multi-protocol | Targets with different protocols | All protocols work |

### 9.3 Docker Test Infrastructure

```yaml
# docker-compose.test.yml
version: '3'
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

### 9.4 Test Wordlists

```
users.txt:
  admin
  root
  testuser

passwords.txt:
  admin
  123456
  testpass
  wrongpass

combos.txt:
  admin:admin
  root:123456
  testuser:testpass
```

### 9.5 CI Pipeline (GitHub Actions)

```yaml
name: Veltrix CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      
      - name: Check formatting
        run: cargo fmt --check
      
      - name: Lint
        run: cargo clippy -- -D warnings
      
      - name: Unit tests
        run: cargo test --lib
      
      - name: Integration tests
        run: docker-compose -f docker-compose.test.yml up -d && cargo test --test integration && docker-compose down
      
      - name: Build release
        run: cargo build --release
      
      - name: Security audit
        run: cargo audit
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
  feat(ssh): add connection timeout handling
  fix(ftp): resolve lifetime issue in spawn_blocking
  refactor(core): extract wordlist loading to separate module
  docs(prd): add protocol implementation guide
  test(cli): add config validation test cases
```

### 10.3 Code Review Checklist

- [ ] Compiles without errors/warnings
- [ ] Clippy passes (no warnings)
- [ ] Tests pass
- [ ] Error handling covers all edge cases
- [ ] No unsafe code
- [ ] Protocol implementations handle timeout correctly
- [ ] No secrets/hardcoded credentials
- [ ] Log messages are informative
- [ ] CLI --help output is accurate
- [ ] PRD is updated if behavior changed

### 10.4 Adding a New Protocol

1. Create file `src/protocols/<name>.rs`
2. Implement `Protocol` trait for the struct
3. Register in `src/protocols/mod.rs`:
   - Add `pub mod <name>;`
   - Add to `get_protocol()` match
   - Add to `list_protocols()` vec
4. Test with Docker container
5. Add to PRD protocol matrix
6. Run `cargo build` and `cargo clippy`

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

### Phase 1: Foundation — v1.0.0 (Current)

| Task | Status | Priority |
|------|--------|----------|
| Project structure & module architecture | ✅ Done | P0 |
| Core engine: config, target, credential | ✅ Done | P0 |
| Protocol trait & registry | ✅ Done | P0 |
| SSH implementation | ✅ Done | P0 |
| FTP implementation | ✅ Done | P0 |
| Telnet implementation | ✅ Done | P0 |
| SMTP implementation | ✅ Done | P0 |
| POP3 implementation | ✅ Done | P0 |
| RDP implementation (connection check) | ✅ Done | P0 |
| MySQL implementation | ✅ Done | P0 |
| HTTP implementation | ✅ Done | P0 |
| Attack orchestrator (async worker pool) | ✅ Done | P0 |
| Output formatters (JSON, CSV, plain) | ✅ Done | P0 |
| Wordlist loader | ✅ Done | P0 |
| CLI argument parser | ✅ Done | P0 |
| Build & compilation fixes | ✅ Done | P0 |

### Phase 2: Protocol Expansion — v1.1.0

| Task | Priority | ETA |
|------|----------|-----|
| Full NLA/CredSSP for RDP | P0 | Phase 2 |
| HTTPS proxy support | P1 | Phase 2 |
| Credential spraying mode | P1 | Phase 2 |
| Response pattern detection | P1 | Phase 2 |
| Auto backoff & evasion | P2 | Phase 2 |
| Enhanced error messages | P1 | Phase 2 |
| Unit tests for all modules | P0 | Phase 2 |

### Phase 3: Advanced Features — v1.2.0

| Task | Priority | ETA |
|------|----------|-----|
| PostgreSQL protocol | P1 | Phase 3 |
| LDAP protocol | P1 | Phase 3 |
| Redis protocol | P1 | Phase 3 |
| CIDR & range target parsing | P1 | Phase 3 |
| Rule-based password mutation | P2 | Phase 3 |
| HTML report generation | P2 | Phase 3 |
| Proxy chain (multi-hop) | P2 | Phase 3 |
| Graceful SIGINT handler | P1 | Phase 3 |

### Phase 4: Enterprise — v2.0.0

| Task | Priority | ETA |
|------|----------|-----|
| SMB protocol | P1 | Phase 4 |
| SNMP protocol | P2 | Phase 4 |
| VNC protocol | P2 | Phase 4 |
| MSSQL protocol | P2 | Phase 4 |
| MongoDB protocol | P2 | Phase 4 |
| IMAP protocol | P2 | Phase 4 |
| Distributed attack mode (client/server) | P2 | Phase 4 |
| Plugin system for custom protocols | P2 | Phase 4 |
| REST API mode | P3 | Phase 4 |
| Web UI (Tauri?) | P3 | Phase 4 |

---

## 13. Appendix

### 13.1 Comparison Matrix — Veltrix vs Competition

| Feature | Veltrix | THC-Hydra | Medusa | Crowbar | Ncrack |
|---------|---------|-----------|--------|---------|--------|
| Language | Rust | C | C | Python | C |
| Async I/O | ✅ Tokio | ❌ | ❌ | ❌ | ❌ |
| Memory Safety | ✅ (compile) | ❌ | ❌ | ❌ | ❌ |
| Single Binary | ✅ (8MB) | ❌ | ❌ | ❌ (script) | ❌ |
| Cross-platform | ✅ | ✅ | ✅ | ✅ | ✅ |
| Protocol Count | 8+ | 50+ | 11 | 3 | 12 |
| SSH | ✅ | ✅ | ✅ | ✅ | ✅ |
| FTP | ✅ | ✅ | ✅ | ❌ | ✅ |
| Telnet | ✅ | ✅ | ✅ | ✅ | ✅ |
| SMTP | ✅ | ✅ | ✅ | ❌ | ✅ |
| POP3 | ✅ | ✅ | ✅ | ❌ | ✅ |
| RDP | ✅ (partial) | ✅ | ❌ | ❌ | ✅ |
| MySQL | ✅ | ✅ | ✅ | ❌ | ❌ |
| HTTP | ✅ | ✅ | ✅ | ❌ | ✅ |
| Proxy Support | ✅ SOCKS4/5/HTTP | ✅ | ❌ | ❌ | ❌ |
| Rate Limiting | ✅ | ✅ | ❌ | ❌ | ✅ |
| Resume Support | ✅ | ❌ | ❌ | ❌ | ❌ |
| JSON Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| CSV Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Progress Bar | ✅ | ❌ | ❌ | ❌ | ❌ |
| Colored Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Verbose Levels | 3 levels | 2 levels | 1 level | 1 level | 2 levels |

### 13.2 Dependencies & Justification

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
# Alasan: Timezone-aware timestamps, RFC3339 formatting
chrono = { version = "0.4", features = ["serde"] }

# Terminal — colored v2 + indicatif v0.17
# Alasan: Cross-platform colored output + async-compatible progress bar
colored = "2"
indicatif = { version = "0.17", features = ["tokio"] }

# Protocols
ssh2 = "0.9"          # libssh2 binding — mature, stable, widely used
suppaftp = "5"        # Pure Rust FTP — async, TLS support
lettre = "0.11"       # Pure Rust SMTP — STARTTLS, auth
mysql_async = "0.34"  # Pure Rust MySQL — async driver
reqwest = "0.12"      # HTTP client — proxy, TLS, cookies

# DNS
trust-dns-resolver = "0.23"  # Pure Rust DNS resolver
trust-dns-proto = "0.23"

# Async trait support
async-trait = "0.1"
```

### 13.3 Glossary

| Term | Definition |
|------|------------|
| **Brute Force** | Mencoba semua kombinasi credential secara sistematis |
| **Dictionary Attack** | Menggunakan wordlist berisi kemungkinan password |
| **Credential Spraying** | Satu password dicoba ke banyak akun untuk hindari lockout |
| **Combo List** | File berisi pasangan `username:password` |
| **NLA** | Network Level Authentication (RDP) — pre-login auth |
| **CredSSP** | Credential Security Support Provider — RDP NLA protocol |
| **SOCKS** | Protokol proxy untuk tunneling traffic (firewall bypass) |
| **Jitter** | Variasi acak pada timing untuk hindari deteksi |
| **Token Bucket** | Algoritma rate limiting dengan burst capacity |
| **IDOR** | Insecure Direct Object Reference |
| **Cartesian Product** | Setiap user × setiap password (kombinasi penuh) |
| **Work-stealing** | Scheduler yang mendistribusikan task ke idle workers |
| **Backoff** | Penundaan eksponensial setelah failure untuk hindari ban |

### 13.4 License & Attribution

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

---

## 14. Full API Reference & Function Contracts

### 14.1 `src/main.rs`

```rust
/// Entry point. Initializes runtime, parses args, runs attack.
///
/// # Preconditions
/// - No other Veltrix instance writing to same output file
/// - Network access to targets
/// - Wordlist files exist and are readable (if specified)
///
/// # Postconditions
/// - If successes > 0: exit(0)
/// - If successes == 0: exit(1)
/// - Output file written (if specified)
/// - Resume file saved (if specified)
///
/// # Panics
/// - Never (all errors handled via eprintln + exit)
#[tokio::main]
async fn main();
```

### 14.2 `src/cli.rs`

```rust
/// CLI argument struct, auto-generated by clap derive.
///
/// # Validation Rules (implemented in `into_config()`)
/// 1. At least one of --target or --target-file must be provided
/// 2. At least one --protocol must be specified (unless --list-protocols)
/// 3. Credentials via --user/--user-file or --combo (not both)
/// 4. --combo is mutually exclusive with --user/--user-file/--password/--password-file
/// 5. --single-user requires --user or --user-file
///
/// # Type Constraints
/// - --threads: 1..=1000
/// - --timeout: 1..=300 seconds
/// - --delay: 0..=60000 ms
/// - --port: 1..=65535
/// - --retries: 0..=10
#[derive(Parser, Debug)]
pub struct CliArgs;

impl CliArgs {
    /// Convert parsed CLI args into validated AttackConfig
    ///
    /// # Returns
    /// - Ok(AttackConfig) if validation passes
    /// - Err(String) with human-readable error message
    pub fn into_config(self) -> Result<AttackConfig, String>;

    /// Whether to show the startup banner
    pub fn should_show_banner(&self) -> bool;
}

/// Print the Veltrix ASCII banner to stdout
pub fn print_banner();

/// Print the supported protocols table to stdout
pub fn print_protocols();
```

### 14.3 `src/core/config.rs`

```rust
/// Complete attack configuration, created from CLI args.
///
/// # Invariants
/// - At least one of targets/target_file is non-empty/Some
/// - protocols is non-empty
/// - At least one credential source is configured
/// - threads >= 1
/// - timeout >= 1 second
#[derive(Clone, Debug)]
pub struct AttackConfig;

impl AttackConfig {
    /// Validate the configuration.
    ///
    /// # Returns
    /// - Ok(()) if all constraints are satisfied
    /// - Err(String) describing the first validation failure
    ///
    /// # Validates
    /// - Targets exist (CLI or file)
    /// - Protocols specified
    /// - Credentials configured (user/combo)
    pub fn validate(&self) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub enum OutputFormat { Json, Csv, Plain }
```

### 14.4 `src/core/target.rs`

```rust
/// A single attack target with resolved address.
///
/// # Invariants
/// - host is a valid hostname or IP string
/// - port is 1..=65535
/// - protocol is a registered protocol name
/// - address is None until resolve() is called
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub address: Option<SocketAddr>,
}

impl Target {
    /// Create a new target with default port for protocol.
    pub fn new(host: String, port: u16, protocol: &str) -> Self;

    /// Format display string with colors.
    pub fn display(&self) -> String;

    /// Resolve hostname to SocketAddr via DNS.
    ///
    /// # Timeout
    /// - Fails after `timeout` duration
    ///
    /// # Side effects
    /// - Sets self.address on success
    ///
    /// # Errors
    /// - DNS resolution failure
    /// - Timeout exceeded
    pub async fn resolve(&mut self, timeout: Duration) -> Result<(), String>;

    /// Return "host:port" string.
    pub fn addr_string(&self) -> String;

    /// Whether DNS resolution has been attempted and succeeded.
    pub fn is_resolved(&self) -> bool;
}

impl FromStr for Target;  // Parse "host:port" format

/// Parse target strings with protocol and port expansion.
///
/// # Algorithm
/// For each target string:
///   1. Try to parse as "host:port"
///   2. If port found: create one Target per protocol with that port
///   3. If no port: create one Target per (protocol, port) combination
///
/// # Returns
/// Cartesian product of (targets × protocols × ports) for targets without explicit ports
pub fn parse_targets(
    targets: &[String],
    protocols: &[String],
    ports: &[u16],
) -> Vec<Target>;
```

### 14.5 `src/core/credential.rs`

```rust
/// A username/password pair for authentication attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: String, password: String) -> Self;
    pub fn display(&self) -> String;
}

/// Parse a single combo list line.
///
/// # Format
/// "username:password"
///
/// # Rules
/// - Lines starting with '#' are comments (return None)
/// - Empty lines return None
/// - Must contain exactly one ':' separator
/// - Both username and password must be non-empty
///
/// # Returns
/// Some(Credential) for valid lines, None for comments/empty/invalid
pub fn parse_combo_line(line: &str) -> Option<Credential>;
```

### 14.6 `src/core/result.rs`

```rust
/// Result of a single authentication attempt.
///
/// # Invariants
/// - If success == true, error must be None
/// - If success == false, error may be Some or None
/// - timestamp is set at construction time
/// - duration_ms is measured from start of attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult;

impl AuthResult {
    /// Create a new AuthResult.
    ///
    /// # Parameters
    /// - duration: std::time::Duration from attempt start to now
    /// - error: None for success, Some(message) for failures with errors
    pub fn new(
        target_host: String, target_port: u16, protocol: &str,
        username: String, password: String,
        success: bool, duration: Duration, error: Option<String>,
    ) -> Self;

    /// Colored display string for terminal output.
    pub fn display(&self) -> String;
}

/// Summary of a complete attack session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSummary;
```

### 14.7 `src/core/wordlist.rs`

```rust
/// Load a wordlist file into a vector of strings.
///
/// # Format
/// - One entry per line
/// - Lines starting with '#' are ignored (comments)
/// - Empty lines are ignored
/// - Leading/trailing whitespace is trimmed
///
/// # Performance
/// Uses buffered async I/O for efficient file reading.
///
/// # Errors
/// - File not found
/// - Permission denied
/// - I/O errors during read
pub async fn load_wordlist(path: &Path) -> Result<Vec<String>, String>;

/// Load a combo list file (user:pass pairs).
///
/// # Format
/// "username:password" per line
/// - Lines starting with '#' are ignored
/// - Lines without ':' separator are silently skipped
///
/// # Returns
/// Vec of (username, password) tuples
pub async fn load_combo_list(path: &Path) -> Result<Vec<(String, String)>, String>;
```

### 14.8 `src/core/attack.rs` — Orchestrator (Critical Path)

```rust
/// Main attack orchestrator. Manages resource loading, worker pool, and result collection.
///
/// # Lifecycle
/// 1. new(config) — Loads all resources, prepares state
/// 2. run() — Executes attack, collects results, generates summary
///
/// # Resource Management
/// - Targets: resolved eagerly on construction
/// - Credentials: loaded eagerly on construction
/// - Proxies: loaded eagerly on construction
/// - Session: loaded lazily if resume file specified
///
/// # Concurrency
/// - Worker pool bounded by config.threads
/// - Rate limited by config.rate_limit
/// - Delayed by config.delay + jitter
pub struct AttackOrchestrator;

impl AttackOrchestrator {
    /// Initialize orchestrator with configuration.
    ///
    /// # Errors
    /// - Config validation fails
    /// - Target file not found/unreadable
    /// - Wordlist file not found/unreadable
    /// - All targets fail DNS resolution
    /// - Proxy file parse errors (warnings only)
    pub async fn new(config: AttackConfig) -> Result<Self, String>;

    /// Execute the full attack.
    ///
    /// # Algorithm
    /// 1. Create task queue: cartesian product of targets × credentials
    /// 2. Spawn worker pool: bounded by semaphore
    /// 3. For each task:
    ///    a. Rate limit check
    ///    b. Jitter delay
    ///    c. Lookup protocol handler from registry
    ///    d. Spawn async task for authentication
    ///    e. Collect result via FuturesUnordered
    /// 4. Process results: display + save + checkpoint
    /// 5. Check stop_on_first condition
    /// 6. Generate and return AttackSummary
    ///
    /// # Postconditions
    /// - All attempted results stored in self.results
    /// - Output file written (if configured)
    /// - Session file saved at checkpoint intervals and at end
    /// - Progress bar completed
    /// - Summary printed to stdout
    pub async fn run(&mut self) -> AttackSummary;

    // Private helpers:
    async fn load_targets(config: &AttackConfig) -> Result<Vec<Target>, String>;
    async fn load_credentials(config: &AttackConfig) -> Result<Vec<Credential>, String>;
    fn load_proxies(config: &AttackConfig) -> Vec<ProxyConfig>;
    fn get_proxy_for(&self, index: usize) -> Option<ProxyConfig>;
}
```

### 14.9 Protocol Trait Contract

```rust
/// Protocol authentication trait.
///
/// # Contract
/// - Must be Send + Sync (can be shared across threads)
/// - authenticate() must handle its own timeouts
/// - authenticate() must not panic
/// - Connection errors should include descriptive messages
/// - Auth failures should set error to None (normal flow)
/// - Returned AuthResult must use the provided start time
///
/// # Thread Safety
/// - Implementations are stateless (no self mutation)
/// - All state must be passed via parameters
///
/// # Adding New Protocols
/// 1. Create struct implementing this trait
/// 2. Register in get_protocol() factory
/// 3. Add to list_protocols()
/// 4. Ensure all contract conditions are met
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

### 14.10 Proxy Module Contract

```rust
/// Proxy configuration for tunneling connections.
///
/// # Support Matrix
/// - Http: CONNECT method, optional basic auth
/// - Socks4: No auth or username-based
/// - Socks5: No auth, username/password auth
/// - None: Direct connection (default)
#[derive(Debug, Clone)]
pub enum ProxyConfig {
    Http { host: String, port: u16, username: Option<String>, password: Option<String> },
    Socks4 { host: String, port: u16, username: Option<String> },
    Socks5 { host: String, port: u16, username: Option<String>, password: Option<String> },
    None,
}

impl ProxyConfig {
    /// Parse proxy URL string.
    ///
    /// # Format
    /// type://[user[:pass]@]host:port
    ///
    /// # Supported types
    /// http, https, socks4, socks5
    ///
    /// # Examples
    /// - "socks5://127.0.0.1:9050"
    /// - "http://user:pass@proxy.example.com:8080"
    /// - "socks4://10.0.0.1:1080"
    ///
    /// # Errors
    /// - Missing "://" separator
    /// - Invalid port number
    /// - Unsupported proxy type
    pub fn parse(input: &str) -> Result<Self, String>;
}

/// Load proxy list from file (one proxy per line).
pub fn load_proxy_list(path: &Path) -> Result<Vec<ProxyConfig>, String>;
```

### 14.11 Utils Contracts

```rust
// ── Rate Limiter ──
/// Token-bucket rate limiter for controlling attempt frequency.
pub struct RateLimiter;

impl RateLimiter {
    /// Create rate limiter.
    /// max_per_second = None disables rate limiting.
    pub fn new(max_per_second: Option<u64>) -> Self;

    /// Wait if rate limit would be exceeded.
    /// Blocking call (uses tokio::time::sleep internally).
    pub async fn wait_if_needed(&mut self);
}

/// Random delay generator for evasion.
pub struct JitterDelay;

impl JitterDelay {
    /// base_delay: minimum delay between attempts
    /// jitter_ms: random additional delay 0..jitter_ms
    pub fn new(base_delay: Duration, jitter_ms: u64) -> Self;
    pub async fn delay(&self);
}

// ── Session Manager ──
/// Serializable session state for resume functionality.
pub struct SessionState;

impl SessionState {
    pub fn new(targets: Vec<String>, protocols: Vec<String>, checkpoint_interval: u64) -> Self;
    pub fn is_tested(&self, username: &str, password: &str) -> bool;
    pub fn mark_tested(&mut self, username: &str, password: &str);
    pub fn add_success(&mut self, target: &str, protocol: &str, username: &str, password: &str);
    pub fn save(&self, path: &Path) -> Result<(), String>;
    pub fn load(path: &Path) -> Result<Self, String>;
}

// ── Output Handler ──
pub struct OutputHandler;

impl OutputHandler {
    pub fn new(format: OutputFormat, output_path: Option<&Path>) -> Result<Self, String>;
    pub fn init_progress(&mut self, total: u64);
    pub fn inc_progress(&self);
    pub fn finish_progress(&self);
    pub fn write_result(&mut self, result: &AuthResult);
    pub fn write_summary(&mut self, summary: &AttackSummary);
}
```

---

## 15. Algorithm Deep Dives

### 15.1 Token Bucket Rate Limiter

```
ALGORITHM: TokenBucket(wait_if_needed)
INPUT:  self (with max_per_second, tokens, last_update)
OUTPUT: (waits if necessary)

1. now ← Instant::now()
2. elapsed ← now - self.last_update
3. tokens_to_add ← elapsed.as_secs_f64() × self.max_per_second
4. self.tokens ← min(self.tokens + tokens_to_add, self.max_per_second)
5. self.last_update ← now
6.
7. if self.tokens < 1.0:
8.     wait_duration ← (1.0 - self.tokens) / self.max_per_second
9.     sleep(wait_duration)
10.    self.tokens ← 0.0
11. else:
12.    self.tokens ← self.tokens - 1.0

─────────────────────────────────────────────
EXAMPLE: max_per_second = 10, tokens = 0
  Wait 1: wait 100ms, tokens = 0
  Wait 2: wait 100ms, tokens = 0
  ...steady state: 10 requests per second
```

### 15.2 Target Queue Construction

```
ALGORITHM: ParseTargets
INPUT:  target_strings: [String], protocols: [String], ports: [u16]
OUTPUT: targets: [Target]

1. targets ← []
2.
3. FOR EACH target_str IN target_strings:
4.     parts ← target_str.split(':')
5.
6.     IF last_part IS valid_port:
7.         host ← parts[0..-1].join(':')
8.         port ← parts[-1]
9.         FOR EACH protocol IN protocols:
10.            targets.push(Target(host, port, protocol))
11.    ELSE:
12.        host ← target_str
13.        FOR EACH protocol IN protocols:
14.            FOR EACH port IN ports:
15.                targets.push(Target(host, port, protocol))
16.
17. RETURN targets

─────────────────────────────────────────────
EXAMPLE: targets=["10.0.0.1","10.0.0.2:3389"],
         protocols=["ssh","rdp"],
         ports=[22,3389]

Result:
  Target("10.0.0.1", 22, "ssh")
  Target("10.0.0.1", 3389, "ssh")
  Target("10.0.0.1", 22, "rdp")
  Target("10.0.0.1", 3389, "rdp")
  Target("10.0.0.2", 3389, "rdp")
```

### 15.3 Credential Cartesian Product

```
ALGORITHM: LoadCredentials
INPUT:  config: AttackConfig
OUTPUT: credentials: [Credential]

1. IF config.combo_file IS Some:
2.     RETURN load_combo_list(config.combo_file)  // user:pass pairs
3.
4. users ← config.users OR load_wordlist(config.user_file)
5. passwords ← config.passwords OR load_wordlist(config.password_file)
6.
7. IF config.single_user_mode:
8.     // Single user × all passwords
9.     first_user ← users[0]
10.    FOR EACH pass IN passwords:
11.        credentials.push(Credential(first_user, pass))
12. ELSE:
13.    // Cartesian product: all users × all passwords
14.    FOR EACH user IN users:
15.        FOR EACH pass IN passwords:
16.            credentials.push(Credential(user, pass))
17.
18. RETURN credentials
```

### 15.4 Worker Pool Execution

```
ALGORITHM: RunAttack (simplified)
INPUT:  self (with targets, credentials, config)
OUTPUT: summary: AttackSummary

1. total_attempts ← len(targets) × len(credentials)
2. semaphore ← Semaphore(config.threads)
3. stream ← FuturesUnordered::new()
4.
5. FOR EACH (target_idx, cred_idx) IN cartesian(targets, credentials):
6.     target ← targets[target_idx]
7.     cred ← credentials[cred_idx]
8.     proxy ← get_proxy_for(attempt_index)
9.     handler ← get_protocol(target.protocol)
10.
11.    IF session.is_tested(cred.user, cred.pass): SKIP
12.
13.    rate_limiter.wait_if_needed().await
14.    jitter.delay().await
15.
16.    task ← tokio::spawn(async {
17.        permit ← semaphore.acquire()
18.        FOR retry IN 0..=config.retries:
19.            result ← handler.authenticate(target, cred, timeout, proxy)
20.            IF result.success: BREAK
21.            sleep(500ms × 2^retry)  // exponential backoff
22.        RETURN result
23.    })
24.
25.    stream.push(task)
26.
27. WHILE let Some(result) = stream.next().await:
28.     IF result.success: successes++
29.     output.write_result(result)
30.     results.push(result)
31.     IF config.stop_on_first AND any_success: BREAK
32.
33. RETURN AttackSummary { ... }
```

### 15.5 Exponential Backoff

```
ALGORITHM: ExponentialBackoff(retry_count)
INPUT:  retry_count: u32 (0-based)
OUTPUT: wait_duration: Duration

1. base_ms ← 500
2. wait_ms ← base_ms × 2^retry_count     // 500, 1000, 2000, 4000, ...
3. wait_ms ← min(wait_ms, 30000)          // cap at 30 seconds
4. RETURN Duration::from_millis(wait_ms)

─────────────────────────────────────────────
Retry 0:  500ms
Retry 1:  1000ms
Retry 2:  2000ms
Retry 3:  4000ms
Retry 4:  8000ms
Retry 5:  16000ms
Retry 6+: 30000ms (capped)
```

### 15.6 Proxy Round-Robin Selection

```
ALGORITHM: GetProxyFor(attempt_index)
INPUT:  attempt_index: usize
OUTPUT: proxy: Option<ProxyConfig>

1. IF proxies.is_empty(): RETURN None
2. index ← attempt_index % len(proxies)
3. RETURN Some(proxies[index])

─────────────────────────────────────────────
EXAMPLE: 3 proxies, 10 attempts
  Attempt 0 → proxy[0]
  Attempt 1 → proxy[1]
  Attempt 2 → proxy[2]
  Attempt 3 → proxy[0]
  Attempt 4 → proxy[1]
  ...
```

### 15.7 Telnet Negotiation Handler

```
ALGORITHM: HandleTelnetNegotiation(buf)
INPUT:  buf: [u8] (raw bytes from server)
OUTPUT: response: [u8] (IAC responses)

1. response ← []
2. i ← 0
3. WHILE i < len(buf):
4.     IF buf[i] == IAC(255) AND i + 2 < len(buf):
5.         command ← buf[i+1]
6.         option ← buf[i+2]
7.         IF command == DO(253):
8.             response += [IAC, WONT(252), option]   // refuse all DO
9.         ELIF command == WILL(251):
10.            response += [IAC, DONT(254), option]   // reject all WILL
11.        // DONT(254) and WONT(252): no response needed
12.        i += 3
13.    ELSE:
14.        i += 1
15. RETURN response

─────────────────────────────────────────────
TELNET CONSTANTS:
  IAC  = 255  (Interpret As Command)
  DONT = 254  (Do Not)
  DO   = 253  (Do)
  WONT = 252  (Will Not)
  WILL = 251  (Will)
```

---

## 16. Data Flow Diagrams (DFD)

### 16.1 DFD Level 0 — Context Diagram

```
                         ┌─────────────────┐
                         │     Operator    │
                         │     (User)      │
                         └────────┬────────┘
                                  │
                    CLI Arguments  │  Output
                    ┌─────────────┴──────────────┐
                    │                            │
                    ▼                            ▼
              ┌──────────────────────────────────────┐
              │              VELTRIX                 │
              │         Brute Force Toolkit           │
              └──────────┬──────────────────┬────────┘
                         │                  │
                         ▼                  ▼
              ┌──────────────────┐  ┌──────────────────┐
              │   Target System  │  │   File System    │
              │   (SSH/FTP/etc)  │  │ (wordlists/output)│
              └──────────────────┘  └──────────────────┘
```

### 16.2 DFD Level 1 — Process Decomposition

```
                            ┌─────────────┐
                            │   CLI Args  │
                            └──────┬──────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────┐
│                    MAIN PROCESS                     │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐ │
│  │  Parse CLI │──▶│  Validate  │──▶│  Initialize  │ │
│  │    Args    │  │  Config    │  │  Orchestrator │ │
│  └────────────┘  └────────────┘  └──────┬───────┘ │
└─────────────────────────────────────────┼─────────┘
                                          │
                                          ▼
                ┌────────────────────────────────────┐
                │         ATTACK ORCHESTRATOR         │
                │                                     │
                │  ┌──────────┐    ┌────────────────┐ │
    ┌───────────│──│ Load     │───▶│ Create Task    │ │
    │           │  │ Wordlists│    │ Queue          │ │
    │           │  └──────────┘    └────────┬───────┘ │
    │           │                           │         │
    │           │  ┌────────────────────────┘         │
    │           │  │                                  │
    │           │  ▼                                  │
    │           │  ┌──────────────────────────────┐   │
    │           │  │      WORKER POOL             │   │
    │           │  │  ┌─────┐ ┌─────┐ ┌─────┐   │   │
    │           │  │  │ W1  │ │ W2  │ │ W3  │...│   │
    │           │  │  └──┬──┘ └──┬──┘ └──┬──┘   │   │
    │           │  └─────┼───────┼───────┼──────┘   │
    │           │        │       │       │          │
    ▼           │        ▼       ▼       ▼          │
┌────────┐     │  ┌────────────────────────────┐    │
│  File  │     │  │    PROTOCOL HANDLERS       │    │
│ System │◀────│  │  SSH │ FTP │ Telnet │ ... │    │
└────────┘     │  └────────────────────────────┘    │
               │        │       │       │          │
               │        ▼       ▼       ▼          │
               │  ┌────────────────────────────┐    │
               │  │     RESULT COLLECTOR       │    │
               │  └────────────┬───────────────┘    │
               └───────────────┼────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
             ┌────────────┐      ┌──────────────┐
             │   Stdout   │      │  Output File │
             │  (display) │      │ (JSON/CSV)   │
             └────────────┘      └──────────────┘
```

### 16.3 DFD Level 2 — Worker Process Detail

```
                    ┌──────────────────────┐
                    │   Task Queue Item    │
                    │  { target, cred }    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Rate Limiter      │
                    │  (Token Bucket)      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Jitter Delay      │
                    │  base + random       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Protocol Registry   │
                    │  get_protocol(name)  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Protocol.authenticate│
                    │  ┌─────────────────┐ │
                    │  │ TCP Connect     │ │────▶ Target:Port
                    │  ├─────────────────┤ │
                    │  │ Auth Handshake  │ │────▶ Protocol exchange
                    │  ├─────────────────┤ │
                    │  │ Return Result   │ │
                    │  └─────────────────┘ │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   AuthResult         │
                    │  { success, error,   │
                    │    duration, ... }   │
                    └──────────────────────┘
```

---

## 17. Configuration File Format (veltrix.json)

### 17.1 JSON Schema

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
        "targets": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Target host:port entries"
        },
        "target_file": {
          "type": "string",
          "description": "Path to target list file"
        },
        "protocols": {
          "type": "array",
          "items": { "type": "string", "enum": ["ssh", "ftp", "telnet", "smtp", "pop3", "rdp", "mysql", "http"] },
          "minItems": 1
        },
        "ports": {
          "type": "array",
          "items": { "type": "integer", "minimum": 1, "maximum": 65535 }
        }
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
        "single_user": { "type": "boolean", "default": false }
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
        "proxy_file": { "type": "string" }
      }
    },
    "output": {
      "type": "object",
      "properties": {
        "file": { "type": "string" },
        "format": { "type": "string", "enum": ["plain", "json", "csv"], "default": "plain" },
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

### 17.2 Example Configuration

```json
{
  "attack": {
    "targets": ["192.168.1.1", "10.0.0.5:3389"],
    "target_file": "/path/to/targets.txt",
    "protocols": ["ssh", "rdp", "mysql"],
    "ports": [22, 3389, 3306]
  },
  "credentials": {
    "user_file": "users.txt",
    "password_file": "rockyou.txt",
    "single_user": false
  },
  "performance": {
    "threads": 20,
    "timeout": 15,
    "delay": 100,
    "rate_limit": 50,
    "retries": 2
  },
  "proxy": {
    "proxy_file": "proxies.txt"
  },
  "output": {
    "file": "results.json",
    "format": "json",
    "resume": "session.json"
  },
  "behavior": {
    "stop_on_first": true,
    "verbose": false,
    "quiet": false
  }
}
```

### 17.3 Configuration Precedence

```
1. CLI arguments (highest priority)
2. Config file (medium priority)
3. Built-in defaults (lowest priority)

CLI arguments ALWAYS override config file values.
Config file is specified via --config <path> (future feature).
```

---

## 18. Threat Model (STRIDE Analysis)

### 18.1 Overview

Veltrix adalah security tool yang secara inheren berinteraksi dengan sistem target. Threat model berikut menganalisis risiko terhadap **pengguna Veltrix** dan **sistem yang diuji**.

### 18.2 STRIDE per Component

| Component | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|-----------|----------|-----------|-------------|-----------------|-----|-----------|
| CLI Parser | Low | Low | N/A | N/A | Low | N/A |
| Config | Low | Medium | Low | Medium | Low | Low |
| Wordlist Loader | Low | High | Low | N/A | Medium | N/A |
| Target Resolver | Medium | Low | N/A | N/A | Low | N/A |
| Protocol Handlers | High | Low | N/A | High | High | N/A |
| Proxy Module | High | Medium | N/A | High | Low | N/A |
| Output Handler | Low | Medium | High | High | Low | N/A |
| Session Manager | Low | High | High | High | Low | N/A |
| Rate Limiter | N/A | N/A | N/A | N/A | N/A | N/A |

### 18.3 Detailed Threat Descriptions

#### T1: Malicious Wordlist (Tampering — High)
- **Threat**: Attacker provides wordlist containing shellcode or trigger strings
- **Impact**: Low (Rust memory safety prevents buffer overflow)
- **Mitigation**: Input validation, memory-safe language
- **Detection**: File hash verification (future)

#### T2: Credential Leakage (Info Disclosure — High)
- **Threat**: Output file with discovered credentials is exposed
- **Impact**: Critical (exposed credentials)
- **Mitigation**: File permissions warning, encryption support (future)
- **Detection**: File access audit

#### T3: Session Poisoning (Tampering — High)
- **Threat**: Attacker modifies session.json to skip or repeat attempts
- **Impact**: Medium (incorrect results)
- **Mitigation**: Session file checksum (future)
- **Note**: MitM required, attacker needs filesystem access

#### T4: Rogue Proxy (Spoofing — High)
- **Threat**: Malicious proxy captures credentials in transit
- **Impact**: Critical (credential theft)
- **Mitigation**: SOCKS5 proxy auth, user-verified proxy list
- **Warning**: Documented in security guidelines

#### T5: DNS Spoofing (Spoofing — Medium)
- **Threat**: Attacker poisons DNS to redirect traffic
- **Impact**: High (wrong target)
- **Mitigation**: IP-based targets recommended for sensitive use

#### T6: Rate Limit Bypass (DoS — Medium)
- **Threat**: Target rate limiting causes connection blocks
- **Impact**: Medium (target lockout)
- **Mitigation**: Configurable rate limiting, exponential backoff
- **Warning**: User responsibility to configure appropriately

#### T7: Resource Exhaustion (DoS — High)
- **Threat**: Large wordlists consume all available memory
- **Impact**: Medium (OOM kill)
- **Mitigation**: Streaming wordlist loading (future), memory limits
- **Current**: All wordlists loaded into memory

### 18.4 Security Assumptions

| # | Assumption | Risk if Broken | Mitigation |
|---|------------|----------------|------------|
| 1 | User has permission to test targets | Legal liability | Warning banner |
| 2 | Wordlist files are trusted | Credential leak | Warn on untrusted paths (future) |
| 3 | Network between Veltrix and target is secure | Credential sniffing | Proxy encryption (future) |
| 4 | Output files are stored securely | Credential exposure | File permission validation (future) |
| 5 | Proxy list is trusted | Credential theft | User verification |
| 6 | System running Veltrix is not compromised | Complete compromise | N/A (trusted execution environment) |

---

## 19. Operational Runbook

### 19.1 Installation

```bash
# Option 1: Download pre-built binary (future)
curl -L https://github.com/aniippxploit/veltrix/releases/latest/download/veltrix-linux-amd64.tar.gz | tar xz
sudo mv veltrix /usr/local/bin/

# Option 2: Build from source
git clone https://github.com/aniippxploit/veltrix.git
cd veltrix
cargo build --release
sudo cp target/release/veltrix /usr/local/bin/

# Option 3: Cargo install (future)
cargo install veltrix
```

### 19.2 Basic Operations

```bash
# 1. List supported protocols
veltrix -L

# 2. Basic SSH attack
veltrix -t 192.168.1.1 -P ssh -U users.txt -W passwords.txt

# 3. Multi-target multi-protocol
veltrix -T targets.txt -P ssh,ftp,telnet -U users.txt -W passwords.txt -x 20

# 4. With combo list and JSON output
veltrix -t 10.0.0.5:3389 -P rdp -C combos.txt -o results.json -f json

# 5. Via SOCKS5 proxy with rate limiting
veltrix -t mail.example.com:25 -P smtp -U users.txt -w "Welcome2024" \
  --proxy socks5://127.0.0.1:9050 --rate-limit 5

# 6. Resume interrupted session with new passwords
veltrix --resume session.json -W additional-passwords.txt

# 7. Quiet mode (show only successes)
veltrix -T targets.txt -P ssh -U users.txt -W rockyou.txt -q
```

### 19.3 Common Workflows

#### Workflow A: Internal Network Password Audit
```bash
# 1. Scan for live hosts on subnet
nmap -sn 192.168.1.0/24 -oG - | grep Up | awk '{print $2}' > live_hosts.txt

# 2. Scan for open ports
nmap -sS -p 22,21,23,3389 -iL live_hosts.txt -oG - | \
  grep -E "22/open|21/open|23/open|3389/open" | \
  awk '{print $2 ":" $NF}' > targets.txt

# 3. Run Veltrix against discovered services
veltrix -T targets.txt -P ssh,ftp,telnet,rdp -U common_users.txt \
  -W weak_passwords.txt -o audit_results.json -f json
```

#### Workflow B: Password Spraying (Anti-Lockout)
```bash
# Single password across all users with delay
veltrix -t mail.example.com:25 -P smtp -U users.txt -w "Spring2024!" \
  --delay 10000 --rate-limit 1 --stop-on-first -o spray_results.csv -f csv
```

#### Workflow C: RDP Credential Check
```bash
# Use combo list, stop at first success per target
veltrix -T rdp_targets.txt -P rdp -C domain_combos.txt \
  --timeout 15 -x 5 -o rdp_valid.txt -f plain
```

### 19.4 Troubleshooting Guide

| Problem | Symptom | Diagnosis | Solution |
|---------|---------|-----------|----------|
| Connection refused | Error: "Connection refused" | Target down or blocked | Check target status, firewall |
| Timeout | Error: "Timeout" | Network/firewall issues | Increase --timeout, check connectivity |
| Slow speed | Low attempts/sec | DNS resolution | Use IP addresses, reduce --threads |
| No results | All failed | Wrong credentials | Verify wordlist format, combo format |
| Rate limited | Errors increase | Target blocking | Add --delay, reduce --rate-limit |
| File not found | "Failed to open" | Wrong path | Use absolute paths, check permissions |
| Wrong protocol | Protocol errors | Port mismatch | Specify port explicitly: host:port |
| Session corrupt | Resume fails | Invalid JSON | Delete session file, start fresh |

### 19.5 Debugging

```bash
# Enable full debug logging
RUST_LOG=debug veltrix -t 10.0.0.1 -P ssh -U test -w test --no-banner

# Trace level (extremely verbose)
RUST_LOG=trace veltrix -t 10.0.0.1 -P ssh -U test -w test 2>&1 | head -100

# With verbose flag
veltrix -v -t 10.0.0.1 -P ssh -U test -w test --no-banner

# Test specific protocol
veltrix -L  # Check protocol availability
```

### 19.6 Logging Configuration

```
Environment Variable: RUST_LOG
Values:
  error   → Only errors
  warn    → Warnings + errors (default)
  info    → Informational + warnings + errors
  debug   → Debug + info + warnings + errors
  trace   → Everything (extremely verbose)
```

### 19.7 Performance Tuning Guide

| Scenario | Threads | Timeout | Delay | Rate Limit | Rationale |
|----------|---------|---------|-------|------------|-----------|
| Local network audit | 50 | 5s | 0 | None | Fast internal network |
| WAN/Internet targets | 20 | 15s | 100ms | 100/s | Account for latency |
| Credential spraying | 5 | 10s | 5000ms | 1/s | Avoid lockout |
| Aggressive (red team) | 100 | 3s | 0 | None | Maximum speed |
| Stealth mode | 3 | 20s | 10000ms | 0.1/s | Minimal detection |
| RDP brute force | 10 | 15s | 500ms | 20/s | RDP is slow per attempt |

### 19.8 Maintenance

```bash
# Audit dependencies for vulnerabilities
cargo audit

# Update dependencies
cargo update

# Check for outdated crates
cargo outdated

# Run all tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings
```

---

## 20. Risk Register & Quality Gates

### 20.1 Risk Register

| ID | Risk | Probability | Impact | RPN | Mitigation | Owner |
|----|------|------------|--------|-----|------------|-------|
| R1 | Protocol library API changes break compilation | Medium | High | 15 | Pin versions in Cargo.lock, regular updates | Dev |
| R2 | Memory exhaustion with large wordlists | High | Medium | 12 | Streaming loader (Phase 2) | Dev |
| R3 | Target server blocks IP due to excessive attempts | High | Medium | 12 | Rate limiting, proxy rotation | User |
| R4 | DNS resolution becomes bottleneck | Medium | Medium | 9 | IP targets, batch resolution | Dev |
| R5 | False positive auth results | Medium | High | 12 | Protocol-specific validation | QA |
| R6 | C compilation failure for libssh2-sys | Low | High | 6 | Fallback to pure Rust SSH (future) | Dev |
| R7 | Multi-threaded race condition | Low | Critical | 5 | Arc + Mutex, async ownership | Dev |
| R8 | Output file corruption on crash | Low | High | 6 | Atomic writes, checkpoint save | Dev |
| R9 | Unauthorized usage of tool | Medium | High | 12 | Banner warning, no piracy features | Legal |
| R10 | Dependency supply-chain attack | Low | Critical | 5 | cargo-audit, lockfile, mirroring | Dev |

**RPN = Probability × Impact (1-5 scale each, max 25)**

### 20.2 Quality Gates

#### Gate 1: Compilation
```
□ cargo build --release passes with zero errors
□ cargo clippy passes with zero warnings
□ cargo fmt --check passes
□ Binary size < 10MB (stripped)
```

#### Gate 2: Unit Tests
```
□ All existing tests pass
□ New protocol has minimum 5 test cases
□ Edge case coverage (empty files, invalid formats)
□ Test coverage > 70% (measured via tarpaulin)
```

#### Gate 3: Integration Tests
```
□ Docker test infrastructure operational
□ Each protocol tested against real service container
□ Positive: known valid credentials → success
□ Negative: invalid credentials → failure
□ Timeout handling verified (connect to non-existent host)
```

#### Gate 4: Performance
```
□ Single-threaded: meets 50% of performance target
□ Multi-threaded (10 threads): meets 100% of target
□ Memory usage < 100MB for 10,000 credentials
□ No memory leaks over 5-minute run (steady RSS)
```

#### Gate 5: Security
```
□ cargo audit passes (no known vulnerabilities)
□ No unsafe blocks in new code
□ No hardcoded credentials in codebase
□ All file paths are sanitized
```

#### Gate 6: Documentation
```
□ PRD updated with new feature details
□ CLI --help output matches implementation
□ Code has doc comments on public API
□ README updated with examples
```

### 20.3 Definition of Done

```
For a feature to be considered "Done", ALL must be true:

□ Code compiles without errors or warnings
□ Tests pass (unit + integration)
□ Code reviewed by at least 1 peer
□ Documentation updated (PRD/README)
□ Feature works end-to-end in Docker test environment
□ Error handling covers all edge cases
□ No regression in existing functionality
□ Performance meets threshold targets
□ Security review completed for sensitive features
```

---

## 21. Known Limitations & Technical Debt

### 21.1 Current Limitations

| # | Limitation | Impact | Planned Fix | Priority |
|---|------------|--------|-------------|----------|
| 1 | RDP auth is connection-check only (no NLA) | False positives for RDP | Full CredSSP implementation | P1 |
| 2 | All wordlists loaded into memory | OOM with huge files (>10GB) | Streaming file reader | P1 |
| 3 | No CIDR/range target expansion | Manual target enumeration | CIDR parser (ipnetwork crate) | P2 |
| 4 | No rule-based password mutation | Limited to static wordlists | Hashcat-style rules engine | P2 |
| 5 | Single machine only | Limited total throughput | Distributed mode (client/server) | P2 |
| 6 | No plugin system | Hard to add custom protocols | WASM-based plugin system | P3 |
| 7 | No REST API | Cannot integrate with workflows | Actix-web HTTP server | P3 |
| 8 | No web UI | CLI-only operation | Tauri-based desktop app | P3 |
| 9 | HTTP form auth not implemented | Only Basic Auth | Form field configuration | P1 |
| 10 | No config file support | Must use CLI flags for everything | veltrix.json config parser | P1 |
| 11 | SOCKS4 proxy not used by protocols | Only HTTP protocol uses proxy | Generic proxy abstraction | P1 |
| 12 | No keepalive/connection reuse | TCP overhead per attempt | Connection pool per target | P2 |

### 21.2 Technical Debt Items

| # | Item | Severity | Effort | Reason | Created |
|---|------|----------|--------|--------|---------|
| TD1 | ssh2 uses C library (libssh2-sys) | Medium | 2 weeks | Pure Rust SSH unavailable at start | v1.0 |
| TD2 | FTP protocol uses blocking call via spawn_blocking | Low | 2 days | suppaftp has no async API | v1.0 |
| TD3 | SMTP protocol uses spawn_blocking | Low | 2 days | lettre synchronous transport | v1.0 |
| TD4 | No proper error types (all String) | Medium | 1 week | Quick prototyping | v1.0 |
| TD5 | AttackOrchestrator.run() is too long | Medium | 3 days | All logic in single method | v1.0 |
| TD6 | No integration tests (yet) | High | 2 weeks | Test infra not set up | v1.0 |
| TD7 | Dead code: display(), parse_combo_line() | Low | 1 hour | Future-proofing | v1.0 |
| TD8 | Hardcoded port list in default ports | Low | 1 hour | Should be protocol-derived | v1.0 |
| TD9 | Resume session save/N checkpoint is hardcoded | Low | 1 day | Should be configurable | v1.0 |
| TD10 | No graceful shutdown on SIGINT | Medium | 2 days | Need signal handler | v1.0 |

### 21.3 Refactoring Roadmap

```
Phase 1 (v1.1):
  □ TD4: Custom error types (AttackError enum)
  □ TD5: Extract worker pool into separate struct
  □ TD6: Set up Docker test infrastructure
  □ TD10: SIGINT handler for graceful shutdown
  □ TD9: Make checkpoint interval configurable

Phase 2 (v1.2):
  □ TD1: Evaluate pure Rust SSH alternatives
  □ TD7: Clean up dead code
  □ TD8: Protocol-derived default ports
  □ TD2: Find async FTP library

Phase 3 (v2.0):
  □ TD3: Evaluate async SMTP alternatives
  □ Architecture: Extract coordinator from orchestrator
```

### 21.4 Performance Optimization Queue

```
# Priority-ordered optimization opportunities

P1: Reduce DNS resolution overhead
    - Current: Sequential resolution
    - Fix: Concurrent batch resolution
    - Expected gain: 10-100x for large target sets

P1: Implement TCP connection reuse
    - Current: New connection per attempt
    - Fix: Connection pool per target
    - Expected gain: 2-5x for SSH/FTP

P2: Streaming wordlist processing
    - Current: Load entire file into Vec<String>
    - Fix: Stream from disk, yield iteratively
    - Expected gain: Enable unlimited wordlist sizes

P2: Parallel target resolution
    - Current: Sequential resolve()
    - Fix: tokio::join! or FuturesUnordered
    - Expected gain: Linear speedup with thread count

P3: Reduce memory per AuthResult
    - Current: Full strings stored
    - Fix: String interning or ID-based storage
    - Expected gain: 50% memory reduction for results
```

---

## 22. Appendix B: Environment & Dependencies

### 22.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 4+ cores |
| RAM | 128 MB | 1 GB |
| Disk | 50 MB (binary) | 500 MB (with build artifacts) |
| OS | Linux x86_64 | Linux x86_64 (also macOS, Windows WIP) |
| libc | glibc 2.17+ | glibc 2.31+ |
| libssh2 | Bundled (static) | Bundled (static) |
| OpenSSL | Bundled via openssl-sys | System or bundled |
| Network | Outbound to targets | Outbound + DNS resolution |

### 22.2 Build Dependencies

```bash
# Required for building from source
rustc >= 1.75.0
cargo >= 1.75.0
cmake >= 3.0     (for libssh2-sys)
pkg-config        (for dependency discovery)

# Optional
clang             (faster bindgen for libssh2-sys)
upx               (binary compression: upx --best veltrix)
```

### 22.3 Rust Toolchain

```bash
# Install via rustup
rustup toolchain install stable  # 1.75+ recommended
rustup default stable
rustup component add clippy rustfmt

# Verify
rustc --version    # rustc 1.75.0+
cargo --version    # cargo 1.75.0+
```

### 22.4 Docker Development Environment

```dockerfile
FROM rust:1.75-slim-bookworm

RUN apt-get update && apt-get install -y \
    cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release
CMD ["./target/release/veltrix"]
```

---

## 23. Appendix C: Output Examples

### 23.1 Plain Text Output

```
╔══════════════════════════════════════════════════════╗
║                    VELTRIX v1.0                      ║
║         Multi-Protocol Brute Force Toolkit           ║
╚══════════════════════════════════════════════════════╝

⚠  WARNING: Only use on systems you own or have permission to test.

[INFO] Loaded 3 targets
[INFO] Loaded 10 users × 100 passwords = 1000 combinations
[INFO] Starting attack with 20 workers

[SUCCESS] 192.168.1.1:22 [ssh] root:admin (1250ms)
[FAILED]  192.168.1.1:22 [ssh] root:123456 (1100ms)
[FAILED]  192.168.1.1:22 [ssh] root:password (1050ms)
...

═══════════════════════════════════════════
           ATTACK COMPLETE
═══════════════════════════════════════════
  Started:       2024-01-01 00:00:00
  Ended:         2024-01-01 01:23:45
  Duration:      5025.45s
  Targets:       3
  Credentials:   1000
  Attempts:      3000
  Successes:     2
  Failures:      2995
  Errors:        3
```

### 23.2 JSON Output

```json
{
  "veltrix_version": "1.0.0",
  "attack_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-01T01:23:45Z",
  "config": {
    "targets_count": 3,
    "credentials_count": 1000,
    "protocols": ["ssh", "ftp"],
    "threads": 20,
    "timeout_sec": 10
  },
  "summary": {
    "total_attempts": 3000,
    "successes": 2,
    "failures": 2995,
    "errors": 3
  },
  "results": [
    {
      "target": "192.168.1.1",
      "port": 22,
      "protocol": "ssh",
      "username": "root",
      "password": "admin",
      "success": true,
      "timestamp": "2024-01-01T00:05:23.123Z",
      "duration_ms": 1250,
      "error": null
    }
  ]
}
```

### 23.3 CSV Output

```csv
target,port,protocol,username,password,success,timestamp,duration_ms,error
192.168.1.1,22,ssh,root,admin,true,2024-01-01T00:05:23.123Z,1250,
192.168.1.1,22,ssh,root,123456,false,2024-01-01T00:05:24.456Z,1100,
192.168.1.1,21,ftp,admin,admin,true,2024-01-01T00:06:00.789Z,980,
10.0.0.5,3389,rdp,administrator,Passw0rd,true,2024-01-01T01:00:00.000Z,3200,
```

---

## 24. Appendix D: Code Quality Metrics

### 24.1 Current Codebase Metrics

```
─────────────────────────────────────────────────
  Metric                  Target      Current
─────────────────────────────────────────────────
  Lines of Code           < 5000      ~2500
  Functions               -           ~40
  Public API surface      < 50        ~25
  Test coverage           > 70%       0% (WIP)
  Documentation ratio     > 20%       ~15%
  Cyclomatic complexity   < 10        ~5
  Unsafe blocks           0           0
  Clippy warnings         0           ~8 (minor)
  Compile time            < 30s       ~3 min (cold)
  Binary size (release)   < 10MB      8.4MB
─────────────────────────────────────────────────
```

### 24.2 Quality Tooling

```bash
# All-in-one quality check
cargo fmt --check && cargo clippy -- -D warnings && cargo test && cargo audit

# Individual tools
cargo fmt              # Formatting
cargo clippy           # Linting
cargo test             # Testing
cargo audit            # Security audit
cargo outdated         # Dependency freshness
cargo tarpaulin        # Code coverage (3rd party)
cargo bench            # Benchmarking
cargo bloat            # Binary size analysis
```

---

## 25. Appendix E: Quick Reference Cards

### 25.1 CLI Quick Reference

```
TARGETS:
  -t, --target HOST:PORT         Single target
  -T, --target-file FILE         Target list file

PROTOCOLS:
  -P, --protocol PROTO           ssh,ftp,telnet,smtp,pop3,rdp,mysql,http
  -L, --list-protocols           List all

CREDENTIALS:
  -u, --user USER                Single username
  -U, --user-file FILE           Username list
  -w, --password PASS            Single password
  -W, --password-file FILE       Password list
  -C, --combo FILE               user:pass combo list
  --single-user                  One user × all passwords

PERFORMANCE:
  -x, --threads N                Workers (default: 10)
  --timeout SEC                  Connection timeout (default: 10s)
  --delay MS                     Inter-attempt delay (default: 0)
  --rate-limit N                 Max att/sec (0 = unlimited)
  --retries N                    Connection retries (default: 1)

PROXY:
  --proxy TYPE://HOST:PORT       Single proxy
  --proxy-file FILE              Proxy rotation list

OUTPUT:
  -o, --output FILE              Output file
  -f, --format FMT               plain, json, csv (default: plain)
  --resume FILE                  Resume session

BEHAVIOR:
  --stop-on-first                Stop at first success
  -v, --verbose                  Verbose
  -q, --quiet                    Successes only
  --no-banner                    Hide banner
  -h, --help                     Help
  -V, --version                  Version
```

### 25.2 Protocol Quick Reference

```
Protocol  Default Port  Auth Methods         Library         Status
────────  ───────────── ──────────────────── ─────────────── ──────
ssh       22            password, key         ssh2            ✅
ftp       21            plain, TLS/SSL        suppaftp        ✅
telnet    23            plaintext             raw TCP         ✅
smtp      25/465/587    LOGIN, PLAIN, CRAM-MD5 lettre         ✅
pop3      110/995       USER/PASS             raw TCP/TLS     ✅
rdp       3389          NLA (partial)         raw TCP         ⚠️
mysql     3306          mysql_native_password mysql_async     ✅
http      80/443        Basic                 reqwest         ✅
```

### 25.3 Exit Codes

```
0   → Success (at least one credential found)
1   → No successes or configuration error
```

### 25.4 Environment Variables

```
RUST_LOG    → error | warn | info | debug | trace
```

---

> **Document Version:** 2.1  
> **Last Updated:** 2024-07-24  
> **Next Review:** Phase 2 completion  
> **Maintainer:** aniippxploit
