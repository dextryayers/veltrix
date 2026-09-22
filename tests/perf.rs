/// Bench resmi v2.0 (F9.3): skenario planner end-to-end via `--dry-run`
/// (tanpa network I/O, reproducible di CI).
///
/// Skenario plan1: single target, multi target/CIDR, 1M password,
/// proxy on vs off, rules expansion.
///
/// Jalankan: `cargo test --test perf -- --nocapture`
/// Angka resmi diukur ulang di profile release, lihat `docs/bench-v2.md`.
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_veltrix"))
}

fn small_files(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    // File NAMA-UNIK per pemanggil? Tidak — nama tetap, tapi TIDAK PERNAH
    // ditimpa setelah dibuat (bandingkan perf_dryrun_1m_passwords yang memakai
    // file user-nya sendiri agar test paralel tidak race).
    let u = dir.join("perf_users3.txt");
    let p = dir.join("perf_passwords4.txt");
    if !u.exists() {
        std::fs::write(&u, "admin\nroot\nuser\n").unwrap();
    }
    if !p.exists() {
        std::fs::write(&p, "password\n123456\nqwerty\nletmein\n").unwrap();
    }
    (u, p)
}

fn run_dry(args: &[&str]) -> (std::time::Duration, String) {
    let start = Instant::now();
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn veltrix binary");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "dry-run failed: {}\n{}",
        stdout,
        stderr
    );
    (elapsed, format!("{}\n{}", stdout, stderr))
}

fn workdir() -> PathBuf {
    std::env::temp_dir().join("veltrix-perf")
}

#[test]
fn perf_dryrun_single_target() {
    let dir = workdir();
    std::fs::create_dir_all(&dir).unwrap();
    let (u, p) = small_files(&dir);
    let (el, out) = run_dry(&[
        "ssh",
        "-t",
        "192.168.1.1",
        "-U",
        u.to_str().unwrap(),
        "-W",
        p.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(out.contains("Total: 12"), "unexpected plan output:\n{}", out);
    println!("single-target dry-run (12 combos): {:?}", el);
}

#[test]
fn perf_dryrun_cidr_24() {
    let dir = workdir();
    std::fs::create_dir_all(&dir).unwrap();
    let (u, p) = small_files(&dir);
    let (el, out) = run_dry(&[
        "ssh",
        "-t",
        "192.168.1.0/24",
        "-U",
        u.to_str().unwrap(),
        "-W",
        p.to_str().unwrap(),
        "--dry-run",
    ]);
    // /24 = 254 host x 12 kredensial = 3048.
    assert!(out.contains("Total: 3048"), "unexpected plan output:\n{}", out);
    println!("cidr-/24 dry-run (3048 combos): {:?}", el);
}

#[test]
fn perf_dryrun_1m_passwords() {
    let dir = workdir();
    std::fs::create_dir_all(&dir).unwrap();
    let big = dir.join("perf_1m_passwords.txt");
    if !big.exists() || std::fs::metadata(&big).map(|m| m.len()).unwrap_or(0) < 5_000_000 {
        println!("generating 1M password file (one-time)...");
        let mut s = String::with_capacity(12_000_000);
        for i in 0..1_000_000u32 {
            s.push_str(&format!("Password{:07}!\n", i));
        }
        std::fs::write(&big, s).unwrap();
    }
    let u = dir.join("perf_1m_user.txt");
    std::fs::write(&u, "admin\n").unwrap();
    let (el, out) = run_dry(&[
        "ssh",
        "-t",
        "192.168.1.1",
        "-U",
        u.to_str().unwrap(),
        "-W",
        big.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(out.contains("Total: 1000000"), "unexpected plan output:\n{}", out);
    println!("1M-password dry-run (1 target x 1M): {:?}", el);
}

#[test]
fn perf_dryrun_proxy_off_vs_on() {
    let dir = workdir();
    std::fs::create_dir_all(&dir).unwrap();
    let (u, p) = small_files(&dir);
    let base = [
        "ssh",
        "-t",
        "192.168.1.1",
        "-U",
        u.to_str().unwrap(),
        "-W",
        p.to_str().unwrap(),
        "--dry-run",
    ];
    let (off, _) = run_dry(&base);
    let mut with_proxy: Vec<&str> = base.to_vec();
    with_proxy.extend(["--proxy", "socks5://127.0.0.1:9050"]);
    let (on, _) = run_dry(&with_proxy);
    let ratio = on.as_secs_f64() / off.as_secs_f64().max(1e-9);
    println!(
        "proxy off={:?} on={:?} ratio={:.2}x (config path only, no traffic)",
        off, on, ratio
    );
    // Path proxy dry-run tidak boleh lebih dari 10x path langsung
    // (keduanya tanpa network; ini hanya guard regresi config).
    assert!(ratio < 10.0, "proxy config path regressed: {:.2}x", ratio);
}

#[test]
fn perf_dryrun_rules_expansion() {
    let dir = workdir();
    std::fs::create_dir_all(&dir).unwrap();
    let (u, p) = small_files(&dir);
    let rule = dir.join("perf_bench.rule");
    std::fs::write(&rule, "@123\n@!\n~2\n&a:4\nD\n").unwrap();
    let (el, out) = run_dry(&[
        "ssh",
        "-t",
        "192.168.1.1",
        "-U",
        u.to_str().unwrap(),
        "-W",
        p.to_str().unwrap(),
        "--rule",
        rule.to_str().unwrap(),
        "--max-mutations",
        "500",
        "--dry-run",
    ]);
    assert!(out.contains("Rules:"), "rules note missing:\n{}", out);
    println!("rules dry-run (4 base, 5 rules): {:?}\n{}", el, out.lines().last().unwrap_or(""));
}
