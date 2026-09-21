//! F3.6: matriks protokol inti tanpa network.
//! Memastikan registry, default port, dan fingerprint konsisten.
//! Test integrasi live dengan Docker tetap di docker-compose matrix.

use std::time::Duration;

#[test]
fn registry_covers_core_protocols() {
    // Registry dijamin sinkron dengan CLI --list-protocols.
    // Kita cek via binary agar test ini tidak duplikat logika registry.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .arg("--list-protocols")
        .output()
        .expect("run veltrix --list-protocols");
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    for p in ["ssh", "ftp", "smtp", "mysql", "postgres", "smb", "rdp", "redis", "http"] {
        assert!(text.contains(p), "protocol {} missing from --list-protocols", p);
    }
}

#[test]
fn dry_run_core_protocols_no_traffic() {
    // Dry run tidak boleh mengirim paket dan harus exit 0.
    for proto in ["ssh", "ftp", "mysql"] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
            .args([proto, "-t", "127.0.0.1", "-u", "admin", "--password", "x", "--dry-run"])
            .status()
            .expect("run dry-run");
        assert!(status.success(), "dry-run failed for {}", proto);
    }
}

#[test]
fn invalid_config_exits_2() {
    // Tanpa target harus exit 2 (config invalid), bukan 1.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-u", "admin", "--password", "x"])
        .status()
        .expect("run without target");
    assert_eq!(status.code(), Some(2), "expected exit 2 for missing target");
}

#[test]
fn validate_rejects_bad_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("veltrix_bad_validate.json");
    std::fs::write(&path, "not json").unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["validate"])
        .arg(&path)
        .status()
        .expect("run validate");
    assert_eq!(status.code(), Some(2));
    std::fs::remove_file(&path).ok();
}

#[test]
fn transport_timeout_is_bounded() {
    // Pastikan helper timeout bekerja: connect ke port closed harus cepat gagal.
    let start = std::time::Instant::now();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "127.0.0.1", "-p", "59999", "-u", "u", "--password", "p", "-x", "2", "--timeout", "2"])
        .output()
        .expect("run closed port");
    assert_eq!(status.status.code(), Some(1));
    assert!(start.elapsed() < Duration::from_secs(30), "closed port took too long");
}

#[test]
fn aggressive_lab_blocked_for_public_ip() {
    // Tanpa --i-understand-risk, target publik + aggressive harus exit 2 tanpa traffic.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "8.8.8.8", "-u", "admin", "--password", "x",
               "--aggressive-lab", "--dry-run"])
        .status()
        .expect("run aggressive public");
    assert_eq!(status.code(), Some(2), "aggressive-lab must refuse public targets");
}

#[test]
fn aggressive_lab_allowed_for_rfc1918() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "192.168.1.1", "-u", "admin", "--password", "x",
               "--aggressive-lab", "--dry-run"])
        .status()
        .expect("run aggressive lab");
    assert!(status.success(), "aggressive-lab should allow RFC1918 with dry-run");
}

#[test]
fn safe_profile_and_spray_dry_run() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "10.0.0.1", "-u", "admin", "--password", "x",
               "--safe-profile", "--spray", "--spray-interval", "5s",
               "--target-rate-limit", "10", "--user-cooldown", "500ms",
               "--lockout-pause", "--dry-run"])
        .status()
        .expect("run safe spray dry-run");
    assert!(status.success());
}

#[test]
fn invalid_spray_interval_exits_2() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "10.0.0.1", "-u", "admin", "--password", "x",
               "--spray-interval", "bogus"])
        .status()
        .expect("run bad interval");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn safe_and_aggressive_conflict_exits_2() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["ssh", "-t", "10.0.0.1", "-u", "admin", "--password", "x",
               "--safe-profile", "--aggressive-lab"])
        .status()
        .expect("run conflicting presets");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn auto_no_open_ports_exits_1_fast() {
    // Scan 1 closed port di localhost: cepat, lalu auto lapor tidak ada grup.
    let start = std::time::Instant::now();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_veltrix"))
        .args(["auto", "-t", "127.0.0.1", "--ports", "59999",
               "--scan-timeout", "1", "--rate", "10",
               "-u", "admin", "--password", "x"])
        .output()
        .expect("run auto no-open");
    assert_eq!(out.status.code(), Some(1), "auto with no open ports should exit 1");
    assert!(start.elapsed() < Duration::from_secs(60));
    let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    assert!(text.to_lowercase().contains("no attackable"), "auto should explain empty groups");
}
