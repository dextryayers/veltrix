//! F7.6: chaos test - worker mati di tengah run.
//! 200 task (user unik) dibagi chunk 20. Satu worker "killer" mengambil
//! 2 chunk lalu putus tanpa melapor; worker penuh harus menyelesaikan semua.
//! Assert: 200 username unik di output coordinator (tanpa loss, tanpa dup).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "chaos-test-token";
const N_USERS: usize = 200;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_veltrix"))
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn write_users_file(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("chaos_users.txt");
    let content: Vec<String> = (0..N_USERS).map(|i| format!("chaosuser{:03}", i)).collect();
    std::fs::write(&path, content.join("\n")).unwrap();
    path
}

fn spawn_coordinator(port: u16, users: &std::path::Path, out: &std::path::Path) -> Child {
    Command::new(bin())
        .args([
            "dist-coordinator",
            "--bind",
            &format!("127.0.0.1:{}", port),
            "--dist-token",
            TOKEN,
            "--chunk-size",
            "20",
            "--chunk-timeout",
            "2",
            "--heartbeat-timeout",
            "10",
            "-t",
            "127.0.0.1:59999",
            "-U",
            users.to_str().unwrap(),
            "--password",
            "x",
            "--timeout",
            "2",
            "-x",
            "4",
            "-o",
            out.to_str().unwrap(),
            "-f",
            "json",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn coordinator")
}

fn spawn_worker(port: u16, name: &str) -> Child {
    Command::new(bin())
        .args([
            "dist-worker",
            "--connect",
            &format!("127.0.0.1:{}", port),
            "--dist-token",
            TOKEN,
            "--name",
            name,
            "--threads",
            "10",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn worker")
}

/// Worker "killer": handshake, ambil 2 batch, putus tanpa ResultReport.
fn killer_takes_two_batches(port: u16) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let hello = serde_json::json!({
        "Hello": {
            "version": "veltrix-dist-v2",
            "run_token": TOKEN,
            "hostname": "killer",
            "max_concurrent": 4,
            "completed_hint": []
        }
    });
    writeln!(stream, "{}", hello).unwrap();
    stream.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let ack: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let wid = ack
        .get("HelloAck")
        .and_then(|a| a.get("worker_id"))
        .and_then(|w| w.as_str())
        .expect("HelloAck with worker_id")
        .to_string();
    for _ in 0..2 {
        let req = serde_json::json!({
            "TaskRequest": { "worker_id": wid, "batch_size": 20 }
        });
        writeln!(stream, "{}", req).unwrap();
        stream.flush().unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("TaskBatch"), "expected TaskBatch, got: {}", line.trim());
    }
    // Mati tanpa melapor: drop koneksi.
}

fn wait_exit(child: &mut Child, timeout: Duration, what: &str) {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                eprintln!("{} exited: {}", what, status);
                return;
            }
            None => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    panic!("{} did not exit within {:?}", what, timeout);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

#[test]
fn chaos_worker_death_loses_nothing() {
    let dir = std::env::temp_dir().join(format!("veltrix_chaos_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let users = write_users_file(&dir);
    let out = dir.join("chaos_out.json");
    let port = free_port();

    let mut coord = spawn_coordinator(port, &users, &out);
    // Tunggu coordinator listen.
    std::thread::sleep(Duration::from_secs(2));

    // Killer dulu: ambil 2 chunk (40 task) lalu mati.
    killer_takes_two_batches(port);
    // Beri jeda agar chunk killer tercatat InFlight sebelum worker penuh datang.
    std::thread::sleep(Duration::from_millis(500));

    // Worker penuh menyelesaikan sisanya + requeue dari reaper.
    let mut worker = spawn_worker(port, "full");

    wait_exit(&mut worker, Duration::from_secs(90), "full worker");
    wait_exit(&mut coord, Duration::from_secs(30), "coordinator");

    // Assert: 200 username unik di JSONL v2 output.
    let content = std::fs::read_to_string(&out).expect("coordinator output file");
    let mut users_seen: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("valid finding json");
        assert_eq!(v.get("schema").and_then(|s| s.as_str()), Some("veltrix-finding/v2"));
        users_seen.push(v.get("username").and_then(|u| u.as_str()).unwrap_or("").to_string());
    }
    users_seen.sort();
    users_seen.dedup();
    assert_eq!(
        users_seen.len(),
        N_USERS,
        "expected {} unique users (no loss, no dup), got {}",
        N_USERS,
        users_seen.len()
    );
    assert!(users_seen.iter().all(|u| u.starts_with("chaosuser")));

    std::fs::remove_dir_all(&dir).ok();
}
