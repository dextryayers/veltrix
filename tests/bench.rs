/// Simple benchmark — no external deps needed.
/// Run with: cargo test --test simple_bench -- --nocapture

use std::time::Instant;

#[test]
fn bench_target_parse() {
    let start = Instant::now();
    let iterations = 100_000;
    for _ in 0..iterations {
        let parts: Vec<&str> = "192.168.1.1:22".split(':').collect();
        let _host = parts[..parts.len() - 1].join(":");
        let _port: u16 = parts.last().unwrap().parse().unwrap();
    }
    let elapsed = start.elapsed();
    println!("Target parse: {} iterations in {:?} ({:?} each)", iterations, elapsed, elapsed / iterations);
}

#[test]
fn bench_credential_parse() {
    let start = Instant::now();
    let iterations = 100_000;
    for _ in 0..iterations {
        let parts: Vec<&str> = "admin:password123".splitn(2, ':').collect();
        let _user = parts[0];
        let _pass = parts[1];
    }
    let elapsed = start.elapsed();
    println!("Credential parse: {} iterations in {:?} ({:?} each)", iterations, elapsed, elapsed / iterations);
}

#[test]
fn bench_string_format() {
    let start = Instant::now();
    let iterations = 100_000;
    for i in 0..iterations {
        let _s = format!("test:{}", i);
    }
    let elapsed = start.elapsed();
    println!("String format: {} iterations in {:?} ({:?} each)", iterations, elapsed, elapsed / iterations);
}

#[test]
fn bench_hashset_insert() {
    use std::collections::HashSet;
    let start = Instant::now();
    let iterations = 10_000;
    let mut set = HashSet::new();
    for i in 0..iterations {
        set.insert(format!("user{}:pass{}", i, i));
    }
    let elapsed = start.elapsed();
    println!("HashSet insert: {} items in {:?} ({:?} each)", iterations, elapsed, elapsed / iterations);
}
