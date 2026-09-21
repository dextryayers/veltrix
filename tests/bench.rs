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

#[test]
fn bench_cartesian_lazy_vs_vec() {
    let start = Instant::now();
    let users = 1_000;
    let passwords = 1_000;
    let mut count = 0u64;
    for u in 0..users {
        for p in 0..passwords {
            count += ((u ^ p) & 1) as u64;
        }
    }
    let elapsed = start.elapsed();
    println!("Lazy cartesian 1M combos: count={} in {:?}", count, elapsed);
}

#[test]
fn bench_dedup_fxhash() {
    use std::collections::HashSet;
    let start = Instant::now();
    let iterations = 100_000;
    let mut set: HashSet<String> = HashSet::with_capacity(iterations);
    for i in 0..iterations {
        set.insert(format!("user{}:pass{}", i % 50_000, i));
    }
    let elapsed = start.elapsed();
    println!("Dedup 100k with 50k dup keys: {} unique in {:?}", set.len(), elapsed);
}

#[test]
fn bench_combo_line_parse() {
    let start = Instant::now();
    let iterations = 100_000;
    let mut valid = 0;
    for i in 0..iterations {
        let line = format!("user{}:pass:word{}", i, i);
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            valid += 1;
        }
    }
    let elapsed = start.elapsed();
    println!("Combo parse: {} valid in {:?}", valid, elapsed);
}
