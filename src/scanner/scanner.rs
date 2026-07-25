use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::io::{Write, stdout};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use colored::Colorize;

use super::{ScanResult, BannerGrabber, ServiceDb};

const SPINNER: &[&str] = &["◐", "◓", "◑", "◒"];

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub timeout_secs: u64,
    pub max_concurrent: usize,
    pub banner_grab: bool,
    pub retries: u32,
    pub show_progress: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            ports: Vec::new(),
            timeout_secs: 5,
            max_concurrent: 100,
            banner_grab: true,
            retries: 1,
            show_progress: true,
        }
    }
}

pub struct Scanner {
    config: ScanConfig,
    service_db: ServiceDb,
    running: Arc<AtomicBool>,
}

impl Scanner {
    pub fn new(config: ScanConfig, running: Arc<AtomicBool>) -> Self {
        Self {
            service_db: ServiceDb::new(),
            config,
            running,
        }
    }

    pub async fn scan(&self) -> Vec<ScanResult> {
        let total_tasks = self.config.hosts.len() * self.config.ports.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));
        let start_time = Instant::now();

        if self.config.show_progress && total_tasks > 1 {
            println!(
                "  {} Scanning {} host(s), {} port(s) ({} probes)",
                "▶".cyan(),
                self.config.hosts.len(),
                self.config.ports.len(),
                total_tasks
            );
        }

        let mut handles = Vec::with_capacity(total_tasks);

        for host in &self.config.hosts {
            for &port in &self.config.ports {
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }

                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let host = host.clone();
                let running = self.running.clone();
                let service_db = self.service_db.clone();
                let config = self.config.clone();
                let completed = completed.clone();
                let total = total_tasks;
                let show_progress = self.config.show_progress;
                let start = start_time;

                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let result = scan_port(&host, port, &config, &service_db, running).await;
                    let prev = completed.fetch_add(1, Ordering::SeqCst) + 1;
                    if show_progress && total > 0 {
                        let pct = prev * 100 / total;
                        let elapsed = start.elapsed();
                        let spin = SPINNER[(prev as usize) % SPINNER.len()];
                        let mut out = stdout().lock();
                        let _ = write!(out,
                            "\r  {} {}%  [{}/{}]  {}.{:02}s",
                            spin.cyan(),
                            pct,
                            prev,
                            total,
                            elapsed.as_secs(),
                            elapsed.subsec_millis() / 10
                        );
                        let _ = out.flush();
                    }
                    result
                }));
            }
        }

        let mut results = Vec::with_capacity(total_tasks / 10);
        for handle in handles {
            match handle.await {
                Ok(Some(r)) => results.push(r),
                _ => {}
            }
        }

        if self.config.show_progress && total_tasks > 1 {
            let elapsed = start_time.elapsed();
            println!();
            println!(
                "  {} Scan completed in {}.{:02}s",
                "✓".green(),
                elapsed.as_secs(),
                elapsed.subsec_millis() / 10
            );
        }

        results
    }
}

async fn scan_port(
    host: &str,
    port: u16,
    config: &ScanConfig,
    service_db: &ServiceDb,
    running: Arc<AtomicBool>,
) -> Option<ScanResult> {
    if !running.load(Ordering::SeqCst) {
        return None;
    }

    let addr = format!("{}:{}", host, port);
    let max_retries = config.retries;

    for attempt in 0..=max_retries {
        if !running.load(Ordering::SeqCst) {
            return None;
        }

        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let start = Instant::now();

        match timeout(
            Duration::from_secs(config.timeout_secs),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(mut stream)) => {
                let _ = stream.set_nodelay(true);
                let latency_ms = start.elapsed().as_millis() as u64;

                let service = service_db.lookup(port);
                let (product, version, banner) = if config.banner_grab {
                    match BannerGrabber::grab(
                        &mut stream,
                        port,
                        Duration::from_secs(config.timeout_secs),
                    )
                    .await
                    {
                        Ok(b) => {
                            let (prod, ver) = if b.is_empty() {
                                (None, None)
                            } else {
                                service_db.identify(port, &b)
                            };
                            (prod, ver, if b.is_empty() { None } else { Some(b) })
                        }
                        Err(_) => (None, None, None),
                    }
                } else {
                    (None, None, None)
                };

                return Some(ScanResult {
                    host: host.to_string(),
                    port,
                    open: true,
                    service,
                    product,
                    version,
                    banner,
                    latency_ms,
                });
            }
            Ok(Err(e)) => {
                let err_str = e.to_string();
                if attempt < max_retries {
                    if err_str.contains("refused")
                        || err_str.contains("reset")
                        || err_str.contains("broken pipe")
                    {
                        return None;
                    }
                }
                if attempt == max_retries {
                    log::debug!("Port {}/{} connection failed: {}", host, port, err_str);
                }
            }
            Err(_) => {
                if attempt < max_retries {
                    continue;
                }
            }
        }
    }

    None
}

pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range: Vec<&str> = part.splitn(2, '-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }
            let start: u16 = range[0]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", range[0]))?;
            let end: u16 = range[1]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", range[1]))?;
            if start > end {
                return Err(format!("Invalid range: {} > {}", start, end));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err("No valid ports specified".to_string());
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 113, 119, 123, 135,
        137, 139, 143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520,
        546, 547, 554, 563, 585, 587, 593, 636, 646, 691, 902, 989, 990, 992,
        993, 994, 995, 1025, 1080, 1099, 1194, 1214, 1241, 1311, 1337, 1352,
        1386, 1414, 1433, 1434, 1494, 1521, 1583, 1720, 1723, 1741, 1755,
        1812, 1813, 1883, 1900, 1935, 1947, 1964, 1984, 1991, 1999, 2000,
        2001, 2002, 2003, 2004, 2005, 2006, 2008, 2010, 2011, 2012, 2013,
        2014, 2015, 2016, 2017, 2018, 2019, 2049, 2082, 2083, 2086, 2087,
        2095, 2096, 2100, 2222, 2302, 2375, 2376, 2379, 2380, 2483, 2484,
        2525, 2628, 2800, 2947, 3000, 3001, 3030, 3050, 3074, 3128, 3260,
        3268, 3269, 3306, 3307, 3389, 3391, 3443, 3478, 3542, 3632, 3689,
        3690, 3724, 3784, 3785, 4000, 4001, 4045, 4080, 4111, 4224, 4242,
        4321, 4333, 4443, 4444, 4445, 4500, 4567, 4647, 4662, 4711, 4712,
        4730, 4786, 4840, 4848, 4899, 4949, 5000, 5001, 5003, 5004, 5005,
        5010, 5030, 5038, 5050, 5051, 5060, 5061, 5093, 5099, 5104, 5120,
        5190, 5222, 5223, 5269, 5349, 5432, 5433, 5445, 5500, 5555, 5556,
        5601, 5631, 5666, 5667, 5672, 5800, 5801, 5900, 5901, 5902, 5903,
        5984, 5985, 5986, 6000, 6001, 6082, 6086, 6100, 6112, 6346, 6379,
        6380, 6389, 6443, 6444, 6481, 6514, 6515, 6550, 6556, 6566, 6600,
        6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6679,
        6697, 6881, 6969, 7001, 7002, 7004, 7007, 7010, 7077, 7100, 7171,
        7200, 7210, 7443, 7444, 7474, 7475, 7496, 7547, 7675, 7676, 7777,
        7778, 7831, 7869, 7870, 7871, 8000, 8001, 8002, 8003, 8004, 8005,
        8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016,
        8017, 8018, 8019, 8020, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
        8087, 8088, 8089, 8090, 8091, 8092, 8093, 8096, 8100, 8181, 8200,
        8222, 8243, 8280, 8281, 8291, 8300, 8332, 8333, 8403, 8443, 8444,
        8445, 8446, 8447, 8448, 8449, 8472, 8500, 8501, 8530, 8531, 8600,
        8649, 8834, 8843, 8873, 8880, 8883, 8888, 8889, 8983, 8990, 8991,
        8992, 8993, 8994, 8995, 8996, 8997, 8998, 8999, 9000, 9001, 9002,
        9003, 9008, 9009, 9010, 9042, 9043, 9050, 9051, 9060, 9080, 9090,
        9091, 9092, 9093, 9094, 9095, 9100, 9101, 9102, 9103, 9105, 9119,
        9150, 9151, 9160, 9191, 9200, 9201, 9202, 9210, 9250, 9300, 9301,
        9302, 9303, 9304, 9305, 9306, 9307, 9308, 9309, 9310, 9418, 9443,
        9500, 9535, 9594, 9595, 9600, 9876, 9877, 9878, 9898, 9900, 9981,
        9987, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10008,
        10009, 10010, 10050, 10051, 10113, 10114, 10115, 10116, 10117, 10162,
        10200, 10389, 10566, 10616, 10617, 10618, 10619, 10620, 10626, 10627,
        10880, 10990, 11000, 11211, 11214, 11215, 11371, 11433, 11434, 11877,
        12000, 12012, 12013, 12109, 12345, 12975, 12976, 13337, 13338, 13722,
        14500, 14567, 15000, 15118, 15119, 15345, 16000, 16080, 16161, 16379,
        16380, 16400, 16509, 16680, 16992, 16993, 16994, 16995, 17000, 18080,
        18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088, 18089, 18090,
        18181, 18200, 18201, 18202, 18203, 18204, 18205, 18206, 18207, 18208,
        18209, 18210, 18333, 18412, 18413, 18414, 18609, 18734, 19000, 19001,
        19101, 19111, 19131, 19132, 19133, 19283, 19315, 19399, 19999, 20000,
        20001, 20002, 20101, 20480, 21025, 22222, 22273, 22305, 22986, 23000,
        23399, 23424, 24554, 24800, 25734, 25735, 26000, 26257, 27015, 27017,
        27018, 27019, 27020, 27272, 27960, 27992, 28000, 28001, 28015, 28017,
        28115, 28200, 28455, 28777, 28778, 28804, 30000, 30303, 30718, 31337,
        31516, 32764, 32768, 32769, 32771, 33060, 33061, 33434, 33848, 34324,
        34443, 34444, 34567, 35000, 35432, 35555, 35800, 36789, 36885, 36886,
        36887, 36888, 37008, 37333, 37434, 37537, 37777, 37877, 37978, 38001,
        38005, 38009, 38013, 38017, 38021, 38584, 38891, 40000, 40001, 40080,
        40125, 40827, 41111, 41770, 42510, 43000, 43120, 44311, 44444, 45555,
        45678, 47100, 47101, 47102, 47103, 47549, 47550, 47623, 47624, 47806,
        48000, 48001, 48002, 48003, 48004, 48005, 48006, 48007, 48008, 48009,
        48010, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
        49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169, 49170,
        49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179, 49180,
        49181, 49182, 49183, 49184, 49185, 49186, 49187, 49188, 49189, 49190,
        49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199, 49200,
        49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209, 49210,
        50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009,
        50010, 50011, 50012, 50013, 50014, 50015, 50016, 50017, 50018, 50019,
        50020, 50021, 50022, 50023, 50024, 50025, 50026, 50027, 50028, 50029,
        50030, 50031, 50032, 50033, 50034, 50035, 50036, 50037, 50038, 50039,
        50040, 50041, 50042, 50043, 50044, 50045, 50046, 50047, 50048, 50049,
        50050, 50070, 50075, 50090, 50100, 50200, 50300, 50400, 50500, 50600,
        50700, 50800, 50900, 51000, 51111, 51234, 51515, 51666, 51777, 51888,
        51999, 52000, 52001, 52002, 52003, 52004, 52005, 52006, 52007, 52008,
        52009, 52010, 52100, 52200, 52299, 52300, 52400, 52500, 52600, 52700,
        52800, 52900, 53000, 53100, 53200, 53300, 53400, 53500, 53600, 53700,
        53800, 53900, 54000, 54100, 54200, 54300, 54400, 54500, 54600, 54700,
        54800, 54900, 55000, 55001, 55002, 55003, 55004, 55005, 55006, 56000,
        56100, 56200, 56300, 56400, 56500, 56600, 56700, 56800, 56900, 57000,
        57100, 57200, 57300, 57400, 57500, 57600, 57700, 57800, 57900, 58000,
        58100, 58200, 58300, 58400, 58500, 58600, 58700, 58800, 58900, 59000,
        59100, 59200, 59300, 59400, 59500, 59600, 59700, 59800, 59900, 60000,
        60100, 60200, 60300, 60400, 60500, 60600, 60700, 60800, 60900, 61000,
        61616,
    ]
}
