use std::collections::HashMap;
use std::sync::Arc;
use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::api::cloud::CloudScheduler;
use crate::core::result::AuthResult;
use crate::protocols::get_protocol;

#[derive(Clone)]
#[allow(dead_code)]
pub struct AttackJob {
    pub id: String,
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub status: String,
    pub results: Vec<AuthResult>,
    pub created_at: String,
    pub progress: f64,
}

pub struct ApiServer {
    bind: String,
    jobs: Arc<Mutex<HashMap<String, AttackJob>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    cloud: CloudScheduler,
}

impl ApiServer {
    pub fn new(
        bind: String,
        running: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        ApiServer {
            bind,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            running,
            cloud: CloudScheduler::new(),
        }
    }

    pub async fn run(&self) {
        let listener = match TcpListener::bind(&self.bind).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("API server failed to bind {}: {}", self.bind, e);
                return;
            }
        };
        log::info!("REST API listening on http://{}/", self.bind);

        let jobs = Arc::clone(&self.jobs);
        let running = Arc::clone(&self.running);
        let cloud = self.cloud.clone();

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, addr) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("API accept error: {}", e);
                            continue;
                        }
                    };
                    let jobs = Arc::clone(&jobs);
                    let running = Arc::clone(&running);
                    let cloud = cloud.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, addr, jobs, running, cloud).await {
                            log::debug!("API client {} error: {}", addr, e);
                        }
                    });
                }
                _ = async {
                    while running.load(std::sync::atomic::Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                } => { break; }
            }
        }
    }
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    _addr: std::net::SocketAddr,
    jobs: Arc<Mutex<HashMap<String, AttackJob>>>,
    _running: Arc<std::sync::atomic::AtomicBool>,
    cloud: CloudScheduler,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut request_line = String::new();

    reader.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut writer, 400, "Bad Request: invalid request line").await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    let mut content_length: usize = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        let trimmed = header.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(len_str) = trimmed.strip_prefix("Content-Length:") {
            content_length = len_str.trim().parse().unwrap_or(0);
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        use tokio::io::AsyncReadExt;
        reader.read_exact(&mut buf).await?;
        body = String::from_utf8_lossy(&buf).to_string();
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let body = crate::api::web_ui::WEB_UI_HTML;
            let status_text = "OK";
            let response = format!(
                "HTTP/1.1 200 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_text, body.len(), body
            );
            writer.write_all(response.as_bytes()).await?;
        }
        ("GET", "/api/v1/status") => {
            let status = serde_json::json!({
                "status": "running",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": Utc::now().to_rfc3339(),
                "active_jobs": jobs.lock().await.len(),
            });
            send_json(&mut writer, 200, &status).await?;
        }
        ("GET", "/api/v1/protocols") => {
            let proto_list: Vec<&str> = crate::protocols::list_protocols();
            let str_list: Vec<String> = proto_list.into_iter().map(|s| s.to_string()).collect();
            let resp = serde_json::json!({
                "protocols": str_list,
                "count": str_list.len(),
            });
            send_json(&mut writer, 200, &resp).await?;
        }
        ("GET", "/api/v1/jobs") => {
            let j = jobs.lock().await;
            let jobs_list: Vec<serde_json::Value> = j.values().map(|job| {
                serde_json::json!({
                    "id": job.id,
                    "target": job.target,
                    "port": job.port,
                    "protocol": job.protocol,
                    "status": job.status,
                    "progress": job.progress,
                    "results_count": job.results.len(),
                    "created_at": job.created_at,
                })
            }).collect();
            drop(j);
            let resp = serde_json::json!({ "jobs": jobs_list });
            send_json(&mut writer, 200, &resp).await?;
        }
        ("GET", path) if path.starts_with("/api/v1/jobs/") && path.ends_with("/results") => {
            let job_id = path.trim_start_matches("/api/v1/jobs/")
                .trim_end_matches("/results");
            let j = jobs.lock().await;
            if let Some(job) = j.get(job_id) {
                let resp = serde_json::json!({
                    "job_id": job.id,
                    "status": job.status,
                    "results": job.results,
                    "count": job.results.len(),
                });
                drop(j);
                send_json(&mut writer, 200, &resp).await?;
            } else {
                drop(j);
                send_json(&mut writer, 404, &serde_json::json!({"error": "Job not found"})).await?;
            }
        }
        ("GET", path) if path.starts_with("/api/v1/jobs/") => {
            let job_id = path.trim_start_matches("/api/v1/jobs/");
            let j = jobs.lock().await;
            if let Some(job) = j.get(job_id) {
                let resp = serde_json::json!({
                    "id": job.id,
                    "target": job.target,
                    "port": job.port,
                    "protocol": job.protocol,
                    "status": job.status,
                    "progress": job.progress,
                    "results_count": job.results.len(),
                    "created_at": job.created_at,
                });
                drop(j);
                send_json(&mut writer, 200, &resp).await?;
            } else {
                drop(j);
                send_json(&mut writer, 404, &serde_json::json!({"error": "Job not found"})).await?;
            }
        }
        ("POST", "/api/v1/attack") => {
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    send_json(&mut writer, 400, &serde_json::json!({"error": format!("Invalid JSON: {}", e)})).await?;
                    return Ok(());
                }
            };

            let target = parsed["target"].as_str().unwrap_or("").to_string();
            let protocol = parsed["protocol"].as_str().unwrap_or("").to_string();
            let port = parsed["port"].as_u64().unwrap_or(0) as u16;
            let usernames: Vec<String> = parsed["usernames"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let passwords: Vec<String> = parsed["passwords"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            if target.is_empty() || protocol.is_empty() {
                send_json(&mut writer, 400, &serde_json::json!({
                    "error": "target and protocol are required"
                })).await?;
                return Ok(());
            }

            if usernames.is_empty() || passwords.is_empty() {
                send_json(&mut writer, 400, &serde_json::json!({
                    "error": "usernames and passwords are required"
                })).await?;
                return Ok(());
            }

            if get_protocol(&protocol).is_none() {
                send_json(&mut writer, 400, &serde_json::json!({
                    "error": format!("Unsupported protocol: {}", protocol)
                })).await?;
                return Ok(());
            }

            let job_id = Uuid::new_v4().to_string();

            let total = usernames.len() * passwords.len();
            let mut completed = 0usize;
            let mut results = Vec::new();
            let timeout = std::time::Duration::from_secs(10);

            // Register job
            {
                let mut j = jobs.lock().await;
                j.insert(job_id.clone(), AttackJob {
                    id: job_id.clone(),
                    target: target.clone(),
                    port,
                    protocol: protocol.clone(),
                    usernames: usernames.clone(),
                    passwords: passwords.clone(),
                    status: "running".into(),
                    results: vec![],
                    created_at: Utc::now().to_rfc3339(),
                    progress: 0.0,
                });
            }

            for user in &usernames {
                for pass in &passwords {
                    let cred = crate::core::credential::Credential::new(user.clone(), pass.clone());
                    let tgt = crate::core::target::Target::new(target.clone(), port, &protocol);

                    if let Some(handler) = get_protocol(&protocol) {
                        let result = handler.authenticate(&tgt, &cred, timeout, &None).await;
                        if result.success {
                            log::info!("API: Found valid credential: {}:{} on {}:{}", user, pass, target, port);
                        }
                        results.push(result);
                    }

                    completed += 1;
                    let progress = (completed as f64 / total as f64) * 100.0;

                    if completed % 10 == 0 || completed == total {
                        let mut j = jobs.lock().await;
                        if let Some(job) = j.get_mut(&job_id) {
                            job.progress = progress;
                            job.results = results.clone();
                            if progress >= 100.0 {
                                job.status = "completed".into();
                            }
                        }
                    }
                }
            }

            {
                let mut j = jobs.lock().await;
                if let Some(job) = j.get_mut(&job_id) {
                    job.progress = 100.0;
                    job.status = "completed".into();
                    job.results = results.clone();
                }
            }

            let success_count = results.iter().filter(|r| r.success).count();
            let resp = serde_json::json!({
                "job_id": job_id,
                "status": "completed",
                "total_attempts": total,
                "successes": success_count,
                "failures": total - success_count,
            });
            send_json(&mut writer, 200, &resp).await?;
        }
        ("POST", "/api/v1/stop") => {
            send_json(&mut writer, 200, &serde_json::json!({
                "status": "stopped",
                "message": "Stop endpoint ready. Full graceful shutdown requires SIGINT."
            })).await?;
        }
        // ── Cloud API endpoints ──
        ("GET", "/api/v1/cloud/jobs") => {
            let jobs = cloud.list_jobs();
            send_json(&mut writer, 200, &serde_json::json!({ "jobs": jobs })).await?;
        }
        ("GET", path) if path.starts_with("/api/v1/cloud/jobs/") => {
            let job_id = path.trim_start_matches("/api/v1/cloud/jobs/");
            match cloud.get_job(job_id) {
                Some(job) => send_json(&mut writer, 200, &serde_json::to_value(&job).unwrap_or_default()).await?,
                None => send_json(&mut writer, 404, &serde_json::json!({"error": "Job not found"})).await?,
            }
        }
        ("POST", "/api/v1/cloud/submit") => {
            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    send_json(&mut writer, 400, &serde_json::json!({"error": format!("Invalid JSON: {}", e)})).await?;
                    return Ok(());
                }
            };

            let target = parsed["target"].as_str().unwrap_or("").to_string();
            let protocol = parsed["protocol"].as_str().unwrap_or("").to_string();
            let usernames: Vec<String> = parsed["usernames"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let passwords: Vec<String> = parsed["passwords"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            if target.is_empty() || protocol.is_empty() {
                send_json(&mut writer, 400, &serde_json::json!({"error": "target and protocol are required"})).await?;
                return Ok(());
            }
            if usernames.is_empty() || passwords.is_empty() {
                send_json(&mut writer, 400, &serde_json::json!({"error": "usernames and passwords required"})).await?;
                return Ok(());
            }

            let config = crate::core::config::AttackConfig {
                targets: vec![target],
                target_file: None,
                users: usernames,
                passwords,
                user_file: None,
                password_file: None,
                combo_file: None,
                protocols: vec![protocol],
                ports: vec![],
                threads: 5,
                timeout: std::time::Duration::from_secs(10),
                delay: std::time::Duration::ZERO,
                rate_limit: None,
                proxy: None,
                proxy_file: None,
                proxy_chain: None,
                output_file: None,
                output_format: crate::core::config::OutputFormat::Plain,
                resume_file: None,
                config_file: None,
                checkpoint_interval: 100,
                rdp_domain: None,
                http_userfield: None,
                http_passfield: None,
                http_success: None,
                verbose: false,
                quiet: false,
                no_banner: true,
                single_user_mode: false,
                spray_mode: false,
                stop_on_first: false,
                retries: 1,
                rule_file: None,
                max_mutations: 500,
                max_password_len: None,
                distributed: None,
                distributed_token: None,
                distributed_name: None,
                plugins: vec![],
                api_bind: None,
                encrypt: false,
                encrypt_passphrase: None,
                decrypt_file: None,
                decrypt_output: None,
            };

            let job_id = cloud.submit(config, _running);
            send_json(&mut writer, 200, &serde_json::json!({
                "job_id": job_id,
                "status": "submitted",
                "endpoints": {
                    "status": format!("/api/v1/cloud/jobs/{}", job_id),
                }
            })).await?;
        }
        _ => {
            send_json(&mut writer, 404, &serde_json::json!({
                "error": format!("Not found: {} {}", method, path),
                "available_endpoints": [
                    "GET  /api/v1/status",
                    "GET  /api/v1/protocols",
                    "GET  /api/v1/jobs",
                    "GET  /api/v1/jobs/{id}",
                    "GET  /api/v1/jobs/{id}/results",
                    "POST /api/v1/attack",
                    "POST /api/v1/stop",
                ]
            })).await?;
        }
    }

    Ok(())
}

async fn send_response(
    writer: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    status: u16,
    body: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_json(
    writer: &mut tokio::io::WriteHalf<tokio::net::TcpStream>,
    status: u16,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = serde_json::to_string(value)?;
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}
