//! F6.4: REST API v2 di atas axum.
//! - Auth JWT HS256 (lihat auth.rs), rate limit per IP, audit log (F6.6).
//! - Job queue non-blocking: POST /api/v2/jobs -> 202, eksekusi di background
//!   dengan progress hook, hasil live via websocket /api/v2/jobs/:id/events.
//! - Web UI single-file di / (lihat web_ui.rs, F6.5).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json,
};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::auth::ApiAuth;
use super::state::{AppState, AttackSpec, JobEvent, JobStatus, JobV2};
use crate::core::result::{mask_password, severity_for, FindingV2, ProgressTick};
use crate::protocols::get_protocol;

pub struct ApiServer {
    bind: String,
    state: AppState,
}

impl ApiServer {
    pub fn new(
        bind: String,
        running: Arc<std::sync::atomic::AtomicBool>,
        api_token: Option<String>,
        rate_per_min: u32,
    ) -> (Self, Option<String>) {
        let (auth, _ephemeral) = ApiAuth::new(api_token);
        let shown_token = auth.ephemeral_token();
        let state = AppState::new(auth, running, rate_per_min);
        (Self { bind, state }, shown_token)
    }

    pub async fn run(&self) {
        if self.bind.is_empty() {
            log::error!("API bind address is empty");
            return;
        }
        let app = build_router(self.state.clone());
        let listener = match tokio::net::TcpListener::bind(&self.bind).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("API server failed to bind {}: {}", self.bind, e);
                return;
            }
        };
        log::warn!(
            "REST API v2 listening on http://{}/ (auth required; bind to 127.0.0.1 or trusted net only)",
            self.bind
        );
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            log::error!("API server error: {}", e);
        }
    }
}

fn build_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(ui_handler))
        .route("/api/v2/health", get(health_handler))
        .route("/api/v2/login", post(login_handler))
        .route("/api/v2/status", get(status_handler))
        .route("/api/v2/protocols", get(protocols_handler))
        .route("/api/v2/jobs", get(list_jobs_handler).post(submit_job_handler))
        .route("/api/v2/jobs/:id", get(job_detail_handler))
        .route("/api/v2/jobs/:id/results", get(job_results_handler))
        .route("/api/v2/jobs/:id/report", get(job_report_handler))
        .route("/api/v2/jobs/:id/stop", post(stop_job_handler))
        .route("/api/v2/jobs/:id/events", get(job_events_handler))
        .route("/api/v2/audit", get(audit_handler))
        .with_state(state)
}

type ApiResult = Result<Response, (StatusCode, Json<Value>)>;

fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": msg })))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

async fn require_auth(state: &AppState, headers: &HeaderMap, ip: SocketAddr) -> Result<String, (StatusCode, Json<Value>)> {
    if !state.rate_limiter.allow(ip.ip()).await {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "API rate limit exceeded (per-minute quota)"));
    }
    match bearer(headers).and_then(|b| state.auth.verify(&b)) {
        Some(sub) => Ok(sub),
        None => Err(err(StatusCode::UNAUTHORIZED, "missing or invalid Bearer JWT; POST /api/v2/login first")),
    }
}

async fn ui_handler() -> Html<&'static str> {
    Html(super::web_ui::WEB_UI_HTML)
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "veltrix-api", "api": "v2" }))
}

async fn login_handler(State(state): State<AppState>, Json(body): Json<Value>) -> ApiResult {
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let actor = body.get("actor").and_then(|v| v.as_str());
    match state.auth.login(token, actor) {
        Some((jwt, sub)) => {
            state.audit(&sub, "login", None, "issued JWT").await;
            Ok(Json(json!({ "token": jwt, "actor": sub, "expires_in_secs": 43200 })).into_response())
        }
        None => {
            state.audit("unknown", "login_failed", None, "bad API token").await;
            Err(err(StatusCode::UNAUTHORIZED, "invalid API token"))
        }
    }
}

async fn status_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    let _actor = require_auth(&state, &headers, ip).await?;
    let jobs = state.jobs.read().await;
    let active = jobs.values().filter(|j| j.status == JobStatus::Running || j.status == JobStatus::Queued).count();
    Ok(Json(json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "active_jobs": active,
        "total_jobs": jobs.len(),
    }))
    .into_response())
}

async fn protocols_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    let _actor = require_auth(&state, &headers, ip).await?;
    let list: Vec<String> = crate::protocols::list_protocols().into_iter().map(|s| s.to_string()).collect();
    Ok(Json(json!({ "protocols": list, "count": list.len() })).into_response())
}

async fn list_jobs_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    let _actor = require_auth(&state, &headers, ip).await?;
    let jobs = state.jobs.read().await;
    let mut list: Vec<Value> = jobs.values().map(|j| j.masked_summary()).collect();
    list.sort_by(|a, b| {
        b.get("created_at").and_then(|v| v.as_str()).cmp(&a.get("created_at").and_then(|v| v.as_str()))
    });
    Ok(Json(json!({ "jobs": list })).into_response())
}

fn parse_attack_spec(body: &Value) -> Result<AttackSpec, String> {
    let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let protocol = body.get("protocol").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let port = body.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let usernames: Vec<String> = body
        .get("usernames")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let passwords: Vec<String> = body
        .get("passwords")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    if target.is_empty() {
        return Err("target is required".into());
    }
    if protocol.is_empty() {
        return Err("protocol is required".into());
    }
    if get_protocol(&protocol).is_none() {
        return Err(format!("unsupported protocol: {}", protocol));
    }
    if usernames.is_empty() || passwords.is_empty() {
        return Err("usernames and passwords are required and non-empty".into());
    }
    if usernames.len() * passwords.len() > 1_000_000 {
        return Err("combination count exceeds API limit of 1,000,000 (use CLI for larger runs)".into());
    }
    let threads = body.get("threads").and_then(|v| v.as_u64()).unwrap_or(10).clamp(1, 50) as usize;
    let timeout_secs = body.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(10).clamp(1, 120);
    let show_secrets = body.get("show_secrets").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok(AttackSpec { target, port, protocol, usernames, passwords, threads, timeout_secs, show_secrets })
}

async fn submit_job_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let actor = require_auth(&state, &headers, ip).await?;
    let spec = parse_attack_spec(&body).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    let job_id = uuid::Uuid::new_v4().to_string();
    let total_creds = spec.usernames.len() * spec.passwords.len();
    let job = JobV2 {
        id: job_id.clone(),
        run_id: String::new(),
        target: spec.target.clone(),
        port: spec.port,
        protocol: spec.protocol.clone(),
        status: JobStatus::Queued,
        progress: 0.0,
        attempts: 0,
        successes: 0,
        failures: 0,
        errors: 0,
        total_targets_est: 1,
        total_credentials_est: total_creds,
        created_at: chrono::Utc::now().to_rfc3339(),
        started_at: None,
        finished_at: None,
        error: None,
        submitted_by: actor.clone(),
        spec: spec.clone(),
        results: Vec::new(),
        log: Default::default(),
        cancel: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    state.jobs.write().await.insert(job_id.clone(), job);
    state
        .audit(&actor, "job_submit", Some(&job_id), &format!("{} {}:{} {} creds", spec.protocol, spec.target, spec.port, total_creds))
        .await;
    // Non-blocking: eksekusi di background.
    let st = state.clone();
    let jid = job_id.clone();
    tokio::spawn(async move {
        run_job_task(st, jid).await;
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "job_id": job_id, "status": "queued" })),
    )
        .into_response())
}

async fn run_job_task(state: AppState, job_id: String) {
    let (spec, cancel, estimate) = {
        let mut jobs = state.jobs.write().await;
        let job = match jobs.get_mut(&job_id) {
            Some(j) => j,
            None => return,
        };
        job.status = JobStatus::Running;
        job.started_at = Some(chrono::Utc::now().to_rfc3339());
        job.push_log("job started".into());
        (job.spec.clone(), Arc::clone(&job.cancel), job.total_credentials_est as u64)
    };
    emit_event(&state, &job_id, "running", 0.0, 0, 0, "job started").await;

    let config = crate::core::config::AttackConfig {
        targets: vec![if spec.port > 0 { format!("{}:{}", spec.target, spec.port) } else { spec.target.clone() }],
        target_file: None,
        users: spec.usernames.clone(),
        passwords: spec.passwords.clone(),
        user_file: None,
        password_file: None,
        combo_file: None,
        protocols: vec![spec.protocol.clone()],
        ports: if spec.port > 0 { vec![spec.port] } else { vec![] },
        threads: spec.threads,
        timeout: std::time::Duration::from_secs(spec.timeout_secs),
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
        verbose: 0,
        quiet: true,
        no_banner: true,
        single_user_mode: false,
        rdp_domain: None,
        http_userfield: None,
        http_passfield: None,
        http_success: None,
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
        dry_run: false,
        fp_check: false,
        spray_interval: std::time::Duration::ZERO,
        spray_jitter_pct: 0,
        target_rate_limit: None,
        user_cooldown: std::time::Duration::ZERO,
        lockout_cooldown: std::time::Duration::ZERO,
        rate_cooldown: std::time::Duration::ZERO,
        lockout_pause: false,
        user_agent: None,
        safe_profile: false,
        aggressive_lab: false,
        i_understand_risk: false,
        only_open: None,
        show_secrets: spec.show_secrets,
        proxy_required: false,
        rotate_proxy_every: 0,
        source_ip: None,
        delay_jitter_ms: 100,
        check_proxy: false,
    };

    let mut orch = match crate::core::attack::AttackOrchestrator::new(config, cancel).await {
        Ok(o) => o,
        Err(e) => {
            let mut jobs = state.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.status = JobStatus::Failed;
                job.error = Some(e.to_string());
                job.finished_at = Some(chrono::Utc::now().to_rfc3339());
                job.push_log(format!("init failed: {}", e));
            }
            emit_event(&state, &job_id, "failed", 0.0, 0, 0, "init failed").await;
            return;
        }
    };
    let run_id = orch.run_id().to_string();
    {
        let mut jobs = state.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.run_id = run_id;
        }
    }
    let (ptx, mut prx) = mpsc::unbounded_channel::<ProgressTick>();
    orch.set_progress_hook(ptx);
    let run_fut = orch.run();
    tokio::pin!(run_fut);
    let summary = loop {
        tokio::select! {
            s = &mut run_fut => break s,
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                let mut drained = false;
                while let Ok(t) = prx.try_recv() {
                    drained = true;
                    let mut jobs = state.jobs.write().await;
                    if let Some(job) = jobs.get_mut(&job_id) {
                        job.attempts = t.attempts;
                        job.successes = t.successes;
                        job.failures = t.failures;
                        job.errors = t.errors;
                        job.progress = progress_estimate(t.attempts, estimate);
                    }
                }
                if drained {
                    let (p, a, s) = {
                        let jobs = state.jobs.read().await;
                        match jobs.get(&job_id) {
                            Some(j) => (j.progress, j.attempts, j.successes),
                            None => (0.0, 0, 0),
                        }
                    };
                    emit_event(&state, &job_id, "running", p, a, s, "progress").await;
                }
                if !state.running.load(std::sync::atomic::Ordering::SeqCst) {
                    break run_fut.await;
                }
            }
        }
    };
    // Drain sisa tick.
    while let Ok(t) = prx.try_recv() {
        let mut jobs = state.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.attempts = t.attempts;
            job.successes = t.successes;
            job.failures = t.failures;
            job.errors = t.errors;
            job.progress = 1.0;
        }
    }
    let was_cancelled = {
        state.jobs.read().await.get(&job_id).map(|j| !j.cancel.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(false)
    };
    {
        let mut jobs = state.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.results = summary.results.clone();
            job.attempts = summary.attempts;
            job.successes = summary.successes;
            job.failures = summary.failures;
            job.errors = summary.errors;
            job.finished_at = Some(chrono::Utc::now().to_rfc3339());
            job.progress = 1.0;
            if was_cancelled {
                job.status = JobStatus::Stopped;
                job.push_log("stopped by operator".into());
            } else {
                job.status = JobStatus::Completed;
                job.push_log(format!("completed: {} successes", summary.successes));
            }
        }
    }
    let final_status = if was_cancelled { "stopped" } else { "completed" };
    emit_event(&state, &job_id, final_status, 1.0, summary.attempts, summary.successes, final_status).await;
    state.audit("system", &format!("job_{}", final_status), Some(&job_id), &format!("{} successes", summary.successes)).await;
}

fn progress_estimate(attempts: u64, estimate: u64) -> f64 {
    if estimate == 0 {
        return 0.0;
    }
    ((attempts as f64 / estimate as f64).min(0.999) * 100.0).round() / 100.0
}

async fn emit_event(state: &AppState, job_id: &str, status: &str, progress: f64, attempts: u64, successes: u64, msg: &str) {
    let _ = state.events.send(JobEvent {
        job_id: job_id.to_string(),
        status: status.to_string(),
        progress,
        attempts,
        successes,
        msg: msg.to_string(),
    });
}

fn masked_results(job: &JobV2, show_secrets: bool) -> Vec<Value> {
    job.results
        .iter()
        .map(|r| {
            let pw = if show_secrets { r.password.clone() } else { mask_password(&r.password) };
            json!({
                "target_host": r.target_host,
                "target_port": r.target_port,
                "protocol": r.protocol,
                "username": r.username,
                "password": pw,
                "success": r.success,
                "severity": severity_for(r.success, r.error.as_deref()),
                "duration_ms": r.duration_ms,
                "timestamp": r.timestamp.to_rfc3339(),
                "evidence": r.safe_evidence(),
                "credential_ref": crate::core::result::credential_ref(&r.username, &r.password, &r.target_host, r.target_port),
            })
        })
        .collect()
}

async fn job_detail_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let _actor = require_auth(&state, &headers, ip).await?;
    let jobs = state.jobs.read().await;
    match jobs.get(&id) {
        Some(job) => Ok(Json(job.masked_summary()).into_response()),
        None => Err(err(StatusCode::NOT_FOUND, "job not found")),
    }
}

async fn job_results_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let actor = require_auth(&state, &headers, ip).await?;
    let show = q.get("show_secrets").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let jobs = state.jobs.read().await;
    match jobs.get(&id) {
        Some(job) => {
            if show {
                state.audit(&actor, "results_show_secrets", Some(&id), "full passwords exposed via API").await;
            }
            Ok(Json(json!({ "job_id": job.id, "status": job.status.as_str(), "count": job.results.len(), "results": masked_results(job, show) })).into_response())
        }
        None => Err(err(StatusCode::NOT_FOUND, "job not found")),
    }
}

async fn job_report_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let actor = require_auth(&state, &headers, ip).await?;
    let fmt = q.get("format").map(|s| s.as_str()).unwrap_or("json");
    let show = q.get("show_secrets").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let jobs = state.jobs.read().await;
    let job = match jobs.get(&id) {
        Some(j) => j,
        None => return Err(err(StatusCode::NOT_FOUND, "job not found")),
    };
    if show {
        state.audit(&actor, "report_show_secrets", Some(&id), "full passwords in report").await;
    }
    if fmt.eq_ignore_ascii_case("html") {
        let summary = crate::core::result::AttackSummary {
            run_id: job.run_id.clone(),
            start_time: chrono::Utc::now(),
            end_time: None,
            total_targets: job.total_targets_est,
            total_credentials: job.total_credentials_est,
            attempts: job.attempts,
            successes: job.successes,
            failures: job.failures,
            errors: job.errors,
            results: job.results.clone(),
            total_duration: None,
        };
        let html = crate::utils::report::generate_html_report(&summary, show);
        return Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response());
    }
    // JSON envelope v2.
    let findings: Vec<Value> = job
        .results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut f = serde_json::to_value(FindingV2::from_result(r, &job.run_id, i as u64, &job.created_at)).unwrap_or(json!({}));
            if show {
                f["password"] = json!(r.password);
            }
            f
        })
        .collect();
    Ok(Json(json!({
        "schema": "veltrix-report/v2",
        "job_id": job.id,
        "run_id": job.run_id,
        "status": job.status.as_str(),
        "target": job.target,
        "port": job.port,
        "protocol": job.protocol,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "attempts": job.attempts,
        "successes": job.successes,
        "failures": job.failures,
        "errors": job.errors,
        "findings": findings,
    }))
    .into_response())
}

async fn stop_job_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let actor = require_auth(&state, &headers, ip).await?;
    let mut jobs = state.jobs.write().await;
    match jobs.get_mut(&id) {
        Some(job) => {
            if job.status == JobStatus::Running || job.status == JobStatus::Queued {
                job.cancel.store(false, std::sync::atomic::Ordering::SeqCst);
                job.push_log(format!("stop requested by {}", actor));
                state.audit(&actor, "job_stop", Some(&id), "stop requested").await;
                Ok(Json(json!({ "job_id": job.id, "status": "stopping" })).into_response())
            } else {
                Ok(Json(json!({ "job_id": job.id, "status": job.status.as_str(), "note": "job not running" })).into_response())
            }
        }
        None => Err(err(StatusCode::NOT_FOUND, "job not found")),
    }
}

async fn job_events_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    Path(id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
) -> ApiResult {
    // Browser WS tidak bisa set header: terima Bearer header ATAU ?token=.
    let authed = match bearer(&headers).and_then(|b| state.auth.verify(&b)) {
        Some(sub) => Some(sub),
        None => q.get("token").and_then(|t| state.auth.verify(t)),
    };
    let _actor = match authed {
        Some(a) => a,
        None => return Err(err(StatusCode::UNAUTHORIZED, "valid Bearer JWT required (header or ?token=)")),
    };
    if !state.rate_limiter.allow(ip.ip()).await {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "API rate limit exceeded"));
    }
    let snapshot = {
        let jobs = state.jobs.read().await;
        jobs.get(&id).map(|j| JobEvent {
            job_id: j.id.clone(),
            status: j.status.as_str().into(),
            progress: j.progress,
            attempts: j.attempts,
            successes: j.successes,
            msg: "snapshot".into(),
        })
    };
    let snapshot = match snapshot {
        Some(s) => s,
        None => return Err(err(StatusCode::NOT_FOUND, "job not found")),
    };
    let rx = state.events.subscribe();
    Ok(ws.on_upgrade(move |socket| ws_job_feed(socket, rx, id, snapshot)).into_response())
}

async fn ws_send(socket: &mut WebSocket, ev: &JobEvent) -> bool {
    let payload = json!({
        "job_id": ev.job_id,
        "status": ev.status,
        "progress": ev.progress,
        "attempts": ev.attempts,
        "successes": ev.successes,
        "msg": ev.msg,
        "ts": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();
    socket.send(Message::Text(payload)).await.is_ok()
}

async fn ws_job_feed(
    mut socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<JobEvent>,
    job_id: String,
    snapshot: JobEvent,
) {
    if !ws_send(&mut socket, &snapshot).await {
        return;
    }
    if matches!(snapshot.status.as_str(), "completed" | "failed" | "stopped") {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(ev) if ev.job_id == job_id => {
                        if !ws_send(&mut socket, &ev).await {
                            break;
                        }
                        if matches!(ev.status.as_str(), "completed" | "failed" | "stopped") {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    // Ping/pong dijawab otomatis oleh tungstenite; abaikan lainnya.
                    _ => {}
                }
            }
        }
    }
}

async fn audit_handler(
    State(state): State<AppState>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> ApiResult {
    let _actor = require_auth(&state, &headers, ip).await?;
    let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(100).min(1000);
    let log = state.audit.lock().await;
    let entries: Vec<Value> = log
        .iter()
        .rev()
        .take(limit)
        .map(|e| {
            json!({ "ts": e.ts, "actor": e.actor, "action": e.action, "job_id": e.job_id, "detail": e.detail })
        })
        .collect();
    Ok(Json(json!({ "audit": entries, "count": entries.len() })).into_response())
}
