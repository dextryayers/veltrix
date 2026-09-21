use std::path::Path;
use crate::core::result::{mask_password, AttackSummary};
use crate::core::error::AttackError;

/// Rekomendasi remediasi per protokol untuk laporan (F6.2).
fn remediation_for(protocol: &str) -> &'static str {
    match protocol.to_lowercase().as_str() {
        "ssh" => "Disable password auth where possible (keys + MFA); enforce fail2ban / rate limiting; rotate exposed credentials immediately.",
        "ftp" | "telnet" => "Replace plaintext protocols with SFTP/SSH; if FTP is required, enforce FTPS + IP allowlisting.",
        "rdp" => "Restrict RDP to VPN/bastion; enforce NLA + MFA; enable account lockout policy.",
        "smb" => "Disable SMBv1; enforce signing; restrict lateral movement via firewall; rotate machine and service accounts.",
        "http" | "http-basic" | "http-digest" | "http-form" => "Enforce MFA + rate limiting + CAPTCHA on login; review session handling; rotate secrets.",
        "mysql" | "postgres" | "mssql" | "mongodb" | "redis" | "oracle" | "cassandra" | "couchdb" | "elasticsearch" | "firebird" => "Bind databases to private networks; enforce strong unique passwords + TLS; audit grants; rotate credentials.",
        "smtp" | "pop3" | "imap" => "Enforce modern auth (XOAUTH2 where supported) + TLS; review mailbox delegation; rotate app passwords.",
        "ldap" => "Enforce LDAPS + strong bind credentials; review directory ACLs.",
        "vnc" => "Tunnel VNC over SSH/VPN; enforce long random passwords.",
        "snmp" => "Migrate to SNMPv3 with authPriv; remove default community strings.",
        _ => "Rotate exposed credentials; enforce MFA and rate limiting; restrict network exposure to trusted sources.",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn generate_html_report(summary: &AttackSummary, show_secrets: bool) -> String {
    let duration_str = summary.total_duration
        .map(|d| format!("{:.2}s", d.as_secs_f64()))
        .unwrap_or_else(|| "N/A".to_string());

    let success_rows: String = summary.results.iter()
        .filter(|r| r.success)
        .map(|r| {
            let pw = if show_secrets { r.password.clone() } else { mask_password(&r.password) };
            format!(
                "<tr class=\"success-row\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>high</td></tr>",
                esc(&r.target_host),
                r.target_port,
                esc(&r.protocol),
                esc(&r.username),
                esc(&pw),
                r.timestamp.format("%Y-%m-%d %H:%M:%S"),
                r.duration_ms,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Evidence appendix: gagal + error, evidence dipotong aman, tanpa password penuh.
    let mut evidence_rows: Vec<String> = Vec::new();
    for r in summary.results.iter().filter(|r| !r.success).take(100) {
        evidence_rows.push(format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&r.target_host),
            r.target_port,
            esc(&r.protocol),
            esc(&r.username),
            esc(&r.safe_evidence()),
        ));
    }
    let evidence_rows = evidence_rows.join("\n");
    let evidence_count = std::cmp::min(summary.results.iter().filter(|r| !r.success).count(), 100);

    // Rekomendasi per protokol yang terbukti jebol.
    let mut seen_proto: Vec<String> = Vec::new();
    for r in summary.results.iter().filter(|r| r.success) {
        let p = r.protocol.to_lowercase();
        if !seen_proto.contains(&p) {
            seen_proto.push(p);
        }
    }
    let remediation_rows: String = seen_proto.iter()
        .map(|p| format!("<tr><td>{}</td><td>{}</td></tr>", esc(p), esc(remediation_for(p))))
        .collect::<Vec<_>>()
        .join("\n");
    let remediation_section = if remediation_rows.is_empty() {
        "<p>No successful findings. No protocol-specific remediation required from this run.</p>".to_string()
    } else {
        format!(
            "<table><thead><tr><th>Protocol</th><th>Recommended remediation</th></tr></thead><tbody>{}</tbody></table>",
            remediation_rows
        )
    };

    let verdict = if summary.successes > 0 {
        format!(
            "<div class=\"verdict bad\">{} valid credential(s) found. Treat affected accounts as compromised: rotate immediately, review logs for misuse, and apply the remediations below.</div>",
            summary.successes
        )
    } else {
        "<div class=\"verdict ok\">No valid credentials found in this run. This does not prove the absence of weak credentials, only that this wordlist and scope found none.</div>".to_string()
    };

    let finished = summary.end_time
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "N/A".to_string());

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veltrix Attack Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
  h1, h2, h3 {{ color: #58a6ff; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat .value {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ color: #8b949e; font-size: 0.85em; text-transform: uppercase; }}
  .stat.success .value {{ color: #3fb950; }}
  .stat.fail .value {{ color: #f85149; }}
  .stat.error .value {{ color: #d29922; }}
  .verdict {{ border-radius: 8px; padding: 16px; margin: 16px 0; font-weight: 500; }}
  .verdict.bad {{ background: #3d1113; border: 1px solid #f85149; color: #ffb4b4; }}
  .verdict.ok {{ background: #0e2a1a; border: 1px solid #3fb950; color: #9df0b6; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .success-row {{ color: #3fb950; }}
  .fail-row {{ color: #f85149; }}
  .footer {{ margin-top: 32px; color: #8b949e; font-size: 0.85em; text-align: center; }}
  .meta {{ color: #8b949e; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Veltrix Attack Report</h1>
<p class="meta">Run <code>{}</code> &middot; authorized testing only</p>
{}
<div class="summary">
  <div class="stat success"><div class="value">{}</div><div class="label">Successes</div></div>
  <div class="stat fail"><div class="value">{}</div><div class="label">Failures</div></div>
  <div class="stat error"><div class="value">{}</div><div class="label">Errors</div></div>
  <div class="stat"><div class="value">{}</div><div class="label">Targets</div></div>
  <div class="stat"><div class="value">{}</div><div class="label">Credentials</div></div>
  <div class="stat"><div class="value">{}</div><div class="label">Duration</div></div>
</div>

<h2>Executive summary</h2>
<p>Scope: {} target(s), {} credential(s), {} attempt(s). Findings below list every
validated credential{}. Passwords are masked unless the report was generated with
<code>--show-secrets</code>.</p>

<h2>Successes ({} found)</h2>
<table>
<thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Username</th><th>Password</th><th>Timestamp</th><th>ms</th><th>Severity</th></tr></thead>
<tbody>{}
</tbody></table>

<h2>Remediation</h2>
{}

<h2>Evidence appendix ({} shown, truncated, no secrets)</h2>
<table>
<thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Username</th><th>Evidence</th></tr></thead>
<tbody>{}
</tbody></table>

<div class="footer">
  Generated by Veltrix v{} |
  Run: {} |
  Started: {} |
  Finished: {} |
  Total attempts: {}
</div>
</body>
</html>"#,
        esc(&summary.run_id),
        verdict,
        summary.successes,
        summary.failures,
        summary.errors,
        summary.total_targets,
        summary.total_credentials,
        duration_str,
        summary.total_targets,
        summary.total_credentials,
        summary.attempts,
        if summary.successes > 0 { " (rotate immediately)" } else { "" },
        summary.successes,
        success_rows,
        remediation_section,
        evidence_count,
        evidence_rows,
        env!("CARGO_PKG_VERSION"),
        esc(&summary.run_id),
        summary.start_time.format("%Y-%m-%d %H:%M:%S"),
        finished,
        summary.attempts,
    )
}

pub fn save_html_report(path: &Path, summary: &AttackSummary, show_secrets: bool) -> Result<(), AttackError> {
    let html = generate_html_report(summary, show_secrets);
    std::fs::write(path, html)
        .map_err(|e| AttackError::io("report", format!("Failed to write HTML report: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::result::AttackSummary;
    use chrono::Utc;
    use std::time::Duration;

    fn sample_summary() -> AttackSummary {
        AttackSummary {
            run_id: "run-test-1".into(),
            start_time: Utc::now(),
            end_time: Some(Utc::now()),
            total_targets: 2,
            total_credentials: 10,
            attempts: 20,
            successes: 1,
            failures: 19,
            errors: 0,
            results: vec![],
            total_duration: Some(Duration::from_secs(5)),
        }
    }

    #[test]
    fn test_generate_html_report_contains_summary_stats() {
        let html = generate_html_report(&sample_summary(), false);
        assert!(html.contains("Successes"));
        assert!(html.contains("Failures"));
        assert!(html.contains("Targets"));
        assert!(html.contains("Credentials"));
        assert!(html.contains("Veltrix"));
        assert!(html.contains("run-test-1"));
        assert!(html.contains("Remediation"));
    }

    #[test]
    fn test_generate_html_report_empty_results() {
        let summary = sample_summary();
        let html = generate_html_report(&summary, false);
        assert!(html.contains("1")); // successes
        assert!(html.contains("19")); // failures
    }

    #[test]
    fn test_html_report_masks_password_by_default() {
        use crate::core::result::AuthResult;
        let mut s = sample_summary();
        s.results.push(AuthResult::new(
            "10.0.0.1".into(), 22, "ssh",
            "admin".into(), "s3cret!".into(),
            true, Duration::from_millis(10), None,
        ));
        let masked = generate_html_report(&s, false);
        assert!(!masked.contains("s3cret!"));
        assert!(masked.contains("s***"));
        let full = generate_html_report(&s, true);
        assert!(full.contains("s3cret!"));
    }

    #[test]
    fn test_html_escapes_injection() {
        use crate::core::result::AuthResult;
        let mut s = sample_summary();
        s.results.push(AuthResult::new(
            "<script>".into(), 22, "ssh",
            "admin".into(), "p".into(),
            true, Duration::from_millis(10), None,
        ));
        let html = generate_html_report(&s, true);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_save_html_report_creates_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_report.html");
        let r = save_html_report(&path, &sample_summary(), false);
        assert!(r.is_ok());
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Veltrix"));
        std::fs::remove_file(&path).ok();
    }
}
