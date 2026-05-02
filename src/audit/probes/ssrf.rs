use crate::audit::utils::{
    build_operation_query, effective_headers, find_root_field, parse_candidate, post_graphql,
};
use crate::audit::AuditFinding;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_ssrf(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let ssrf_finding = passive_findings.iter().find(|f| f.id == "GQL-014");
    let Some(ssrf) = ssrf_finding else {
        return Ok(());
    };

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &ssrf.affected {
        let Some((root, field_name, arg_name)) = parse_candidate(candidate) else {
            continue;
        };
        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };
        let op = if root == "Mutation" {
            "mutation"
        } else {
            "query"
        };

        let mut baseline_overrides = HashMap::new();
        baseline_overrides.insert(arg_name.clone(), "\"https://example.com/\"".to_string());
        let baseline_query = build_operation_query(schema, op, field, &baseline_overrides, false);
        let baseline_resp =
            post_graphql(client, url, &headers, &baseline_query, rate_limit_ms).await?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            "\"http://169.254.169.254/latest/meta-data/\"",
            "\"http://127.0.0.1:80\"",
        ];

        let mut suspicious = false;
        for payload in payloads {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), payload.to_string());
            let query = build_operation_query(schema, op, field, &overrides, false);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;

            let delayed = resp.elapsed_ms > baseline_ms + 1500;
            let aws_keywords = ["meta-data", "instance-id", "ami-id", "security-credentials"]
                .iter()
                .any(|k| resp.raw_text.to_lowercase().contains(k));

            if delayed || aws_keywords {
                suspicious = true;
                break;
            }
        }

        if suspicious {
            confirmed_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        } else {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        }
    }

    if !confirmed_labels.is_empty() {
        confirmed.push(AuditFinding {
            id: "AUD-003",
            severity: Severity::High,
            title: "SSRF Behavior Suspected/Confirmed",
            description: format!(
                "{} operation(s) showed timing/content indicators consistent with SSRF payload handling.",
                confirmed_labels.len()
            ),
            affected: confirmed_labels,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            evidence: "confirmed",
            poc: None,
        });
    }

    if !inconclusive_labels.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-003",
            severity: Severity::Medium,
            title: "SSRF Probe Inconclusive",
            description: format!(
                "{} SSRF candidate(s) did not show clear SSRF indicators under default payload probes.",
                inconclusive_labels.len()
            ),
            affected: inconclusive_labels,
            remediation: "Try operation-specific payload shaping and monitor egress logs for outbound callbacks.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
