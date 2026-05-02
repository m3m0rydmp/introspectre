use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data, find_root_field,
    parse_candidate, post_graphql,
};
use crate::audit::AuditFinding;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_idor(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
    idor_payloads: &[String],
) -> Result<(), String> {
    let idor_finding = passive_findings.iter().find(|f| f.id == "GQL-013");
    let Some(idor) = idor_finding else {
        return Ok(());
    };

    if config.session.auth_header.trim().is_empty() || config.session.owned_ids.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-002",
            severity: Severity::Medium,
            title: "IDOR Probe Skipped (Missing Session Config)",
            description: "IDOR probing requires session.auth_header and at least one session.owned_ids value in config.".to_string(),
            affected: vec!["session.auth_header / session.owned_ids".to_string()],
            remediation: "Provide a valid authenticated header and owned IDs in config before running audit with test_idor enabled.",
            evidence: "inconclusive",
            poc: None,
        });
        return Ok(());
    }

    let headers = effective_headers(
        extra_headers,
        Some(config.session.auth_header.as_str()),
        true,
    );
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &idor.affected {
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

        let mut baseline_payload: Option<String> = None;
        for owned in &config.session.owned_ids {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), format!("\"{}\"", owned));
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                baseline_payload = Some(data.to_string());
                break;
            }
        }

        let Some(baseline) = baseline_payload else {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
            continue;
        };

        let mutated_values = if !idor_payloads.is_empty() {
            idor_payloads.iter().map(|s| format!("\"{}\"", s)).collect()
        } else {
            vec![
                "\"1\"".to_string(),
                "\"2\"".to_string(),
                "\"3\"".to_string(),
            ]
        };

        let mut candidate_confirmed = false;
        for mutated in mutated_values {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), mutated);
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;

            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                let payload = data.to_string();
                if payload != baseline {
                    confirmed_labels.push(format!("{}.{}({})", root, field_name, arg_name));
                    candidate_confirmed = true;
                    break;
                }
            }
        }

        if !candidate_confirmed {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        }
    }

    if !confirmed_labels.is_empty() {
        let poc = confirmed_labels
            .first()
            .and_then(|label| parse_candidate(label))
            .map(|(root, field_name, arg_name)| {
                let keyword = if root == "Mutation" { "mutation" } else { "query" };
                format!(
                    "# IDOR confirmed: {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    id\n    __typename\n  }}\n}}",
                    root, field_name, keyword, field_name, arg_name
                )
            });

        confirmed.push(AuditFinding {
            id: "AUD-002",
            severity: Severity::High,
            title: "IDOR Behavior Confirmed",
            description: format!(
                "{} ID-based operation(s) returned differing data for mutated identifiers using an authenticated session.",
                confirmed_labels.len()
            ),
            affected: confirmed_labels,
            remediation: "Enforce object-level authorization checks by ownership on every ID-based resolver path.",
            evidence: "confirmed",
            poc,
        });
    }

    if !inconclusive_labels.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-002",
            severity: Severity::Medium,
            title: "IDOR Probe Inconclusive",
            description: format!(
                "{} IDOR candidate(s) could not be confirmed with current owned IDs and default mutation set.",
                inconclusive_labels.len()
            ),
            affected: inconclusive_labels,
            remediation: "Expand candidate IDs and include operation-specific payloads to increase probe coverage.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
