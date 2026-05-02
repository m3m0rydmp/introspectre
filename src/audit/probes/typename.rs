use crate::audit::utils::{effective_headers, post_graphql};
use crate::audit::AuditFinding;
use crate::types::Severity;
use reqwest::Client;
use serde_json::Value;

pub async fn probe_typename(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let typename_resp = post_graphql(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        "{ __typename }",
        rate_limit_ms,
    )
    .await?;

    if extract_typename(&typename_resp.data).as_deref() == Some("Query") {
        confirmed.push(AuditFinding {
            id: "AUD-004",
            severity: Severity::Low,
            title: "GraphQL Confirmed via __typename Probe",
            description: "Endpoint responded with data.__typename=Query without introspection query usage. This confirms GraphQL behavior even if introspection is disabled.".to_string(),
            affected: vec![url.to_string()],
            remediation: "Restrict endpoint exposure and require authorization where appropriate. Keep introspection disabled in production unless explicitly needed.",
            evidence: "confirmed",
            poc: None,
        });
    } else {
        unconfirmed.push(AuditFinding {
            id: "AUD-004",
            severity: Severity::Low,
            title: "GraphQL __typename Probe Inconclusive",
            description: format!(
                "Endpoint did not return data.__typename=Query (HTTP {}). GraphQL may still be present behind auth or non-standard routing.",
                typename_resp.status
            ),
            affected: vec![url.to_string()],
            remediation: "Validate endpoint path, auth requirements, and gateway routing before deeper active probes.",
            evidence: "inconclusive",
            poc: None,
        });
    }
    Ok(())
}

fn extract_typename(data: &Option<Value>) -> Option<String> {
    data.as_ref()
        .and_then(|d| d.get("__typename"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}
