use crate::audit::utils::effective_headers;
use crate::audit::AuditFinding;
use crate::types::Severity;
use reqwest::Client;
use std::time::Duration;

pub async fn probe_batching(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let headers = effective_headers(extra_headers, None, false);
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Active-Audit-Probe)");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let body = serde_json::json!([
        { "query": "{ __typename }" },
        { "query": "{ __typename }" }
    ]);

    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let raw_text = resp.text().await.unwrap_or_default();

    let is_batched = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw_text) {
        parsed.is_array() && parsed.as_array().unwrap().len() == 2
    } else {
        false
    };

    if is_batched {
        confirmed.push(AuditFinding {
            id: "AUD-007",
            severity: Severity::Medium,
            title: "Query Batching Enabled",
            description: "The GraphQL endpoint accepts an array of queries in a single HTTP request (array-based batching). This can be abused for brute-force or volumetric DoS attacks.".to_string(),
            affected: vec![url.to_string()],
            remediation: "Disable array-based query batching if not required by your frontend clients, or enforce strict rate limits and complexity budgets per HTTP request.",
            evidence: "confirmed",
            poc: Some("[\n  {\"query\": \"{ __typename }\"},\n  {\"query\": \"{ __typename }\"}\n]".to_string()),
        });
    } else {
        unconfirmed.push(AuditFinding {
            id: "AUD-007",
            severity: Severity::Low,
            title: "Query Batching Disabled / Inconclusive",
            description: format!("The server did not respond with an array of results to a batched query array (HTTP {}).", status),
            affected: vec![url.to_string()],
            remediation: "Ensure that other forms of batching (e.g., query aliasing) are also restricted or monitored.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
