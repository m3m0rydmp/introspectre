use crate::audit::utils::{effective_headers, post_graphql};
use crate::audit::AuditFinding;
use crate::types::Severity;
use reqwest::Client;

pub async fn probe_complexity(
    client: &Client,
    url: &str,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query = "query { a: __typename, b: __typename, c: __typename }";
    let resp = post_graphql(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        query,
        rate_limit_ms,
    )
    .await?;

    let mut complexity_detected = false;
    let mut details = String::new();

    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&resp.raw_text) {
        if let Some(extensions) = data.get("extensions") {
            if extensions.get("complexity").is_some()
                || extensions.get("cost").is_some()
                || extensions.get("depth").is_some()
            {
                complexity_detected = true;
                details = "Found complexity/cost info in extensions.".to_string();
            }
        }
    }

    if complexity_detected {
        confirmed.push(AuditFinding {
            id: "AUD-006",
            severity: Severity::Low,
            title: "Query Complexity/Cost Info Exposed",
            description: format!("The server returns query complexity or cost information in the 'extensions' field. {}", details),
            affected: vec![url.to_string()],
            remediation: "Ensure that complexity information does not reveal sensitive internal limit details to unauthenticated users.",
            evidence: "confirmed",
            poc: Some(query.to_string()),
        });
    } else {
        unconfirmed.push(AuditFinding {
            id: "AUD-006",
            severity: Severity::Low,
            title: "Complexity Probe Inconclusive",
            description: "No complexity or cost information was detected in the response extensions.".to_string(),
            affected: vec![url.to_string()],
            remediation: "Confirm if complexity limiting is implemented by manually testing deeply nested queries.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
