use crate::audit::utils::{effective_headers, post_graphql};
use crate::audit::AuditFinding;
use crate::types::{GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_alias_dos(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let binding = schema.fields_for_type(query_name);
    let Some(first_field) = binding.first() else {
        return Ok(());
    };

    // Build a query with 100 aliases of the same field
    let mut alias_parts = Vec::new();
    for i in 0..100 {
        alias_parts.push(format!("a{}: {}", i, first_field.name));
    }
    let query = format!("query {{ {} }}", alias_parts.join(", "));

    let resp = post_graphql(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &query,
        rate_limit_ms,
    )
    .await?;

    if resp.status == 200 && resp.data.is_some() {
        confirmed.push(AuditFinding {
            id: "AUD-008",
            severity: Severity::Medium,
            title: "Alias-Based DoS Possible",
            description: "The server accepted and executed a query with 100 aliases. Large numbers of aliases can be used to exhaust server resources by triggering many resolver executions in a single request.".to_string(),
            affected: vec![url.to_string()],
            remediation: "Implement a limit on the maximum number of aliases allowed in a single GraphQL operation.",
            evidence: "confirmed",
            poc: Some(format!("query {{ a1: {0}, a2: {0}, ... a100: {0} }}", first_field.name)),
        });
    } else if resp.status == 400 || !resp.errors_text.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-008",
            severity: Severity::Low,
            title: "Alias-Based DoS Limited / Inconclusive",
            description: format!("The server rejected or returned errors for a 100-alias query (HTTP {}). This suggests some level of alias or complexity limiting is in place.", resp.status),
            affected: vec![url.to_string()],
            remediation: "Verify the specific alias or complexity limits and ensure they are appropriately restrictive.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
