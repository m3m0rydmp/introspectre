use crate::audit::utils::{
    effective_headers, extract_verbose_error_hint, post_graphql, typo_variant,
};
use crate::audit::AuditFinding;
use crate::types::{GqlSchema, Severity};
use reqwest::Client;

pub async fn probe_verbose_error_disclosure(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    _batch_probes: bool,
    _batch_size: u32,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let binding = schema.fields_for_type(query_name);
    let Some(first_field) = binding.first() else {
        return Ok(());
    };

    let typo = typo_variant(&first_field.name);
    let typo = if typo == first_field.name {
        format!("{}_typo", first_field.name)
    } else {
        typo
    };

    let query = format!("query {{ {} }}", typo);
    let resp = post_graphql(
        client,
        url,
        &effective_headers(extra_headers, None, false),
        &query,
        rate_limit_ms,
    )
    .await?;

    let hint_source = if resp.errors_text.is_empty() {
        &resp.raw_text
    } else {
        &resp.errors_text
    };

    if let Some(hint) = extract_verbose_error_hint(hint_source) {
        confirmed.push(AuditFinding {
            id: "AUD-005",
            severity: Severity::Low,
            title: "Verbose GraphQL Error Disclosure",
            description: "Endpoint returned field/argument suggestions (for example 'Did you mean ...') for invalid queries, which can aid schema enumeration.".to_string(),
            affected: vec![format!("Query.{} -> {}", typo, hint)],
            remediation: "Use generic production validation errors and disable suggestion hints outside development environments.",
            evidence: "confirmed",
            poc: None,
        });
    } else {
        unconfirmed.push(AuditFinding {
            id: "AUD-005",
            severity: Severity::Low,
            title: "Verbose GraphQL Error Disclosure Probe Inconclusive",
            description: "No suggestion-style verbose validation hint was observed for the typo probe. The server may already sanitize errors or require different malformed payloads.".to_string(),
            affected: vec![format!("query {{ {} }}", typo)],
            remediation: "Confirm production error policy by testing multiple malformed field and argument variants across query and mutation roots.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
