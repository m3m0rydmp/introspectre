use crate::audit::utils::{
    build_operation_query, effective_headers, field_non_null_data, has_required_args,
    is_auth_error, is_validation_error, post_graphql, post_batched_graphql,
};
use crate::audit::AuditFinding;
use crate::types::{GqlField, GqlSchema, Severity};
use reqwest::Client;
use std::collections::HashMap;

pub async fn probe_unauth_access(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    batch_probes: bool,
    batch_size: u32,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let mut confirmed_access: Vec<String> = Vec::new();
    let mut inconclusive: Vec<String> = Vec::new();
    let mut skipped_required_args = 0usize;
    let mut auth_blocked = 0usize;
    let mut validation_failures = 0usize;
    let mut attempted = 0usize;

    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    let mut targets: Vec<(&str, &str, &GqlField)> = Vec::new();
    for f in schema.fields_for_type(query_name) {
        targets.push(("query", "Query", f));
    }
    for f in schema.fields_for_type(mutation_name) {
        targets.push(("mutation", "Mutation", f));
    }

    let headers = effective_headers(extra_headers, None, false);

    if batch_probes && batch_size > 0 {
        let batch_size_usize = batch_size as usize;
        let mut query_batch: Vec<(String, &str, &str, &GqlField)> = Vec::new();

        for (op, root, field) in targets {
            if has_required_args(field) {
                skipped_required_args += 1;
                continue;
            }

            attempted += 1;
            let query = build_operation_query(schema, op, field, &HashMap::new(), false);
            query_batch.push((query, op, root, field));

            if query_batch.len() >= batch_size_usize {
                let batch_queries: Vec<String> = query_batch.iter().map(|(q, _, _, _)| q.clone()).collect();
                let responses = post_batched_graphql(client, url, &headers, &batch_queries, rate_limit_ms).await?;

                for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                    let label = format!("{}.{}", root, field.name);
                    if let Some(resp) = responses.get(idx) {
                        if field_non_null_data(&resp.data, &field.name).is_some() {
                            confirmed_access.push(label);
                        } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                            auth_blocked += 1;
                        } else if is_validation_error(&resp.errors_text) {
                            validation_failures += 1;
                        } else {
                            inconclusive.push(label);
                        }
                    }
                }
                query_batch.clear();
            }
        }

        if !query_batch.is_empty() {
            let batch_queries: Vec<String> = query_batch.iter().map(|(q, _, _, _)| q.clone()).collect();
            let responses = post_batched_graphql(client, url, &headers, &batch_queries, rate_limit_ms).await?;

            for (idx, (_, _, root, field)) in query_batch.iter().enumerate() {
                let label = format!("{}.{}", root, field.name);
                if let Some(resp) = responses.get(idx) {
                    if field_non_null_data(&resp.data, &field.name).is_some() {
                        confirmed_access.push(label);
                    } else if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                        auth_blocked += 1;
                    } else if is_validation_error(&resp.errors_text) {
                        validation_failures += 1;
                    } else {
                        inconclusive.push(label);
                    }
                }
            }
        }
    } else {
        for (op, root, field) in targets {
            if has_required_args(field) {
                skipped_required_args += 1;
                continue;
            }

            attempted += 1;
            let query = build_operation_query(schema, op, field, &HashMap::new(), false);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms).await?;
            let label = format!("{}.{}", root, field.name);

            if field_non_null_data(&resp.data, &field.name).is_some() {
                confirmed_access.push(label);
                continue;
            }

            if resp.status == 401 || resp.status == 403 || is_auth_error(&resp.errors_text) {
                auth_blocked += 1;
                continue;
            }

            if is_validation_error(&resp.errors_text) {
                validation_failures += 1;
                continue;
            }

            inconclusive.push(label);
        }
    }

    if !confirmed_access.is_empty() {
        let poc = confirmed_access.first().map(|label| {
            let field = label.split('.').nth(1).unwrap_or("fieldName");
            format!(
                "curl -X POST {} \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"query\":\"{{ {} {{ id }} }}\"}}'",
                url, field
            )
        });

        confirmed.push(AuditFinding {
            id: "AUD-001",
            severity: Severity::High,
            title: "Unauthenticated Access Confirmed",
            description: format!(
                "{} query/mutation root operation(s) returned non-null data without Authorization (attempted {} no-required-arg operations; {} blocked by auth; {} skipped due required args).",
                confirmed_access.len(),
                attempted,
                auth_blocked,
                skipped_required_args
            ),
            affected: confirmed_access,
            remediation: "Require authentication and resolver-level authorization checks before returning data for all root operations.",
            evidence: "confirmed",
            poc,
        });
    }

    if !inconclusive.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-001",
            severity: Severity::Medium,
            title: "Unauthenticated Access Probe Inconclusive",
            description: format!(
                "{} operation(s) returned non-auth errors or null data in unauthenticated probe mode (attempted {}; {} blocked by auth; {} skipped due required args; {} validation failures ignored).",
                inconclusive.len(),
                attempted,
                auth_blocked,
                skipped_required_args,
                validation_failures
            ),
            affected: inconclusive,
            remediation: "Review resolver authorization behavior and test manually with operation-specific payloads.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
