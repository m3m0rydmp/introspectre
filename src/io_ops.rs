use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use reqwest::Client;
use serde::Deserialize;

use crate::types::{
    AuthDiscoveryResult, GqlError, GqlField, GqlSchema, IntrospectionResponse, INTROSPECTION_QUERY,
};

#[derive(Debug, Clone)]
pub struct EndpointProbeResult {
    pub graphql_confirmed: bool,
    pub auth_likely_required: bool,
    pub content_type_or_json_issue: bool,
    pub http_status: u16,
    pub summary: String,
}

fn build_client(timeout_secs: u64) -> Result<Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())
}

fn parse_extra_headers(extra_headers: &[String]) -> Vec<(String, String)> {
    extra_headers
        .iter()
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            if key.is_empty() {
                None
            } else {
                Some((key.to_string(), val.to_string()))
            }
        })
        .collect()
}

pub async fn fetch_introspection(
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    token: Option<&str>,
) -> Result<GqlSchema, String> {
    let client = build_client(timeout_secs)?;

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Security-Audit-Only)");

    for (k, v) in parse_extra_headers(extra_headers) {
        req = req.header(k, v);
    }

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let body = serde_json::json!({ "query": INTROSPECTION_QUERY });
    let resp = req.json(&body).send().await.map_err(|e| {
        format!(
            "Request failed: {}. Check the URL, network access, and any required auth headers.",
            e
        )
    })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}: server returned an error.", status));
    }

    let parsed: IntrospectionResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {}", e))?;

    if let Some(errors) = parsed.errors {
        let msgs: Vec<_> = errors.iter().map(|e| e.message.to_lowercase()).collect();
        let all = msgs.join("; ");
        let introspection_signals = [
            "introspection is disabled",
            "cannot query field \"__schema\"",
            "cannot query field '__schema'",
            "introspection",
            "graphql introspection has been disabled",
        ];
        if introspection_signals.iter().any(|s| all.contains(s)) {
            return Err(
                "GraphQL endpoint responded, but introspection appears disabled or blocked for this request."
                    .to_string(),
            );
        }
        if is_auth_error(&all) {
            return Err("GraphQL endpoint responded, but introspection appears auth-gated. Try --token <JWT>.".to_string());
        }
        return Err(format!("GraphQL errors: {}", all));
    }

    parsed.data.map(|d| d.schema).ok_or_else(|| {
        "Response contained no `data.__schema` field. Introspection may be disabled.".into()
    })
}

pub async fn probe_graphql_endpoint(
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    token: Option<&str>,
) -> Result<EndpointProbeResult, String> {
    let client = build_client(timeout_secs)?;

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            "Introspectre/1.0 (Security-Audit-Only; Endpoint-Probe)",
        );

    for (k, v) in parse_extra_headers(extra_headers) {
        req = req.header(k, v);
    }

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    // Minimal knock that confirms GraphQL without requiring introspection.
    let body = serde_json::json!({ "query": "query ProbeTypename { __typename }" });
    let resp = req
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Probe request failed: {}", e))?;

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Ok(EndpointProbeResult {
            graphql_confirmed: false,
            auth_likely_required: true,
            content_type_or_json_issue: false,
            http_status: status.as_u16(),
            summary: format!(
                "HTTP {} from probe endpoint. This path may be GraphQL but requires authentication.",
                status
            ),
        });
    }

    let parsed: Result<ProbeResponse, _> = resp.json().await;
    let parsed = match parsed {
        Ok(p) => p,
        Err(_) => {
            return Ok(EndpointProbeResult {
                graphql_confirmed: false,
                auth_likely_required: false,
                content_type_or_json_issue: true,
                http_status: status.as_u16(),
                summary: "Probe did not return valid GraphQL JSON. Check endpoint path and Content-Type handling."
                    .to_string(),
            })
        }
    };

    if let Some(data) = &parsed.data {
        if data.get("__typename").is_some() {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                auth_likely_required: false,
                content_type_or_json_issue: false,
                http_status: status.as_u16(),
                summary: "GraphQL confirmed via __typename probe.".to_string(),
            });
        }
    }

    if let Some(errors) = parsed.errors {
        let messages = errors
            .iter()
            .map(|e| e.message.to_lowercase())
            .collect::<Vec<_>>()
            .join(" | ");

        if is_auth_error(&messages) {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                auth_likely_required: true,
                content_type_or_json_issue: false,
                http_status: status.as_u16(),
                summary: "GraphQL confirmed, but auth is likely required for full access."
                    .to_string(),
            });
        }

        let graphql_error_signals = [
            "cannot query field",
            "syntax error",
            "selection set",
            "unknown argument",
            "graphql",
        ];
        if graphql_error_signals.iter().any(|s| messages.contains(s)) {
            return Ok(EndpointProbeResult {
                graphql_confirmed: true,
                auth_likely_required: false,
                content_type_or_json_issue: false,
                http_status: status.as_u16(),
                summary: "Endpoint behaves like GraphQL (GraphQL-formatted errors observed)."
                    .to_string(),
            });
        }

        return Ok(EndpointProbeResult {
            graphql_confirmed: false,
            auth_likely_required: false,
            content_type_or_json_issue: false,
            http_status: status.as_u16(),
            summary: format!("Probe returned inconclusive errors: {}", messages),
        });
    }

    Ok(EndpointProbeResult {
        graphql_confirmed: false,
        auth_likely_required: false,
        content_type_or_json_issue: false,
        http_status: status.as_u16(),
        summary: "Probe response was inconclusive (no GraphQL data/errors).".to_string(),
    })
}

pub fn load_schema_from_file(path: &PathBuf) -> Result<GqlSchema, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read file {:?}: {}", path, e))?;

    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let schema_val = value
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| value.get("__schema"))
        .or_else(|| value.get("schema"))
        .ok_or(
            "Could not find `__schema` key in JSON. Ensure this is a GraphQL introspection result.",
        )?;

    serde_json::from_value(schema_val.clone()).map_err(|e| format!("Failed to parse schema: {}", e))
}

#[derive(Debug, Deserialize)]
struct ProbeResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<GqlError>>,
}

fn type_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.kind.clone())
}

fn knock_query(schema: &GqlSchema, op: &str, field: &GqlField) -> String {
    let selection = match type_kind(schema, field).as_deref() {
        Some("OBJECT") | Some("INTERFACE") | Some("UNION") => " { __typename }",
        _ => "",
    };
    format!("{} {{ {}{} }}", op, field.name, selection)
}

fn is_auth_error(msg: &str) -> bool {
    let m = msg.to_lowercase();
    let auth_signals = [
        "not authenticated",
        "unauthorized",
        "forbidden",
        "auth required",
        "authentication",
        "bearer",
        "jwt",
        "token",
    ];
    auth_signals.iter().any(|s| m.contains(s))
}

fn is_public_likely_error(msg: &str) -> bool {
    let m = msg.to_lowercase();
    let signals = [
        "required",
        "missing",
        "argument",
        "unknown argument",
        "sub selection",
        "selection set",
        "cannot query field",
    ];
    signals.iter().any(|s| m.contains(s))
}

pub async fn discover_auth_requirements(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
) -> Result<AuthDiscoveryResult, String> {
    let client = build_client(timeout_secs)?;
    let mut result = AuthDiscoveryResult::new();

    let mut targets: Vec<(String, String, String)> = Vec::new();
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    for f in schema.fields_for_type(query_name) {
        targets.push((
            "query".to_string(),
            "Query".to_string(),
            knock_query(schema, "query", f),
        ));
    }
    for f in schema.fields_for_type(mutation_name) {
        targets.push((
            "mutation".to_string(),
            "Mutation".to_string(),
            knock_query(schema, "mutation", f),
        ));
    }

    let max_knocks = 80usize;
    if targets.len() > max_knocks {
        for (_, root, _) in targets.iter().skip(max_knocks) {
            result
                .inconclusive
                .push(format!("{} (skipped: probe limit reached)", root));
        }
        targets.truncate(max_knocks);
    }

    let parsed_headers = parse_extra_headers(extra_headers);
    let mut futures = FuturesUnordered::new();

    // Throttled concurrency: process up to 5 concurrent probes
    let concurrency_limit = 5;
    let url_owned = url.to_string();

    for (_op_keyword, root, query) in targets {
        while futures.len() >= concurrency_limit {
            if let Some(res) = futures.next().await {
                process_discovery_result(res, &mut result);
            }
        }

        let client = client.clone();
        let url = url_owned.clone();
        let headers = parsed_headers.clone();

        futures.push(tokio::spawn(async move {
            if rate_limit_ms > 0 {
                tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
            }

            let mut req = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header(
                    "User-Agent",
                    "Introspectre/1.0 (Security-Audit-Only; Auth-Discovery)",
                );
            for (k, v) in headers {
                req = req.header(k, v);
            }

            let body = serde_json::json!({ "query": query });
            // Extract field name from query for the label
            let field_part = query.split_whitespace().nth(2).unwrap_or("unknown");
            let label = format!("{}.{}", root, field_part);

            let resp = req.json(&body).send().await;

            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status == 401 || status == 403 {
                        return (label, status, None);
                    }
                    let parsed: Result<ProbeResponse, _> = r.json().await;
                    (label, status, Some(parsed))
                }
                Err(_) => (label, 0, None),
            }
        }));
    }

    while let Some(res) = futures.next().await {
        process_discovery_result(res, &mut result);
    }

    Ok(result)
}

type DiscoveryResult = (String, u16, Option<Result<ProbeResponse, reqwest::Error>>);

fn process_discovery_result(
    res: Result<DiscoveryResult, tokio::task::JoinError>,
    result: &mut AuthDiscoveryResult,
) {
    if let Ok((label, status, parsed_opt)) = res {
        if status == 401 || status == 403 {
            result.protected.push(label);
            return;
        }

        if status == 0 {
            result
                .inconclusive
                .push(format!("{} (network error)", label));
            return;
        }

        if let Some(parsed_res) = parsed_opt {
            match parsed_res {
                Ok(parsed) => {
                    if let Some(errors) = parsed.errors {
                        let messages = errors
                            .iter()
                            .map(|e| e.message.to_lowercase())
                            .collect::<Vec<_>>()
                            .join(" | ");

                        if is_auth_error(&messages) {
                            result.protected.push(label);
                        } else if is_public_likely_error(&messages) {
                            result.public.push(label);
                        } else {
                            result
                                .inconclusive
                                .push(format!("{} (graphql error: {})", label, messages));
                        }
                    } else if parsed.data.is_some() {
                        result.public.push(label);
                    } else {
                        result.inconclusive.push(format!("{} (no data)", label));
                    }
                }
                Err(_) => {
                    result
                        .inconclusive
                        .push(format!("{} (non-JSON response)", label));
                }
            }
        } else {
            result
                .inconclusive
                .push(format!("{} (unknown error)", label));
        }
    }
}
