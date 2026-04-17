use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::blocking::Client;
use serde::Deserialize;

use crate::analysis::{fields_for_type, unwrap_type_name};
use crate::types::{AuthDiscoveryResult, GqlError, GqlField, GqlSchema, IntrospectionResponse, INTROSPECTION_QUERY};

#[derive(Debug, Clone)]
pub struct EndpointProbeResult {
    pub graphql_confirmed: bool,
    pub auth_likely_required: bool,
    pub content_type_or_json_issue: bool,
    pub http_status: u16,
    pub summary: String,
}

fn build_client(timeout_secs: u64) -> Result<Client, String> {
    reqwest::blocking::Client::builder()
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

pub fn fetch_introspection(
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
        .header("User-Agent", "GQL-Analyzer/1.0 (Security-Audit-Only)");

    for (k, v) in parse_extra_headers(extra_headers) {
        req = req.header(k, v);
    }

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    if rate_limit_ms > 0 {
        std::thread::sleep(Duration::from_millis(rate_limit_ms));
    }

    let body = serde_json::json!({ "query": INTROSPECTION_QUERY });
    let resp = req.json(&body).send().map_err(|e| {
        format!("Request failed: {}. Check the URL, network access, and any required auth headers.", e)
    })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}: server returned an error.", status));
    }

    let parsed: IntrospectionResponse = resp
        .json()
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

    parsed
        .data
        .map(|d| d.schema)
        .ok_or_else(|| "Response contained no `data.__schema` field. Introspection may be disabled.".into())
}

pub fn probe_graphql_endpoint(
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
        .header("User-Agent", "GQL-Analyzer/1.0 (Security-Audit-Only; Endpoint-Probe)");

    for (k, v) in parse_extra_headers(extra_headers) {
        req = req.header(k, v);
    }

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }

    if rate_limit_ms > 0 {
        std::thread::sleep(Duration::from_millis(rate_limit_ms));
    }

    // Minimal knock that confirms GraphQL without requiring introspection.
    let body = serde_json::json!({ "query": "query ProbeTypename { __typename }" });
    let resp = req
        .json(&body)
        .send()
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

    let parsed: Result<ProbeResponse, _> = resp.json();
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
                summary: "GraphQL confirmed, but auth is likely required for full access.".to_string(),
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
                summary: "Endpoint behaves like GraphQL (GraphQL-formatted errors observed).".to_string(),
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
    let content = fs::read_to_string(path).map_err(|e| format!("Cannot read file {:?}: {}", path, e))?;

    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let schema_val = value
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| value.get("__schema"))
        .or_else(|| value.get("schema"))
        .ok_or("Could not find `__schema` key in JSON. Ensure this is a GraphQL introspection result.")?;

    serde_json::from_value(schema_val.clone()).map_err(|e| format!("Failed to parse schema: {}", e))
}

#[derive(Debug, Deserialize)]
struct ProbeResponse {
    data: Option<serde_json::Value>,
    errors: Option<Vec<GqlError>>,
}

fn type_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field.field_type.as_ref().and_then(unwrap_type_name)?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.kind.clone())
}

fn has_required_args(field: &GqlField) -> bool {
    field
        .args
        .as_ref()
        .map(|args| {
            args.iter().any(|a| {
                a.arg_type
                    .as_ref()
                    .and_then(|t| t.kind.as_deref())
                    .map(|k| k == "NON_NULL")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
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

pub fn discover_auth_requirements(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
) -> Result<AuthDiscoveryResult, String> {
    let client = build_client(timeout_secs)?;
    let mut result = AuthDiscoveryResult::new();

    let mut targets: Vec<(String, String, &GqlField)> = Vec::new();
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());

    for f in fields_for_type(schema, query_name) {
        targets.push(("query".to_string(), "Query".to_string(), f));
    }
    for f in fields_for_type(schema, mutation_name) {
        targets.push(("mutation".to_string(), "Mutation".to_string(), f));
    }

    let max_knocks = 80usize;
    if targets.len() > max_knocks {
        for (_, root, f) in targets.iter().skip(max_knocks) {
            result
                .inconclusive
                .push(format!("{}.{} (skipped: probe limit reached)", root, f.name));
        }
        targets.truncate(max_knocks);
    }

    for (op_keyword, root, field) in targets {
        if rate_limit_ms > 0 {
            std::thread::sleep(Duration::from_millis(rate_limit_ms));
        }

        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "GQL-Analyzer/1.0 (Security-Audit-Only; Auth-Discovery)");
        for (k, v) in parse_extra_headers(extra_headers) {
            req = req.header(k, v);
        }

        let query = knock_query(schema, &op_keyword, field);
        let body = serde_json::json!({ "query": query });
        let call = req.json(&body).send();
        let label = format!("{}.{}", root, field.name);

        let resp = match call {
            Ok(r) => r,
            Err(e) => {
                result
                    .inconclusive
                    .push(format!("{} (network error: {})", label, e));
                continue;
            }
        };

        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            result.protected.push(label);
            continue;
        }

        let parsed: Result<ProbeResponse, _> = resp.json();
        let parsed = match parsed {
            Ok(p) => p,
            Err(_) => {
                result
                    .inconclusive
                    .push(format!("{} (non-JSON response)", label));
                continue;
            }
        };

        if let Some(errors) = parsed.errors {
            let messages = errors
                .iter()
                .map(|e| e.message.to_lowercase())
                .collect::<Vec<_>>()
                .join(" | ");

            if is_auth_error(&messages) {
                result.protected.push(label);
                continue;
            }

            if has_required_args(field) || is_public_likely_error(&messages) {
                result.public.push(label);
            } else {
                result
                    .inconclusive
                    .push(format!("{} (graphql error: {})", label, messages));
            }
            continue;
        }

        if parsed.data.is_some() {
            result.public.push(label);
        } else {
            result.inconclusive.push(format!("{} (no data)", label));
        }
    }

    Ok(result)
}
