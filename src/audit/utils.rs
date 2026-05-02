use crate::types::{GqlField, GqlSchema};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ProbeResponse {
    pub status: u16,
    pub elapsed_ms: u128,
    pub data: Option<Value>,
    pub errors_text: String,
    pub raw_text: String,
}

pub fn build_client(timeout_secs: u64) -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())
}

pub fn parse_extra_headers(extra_headers: &[String]) -> Vec<(String, String)> {
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

pub fn parse_header_kv(value: &str) -> Option<(String, String)> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("").trim();
    let val = parts.next().unwrap_or("").trim();
    if key.is_empty() {
        None
    } else {
        Some((key.to_string(), val.to_string()))
    }
}

pub fn effective_headers(
    base_headers: &[String],
    session_auth_header: Option<&str>,
    include_auth: bool,
) -> Vec<(String, String)> {
    let mut parsed = parse_extra_headers(base_headers);
    if !include_auth {
        parsed.retain(|(k, _)| !k.eq_ignore_ascii_case("Authorization"));
    }

    if include_auth {
        if let Some(auth_header) = session_auth_header {
            if let Some((k, v)) = parse_header_kv(auth_header) {
                parsed.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&k));
                parsed.push((k, v));
            }
        }
    }

    parsed
}

pub async fn post_graphql(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    query: &str,
    rate_limit_ms: u64,
) -> Result<ProbeResponse, String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Security-Audit-Only)");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let body = serde_json::json!({ "query": query });
    let started = Instant::now();
    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();
    let raw_text = resp.text().await.unwrap_or_default();

    let parsed = serde_json::from_str::<Value>(&raw_text).ok();
    let data = parsed.as_ref().and_then(|v| v.get("data")).cloned();
    let errors_text = parsed
        .as_ref()
        .and_then(|v| v.get("errors"))
        .map(|v| v.to_string())
        .unwrap_or_default();

    Ok(ProbeResponse {
        status,
        elapsed_ms,
        data,
        errors_text,
        raw_text,
    })
}

pub async fn post_batched_graphql(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    queries: &[String],
    rate_limit_ms: u64,
) -> Result<Vec<ProbeResponse>, String> {
    if rate_limit_ms > 0 {
        tokio::time::sleep(Duration::from_millis(rate_limit_ms)).await;
    }

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "Introspectre/1.0 (Security-Audit-Batched)");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let operations: Vec<serde_json::Value> = queries
        .iter()
        .map(|q| serde_json::json!({ "query": q }))
        .collect();

    let body = serde_json::json!(operations);
    let started = Instant::now();
    let resp = req.json(&body).send().await.map_err(|e| e.to_string())?;
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();
    let raw_text = resp.text().await.unwrap_or_default();

    let parsed: Result<Vec<Value>, _> = serde_json::from_str(&raw_text);
    let responses = match parsed {
        Ok(arr) => arr,
        Err(_) => {
            return match serde_json::from_str::<Value>(&raw_text) {
                Ok(single) => Ok(vec![ProbeResponse {
                    status,
                    elapsed_ms,
                    data: single.get("data").cloned(),
                    errors_text: single
                        .get("errors")
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                    raw_text,
                }]),
                Err(_) => Err("Failed to parse batched response".to_string()),
            };
        }
    };

    Ok(responses
        .into_iter()
        .map(|v| ProbeResponse {
            status,
            elapsed_ms,
            data: v.get("data").cloned(),
            errors_text: v.get("errors").map(|e| e.to_string()).unwrap_or_default(),
            raw_text: v.to_string(),
        })
        .collect())
}

pub fn is_auth_error(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "not authenticated",
        "unauthorized",
        "forbidden",
        "auth required",
        "authentication",
        "bearer",
        "jwt",
        "token",
    ]
    .iter()
    .any(|s| m.contains(s))
}

pub fn is_validation_error(message: &str) -> bool {
    let m = message.to_lowercase();
    [
        "validation",
        "invalid value",
        "expected type",
        "must not be null",
        "required",
        "unknown argument",
        "field",
        "syntax error",
    ]
    .iter()
    .any(|s| m.contains(s))
}

pub fn field_non_null_data(data: &Option<Value>, field_name: &str) -> Option<Value> {
    data.as_ref()
        .and_then(|d| d.get(field_name))
        .filter(|v| !v.is_null())
        .cloned()
}

pub fn field_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let field_type_name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(field_type_name.as_str()))
        .and_then(|t| t.kind.clone())
}

pub fn field_type_name(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field
        .field_type
        .as_ref()
        .and_then(|t| t.unwrap_type_name())?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.name.clone())
}

pub fn base_selection(schema: &GqlSchema, field: &GqlField) -> String {
    match field_kind(schema, field).as_deref() {
        Some("OBJECT") | Some("INTERFACE") | Some("UNION") => "{ __typename }".to_string(),
        _ => String::new(),
    }
}

pub fn idor_selection(schema: &GqlSchema, field: &GqlField) -> String {
    let type_name = match field_type_name(schema, field) {
        Some(n) => n,
        None => return base_selection(schema, field),
    };

    let fields = schema.fields_for_type(Some(type_name.as_str()));
    if fields.is_empty() {
        return base_selection(schema, field);
    }

    let preferred = ["id", "userId", "ownerId", "email", "username", "__typename"];
    let mut selected: Vec<String> = Vec::new();
    for key in preferred {
        if key == "__typename" {
            selected.push("__typename".to_string());
            continue;
        }
        if fields.iter().any(|f| f.name == key) {
            selected.push(key.to_string());
        }
    }

    if selected.is_empty() {
        return base_selection(schema, field);
    }

    format!("{{ {} }}", selected.join(" "))
}

pub fn default_literal(type_name: Option<String>) -> String {
    match type_name.unwrap_or_default().as_str() {
        "Int" => "1".to_string(),
        "Float" => "1.0".to_string(),
        "Boolean" => "true".to_string(),
        "ID" => "\"1\"".to_string(),
        "String" => "\"sample\"".to_string(),
        other if other.contains("ID") => "\"1\"".to_string(),
        _ => "\"sample\"".to_string(),
    }
}

pub fn build_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, String>,
    use_idor_selection: bool,
) -> String {
    let mut args_rendered: Vec<String> = Vec::new();
    if let Some(args) = &field.args {
        for arg in args {
            let value = arg_overrides.get(&arg.name).cloned().unwrap_or_else(|| {
                default_literal(arg.arg_type.as_ref().and_then(|t| t.unwrap_type_name()))
            });
            args_rendered.push(format!("{}: {}", arg.name, value));
        }
    }

    let args_block = if args_rendered.is_empty() {
        String::new()
    } else {
        format!("({})", args_rendered.join(", "))
    };

    let selection = if use_idor_selection {
        idor_selection(schema, field)
    } else {
        base_selection(schema, field)
    };

    format!(
        "{} {{ {}{} {} }}",
        op_keyword, field.name, args_block, selection
    )
}

pub fn has_required_args(field: &GqlField) -> bool {
    field
        .args
        .as_ref()
        .map(|args| {
            args.iter()
                .any(|a| a.arg_type.as_ref().and_then(|t| t.kind.as_deref()) == Some("NON_NULL"))
        })
        .unwrap_or(false)
}

pub fn typo_variant(name: &str) -> String {
    if name.ends_with('s') && name.len() > 1 {
        name[..name.len() - 1].to_string()
    } else {
        format!("{}s", name)
    }
}

pub fn extract_verbose_error_hint(message: &str) -> Option<String> {
    let normalized = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }

    let lower = normalized.to_lowercase();
    let looks_verbose = lower.contains("did you mean")
        || lower.contains("cannot query field")
        || lower.contains("unknown argument")
        || lower.contains("perhaps you meant");

    if !looks_verbose {
        return None;
    }

    let max_len = 220usize;
    if normalized.len() <= max_len {
        Some(normalized)
    } else {
        Some(format!("{}...", &normalized[..max_len]))
    }
}

pub fn parse_candidate(label: &str) -> Option<(String, String, String)> {
    let dot = label.find('.')?;
    let open = label.find('(')?;
    let close = label.find(')')?;
    if close <= open || open <= dot {
        return None;
    }

    let root = label[..dot].to_string();
    let field = label[dot + 1..open].to_string();
    let arg = label[open + 1..close].to_string();
    Some((root, field, arg))
}

pub fn find_root_field<'a>(
    schema: &'a GqlSchema,
    root: &str,
    field_name: &str,
) -> Option<&'a GqlField> {
    let type_name = match root {
        "Query" => schema.query_type.as_ref().map(|q| q.name.as_str()),
        "Mutation" => schema.mutation_type.as_ref().map(|m| m.name.as_str()),
        _ => None,
    };

    schema
        .fields_for_type(type_name)
        .into_iter()
        .find(|f| f.name == field_name)
}
