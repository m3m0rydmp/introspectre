use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};

use colored::Colorize;
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;

use crate::analysis::{fields_for_type, unwrap_type_name};
use crate::config::AppConfig;
use crate::types::{Finding, GqlField, GqlSchema, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: String,
    pub affected: Vec<String>,
    pub remediation: &'static str,
    pub evidence: &'static str,
    pub poc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub source: String,
    pub passive_total_findings: usize,
    pub confirmed: Vec<AuditFinding>,
    pub unconfirmed: Vec<AuditFinding>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
struct ProbeResponse {
    status: u16,
    elapsed_ms: u128,
    data: Option<Value>,
    errors_text: String,
    raw_text: String,
}

fn print_limited_affected_text(affected: &[String], max_affected: usize) {
    let shown = if max_affected == 0 {
        affected.len()
    } else {
        affected.len().min(max_affected)
    };

    for a in affected.iter().take(shown) {
        println!("      {} {}", "·".bright_black(), a.bright_cyan());
    }

    let remaining = affected.len().saturating_sub(shown);
    if remaining > 0 {
        println!(
            "      {} {}",
            "·".bright_black(),
            format!("... and {} more (use --max-affected 0 to show all)", remaining).bright_black()
        );
    }
}

fn print_limited_affected_markdown(affected: &[String], max_affected: usize) {
    let shown = if max_affected == 0 {
        affected.len()
    } else {
        affected.len().min(max_affected)
    };

    for a in affected.iter().take(shown) {
        println!("- {}", a);
    }

    let remaining = affected.len().saturating_sub(shown);
    if remaining > 0 {
        println!("- ... and {} more (use --max-affected 0 to show all)", remaining);
    }
}

pub fn run_audit(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
) -> Result<AuditReport, String> {
    let client = build_client(timeout_secs)?;
    let mut confirmed: Vec<AuditFinding> = Vec::new();
    let mut unconfirmed: Vec<AuditFinding> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Probe D: endpoint confirmation via __typename (must happen before other active probes).
    let typename_resp = post_graphql(
        &client,
        url,
        &effective_headers(extra_headers, None, false),
        "{ __typename }",
        rate_limit_ms,
    )?;
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

    probe_verbose_error_disclosure(
        schema,
        url,
        &client,
        extra_headers,
        rate_limit_ms,
        &mut confirmed,
        &mut unconfirmed,
    )?;

    if config.audit.test_unauth {
        probe_unauth_access(
            schema,
            url,
            &client,
            extra_headers,
            rate_limit_ms,
            &mut confirmed,
            &mut unconfirmed,
        )?;
    }

    if config.audit.test_idor {
        probe_idor(
            schema,
            url,
            &client,
            extra_headers,
            rate_limit_ms,
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
        )?;
    }

    if config.audit.test_injection {
        warnings.push(
            "SSRF probe safety warning: only run with explicit authorization from the target program."
                .to_string(),
        );
        probe_ssrf(
            schema,
            url,
            &client,
            extra_headers,
            rate_limit_ms,
            config,
            passive_findings,
            &mut confirmed,
            &mut unconfirmed,
        )?;
    }

    Ok(AuditReport {
        source: url.to_string(),
        passive_total_findings: passive_findings.len(),
        confirmed,
        unconfirmed,
        warnings,
    })
}

pub fn print_audit_text_report(report: &AuditReport, max_affected: usize, verbose: bool) {
    println!();
    println!("{}", "═".repeat(70).bright_black());
    println!(
        "  {}  {}",
        "GraphQL Security Analyzer".bold().white(),
        "active audit report".bright_black()
    );
    println!("{}", "═".repeat(70).bright_black());
    println!("  Source : {}", report.source.bright_white());
    println!(
        "  Passive findings used as candidates: {}",
        report.passive_total_findings
    );
    println!();

    if !report.warnings.is_empty() {
        println!(
            "{}",
            "  ── Warnings ─────────────────────────────────────────".bright_black()
        );
        for w in &report.warnings {
            println!("  {} {}", "!".yellow().bold(), w.yellow());
        }
        println!();
    }

    println!(
        "{}",
        "  ── Confirmed Findings ───────────────────────────────".bright_black()
    );
    if report.confirmed.is_empty() {
        println!("  {} No confirmed active findings.", "✓".green().bold());
    } else {
        for f in &report.confirmed {
            println!(
                "  [{}] {} {}",
                severity_label(&f.severity),
                f.id.bright_black(),
                f.title.bold()
            );
            println!("      {}", f.description.bright_white());
            print_limited_affected_text(&f.affected, max_affected);
            if verbose {
                if let Some(poc) = &f.poc {
                    println!("      {}", "PoC:".bright_black());
                    for line in poc.lines() {
                        println!("      {}", line.bright_white());
                    }
                }
            }
        }
    }
    println!();

    println!(
        "{}",
        "  ── Unconfirmed / Inconclusive ───────────────────────".bright_black()
    );
    if report.unconfirmed.is_empty() {
        println!("  {} No unconfirmed probe outcomes.", "✓".green().bold());
    } else {
        for f in &report.unconfirmed {
            println!(
                "  [{}] {} {}",
                severity_label(&f.severity),
                f.id.bright_black(),
                f.title.bold()
            );
            println!("      {}", f.description.bright_white());
            print_limited_affected_text(&f.affected, max_affected);
        }
    }
    println!();
}

pub fn print_audit_json_report(report: &AuditReport) {
    let output = serde_json::json!({
        "source": report.source,
        "passive_total_findings": report.passive_total_findings,
        "confirmed_total": report.confirmed.len(),
        "unconfirmed_total": report.unconfirmed.len(),
        "warnings": report.warnings,
        "confirmed": report.confirmed,
        "unconfirmed": report.unconfirmed,
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn print_audit_markdown_report(report: &AuditReport, max_affected: usize) {
    println!("# GraphQL Active Audit Report\n");
    println!("- Source: {}", report.source);
    println!("- Passive candidate findings: {}", report.passive_total_findings);
    println!("- Confirmed: {}", report.confirmed.len());
    println!("- Unconfirmed: {}\n", report.unconfirmed.len());

    if !report.warnings.is_empty() {
        println!("## Warnings\n");
        for w in &report.warnings {
            println!("- {}", w);
        }
        println!();
    }

    println!("## Confirmed Findings\n");
    if report.confirmed.is_empty() {
        println!("No confirmed active findings.\n");
    } else {
        for f in &report.confirmed {
            println!("### {} {}", f.id, f.title);
            println!();
            println!("- Severity: {}", f.severity);
            println!("- Confidence: CONFIRMED");
            println!();
            println!("{}", f.description);
            println!();
            if !f.affected.is_empty() {
                println!("#### Affected\n");
                print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
            if let Some(poc) = markdown_poc_for_audit_finding(f) {
                println!("#### PoC\n");
                println!("```graphql");
                println!("{}", poc);
                println!("```\n");
            } else if let Some(poc) = &f.poc {
                println!("#### PoC\n");
                println!("```bash");
                println!("{}", poc);
                println!("```\n");
            }
            println!("#### Remediation\n");
            println!("{}\n", f.remediation);
        }
    }

    println!("## Unconfirmed Findings\n");
    if report.unconfirmed.is_empty() {
        println!("No unconfirmed probe outcomes.\n");
    } else {
        for f in &report.unconfirmed {
            println!("### {} {}", f.id, f.title);
            println!();
            println!("- Severity: {}", f.severity);
            println!("- Confidence: POSSIBLE");
            println!();
            println!("{}", f.description);
            println!();
            if !f.affected.is_empty() {
                println!("#### Affected\n");
                print_limited_affected_markdown(&f.affected, max_affected);
                println!();
            }
            println!("#### Remediation\n");
            println!("{}\n", f.remediation);
        }
    }
}

fn markdown_poc_for_audit_finding(f: &AuditFinding) -> Option<String> {
    if f.id != "AUD-002" {
        return None;
    }

    let first = f.affected.first()?;
    let dot = first.find('.')?;
    let open = first.find('(')?;
    let close = first.find(')')?;
    if close <= open {
        return None;
    }

    let root = &first[..dot];
    let operation = &first[dot + 1..open];
    let arg = &first[open + 1..close];
    let keyword = if root == "Mutation" { "mutation" } else { "query" };
    Some(format!(
        "# Probe: IDOR on {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    __typename\n  }}\n}}",
        root, operation, keyword, operation, arg
    ))
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

fn build_client(timeout_secs: u64) -> Result<Client, String> {
    Client::builder()
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

fn parse_header_kv(value: &str) -> Option<(String, String)> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("").trim();
    let val = parts.next().unwrap_or("").trim();
    if key.is_empty() {
        None
    } else {
        Some((key.to_string(), val.to_string()))
    }
}

fn effective_headers(
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

fn post_graphql(
    client: &Client,
    url: &str,
    headers: &[(String, String)],
    query: &str,
    rate_limit_ms: u64,
) -> Result<ProbeResponse, String> {
    if rate_limit_ms > 0 {
        thread::sleep(Duration::from_millis(rate_limit_ms));
    }

    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "GQL-Analyzer/1.0 (Active-Audit-Probe)");

    for (k, v) in headers {
        req = req.header(k, v);
    }

    let body = serde_json::json!({ "query": query });
    let started = Instant::now();
    let resp = req.json(&body).send().map_err(|e| e.to_string())?;
    let elapsed_ms = started.elapsed().as_millis();
    let status = resp.status().as_u16();
    let raw_text = resp.text().unwrap_or_default();

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

fn extract_typename(data: &Option<Value>) -> Option<String> {
    data.as_ref()
        .and_then(|d| d.get("__typename"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn is_auth_error(message: &str) -> bool {
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

fn is_validation_error(message: &str) -> bool {
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

fn extract_verbose_error_hint(message: &str) -> Option<String> {
    let normalized = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }

    let lower = normalized.to_lowercase();
    let looks_verbose = lower.contains("did you mean")
        || lower.contains("cannot query field")
        || lower.contains("unknown argument")
        || lower.contains("did you mean")
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

fn has_required_args(field: &GqlField) -> bool {
    field
        .args
        .as_ref()
        .map(|args| {
            args.iter().any(|a| {
                a.arg_type
                    .as_ref()
                    .and_then(|t| t.kind.as_deref())
                    == Some("NON_NULL")
            })
        })
        .unwrap_or(false)
}

fn typo_variant(name: &str) -> String {
    if name.ends_with('s') && name.len() > 1 {
        name[..name.len() - 1].to_string()
    } else {
        format!("{}s", name)
    }
}

fn probe_verbose_error_disclosure(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let binding = fields_for_type(schema, query_name);
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
    )?;

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

fn field_non_null_data(data: &Option<Value>, field_name: &str) -> Option<Value> {
    data.as_ref()
        .and_then(|d| d.get(field_name))
        .filter(|v| !v.is_null())
        .cloned()
}

fn field_kind(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let field_type_name = field.field_type.as_ref().and_then(unwrap_type_name)?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(field_type_name.as_str()))
        .and_then(|t| t.kind.clone())
}

fn field_type_name(schema: &GqlSchema, field: &GqlField) -> Option<String> {
    let name = field.field_type.as_ref().and_then(unwrap_type_name)?;
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name.as_str()))
        .and_then(|t| t.name.clone())
}

fn base_selection(schema: &GqlSchema, field: &GqlField) -> String {
    match field_kind(schema, field).as_deref() {
        Some("OBJECT") | Some("INTERFACE") | Some("UNION") => "{ __typename }".to_string(),
        _ => String::new(),
    }
}

fn idor_selection(schema: &GqlSchema, field: &GqlField) -> String {
    let type_name = match field_type_name(schema, field) {
        Some(n) => n,
        None => return base_selection(schema, field),
    };

    let fields = fields_for_type(schema, Some(type_name.as_str()));
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

fn default_literal(type_name: Option<String>) -> String {
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

fn build_operation_query(
    schema: &GqlSchema,
    op_keyword: &str,
    field: &GqlField,
    arg_overrides: &HashMap<String, String>,
    use_idor_selection: bool,
) -> String {
    let mut args_rendered: Vec<String> = Vec::new();
    if let Some(args) = &field.args {
        for arg in args {
            let value = arg_overrides
                .get(&arg.name)
                .cloned()
                .unwrap_or_else(|| default_literal(arg.arg_type.as_ref().and_then(unwrap_type_name)));
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
        op_keyword,
        field.name,
        args_block,
        selection
    )
}

fn probe_unauth_access(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
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
    for f in fields_for_type(schema, query_name) {
        targets.push(("query", "Query", f));
    }
    for f in fields_for_type(schema, mutation_name) {
        targets.push(("mutation", "Mutation", f));
    }

    let headers = effective_headers(extra_headers, None, false);
    for (op, root, field) in targets {
        if has_required_args(field) {
            skipped_required_args += 1;
            continue;
        }

        attempted += 1;
        let query = build_operation_query(schema, op, field, &HashMap::new(), false);
        let resp = post_graphql(client, url, &headers, &query, rate_limit_ms)?;
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

    if !confirmed_access.is_empty() {
        // COPILOT: Build a ready-to-use curl PoC for confirmed unauthenticated access.
        let poc = confirmed_access.first().map(|label| {
            let field = label.split('.').nth(1).unwrap_or("fieldName");
            format!(
                "curl -X POST {} \\\n+  -H 'Content-Type: application/json' \\\n+  -d '{{\"query\":\"{{ {} {{ id }} }}\"}}'",
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

fn parse_candidate(label: &str) -> Option<(String, String, String)> {
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

fn find_root_field<'a>(schema: &'a GqlSchema, root: &str, field_name: &str) -> Option<&'a GqlField> {
    let type_name = match root {
        "Query" => schema.query_type.as_ref().map(|q| q.name.as_str()),
        "Mutation" => schema.mutation_type.as_ref().map(|m| m.name.as_str()),
        _ => None,
    };

    fields_for_type(schema, type_name)
        .into_iter()
        .find(|f| f.name == field_name)
}

fn probe_idor(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
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

    let headers = effective_headers(extra_headers, Some(config.session.auth_header.as_str()), true);
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &idor.affected {
        let Some((root, field_name, arg_name)) = parse_candidate(candidate) else {
            continue;
        };
        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };

        let op = if root == "Mutation" { "mutation" } else { "query" };

        let mut baseline_payload: Option<String> = None;
        for owned in &config.session.owned_ids {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), format!("\"{}\"", owned));
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms)?;
            if let Some(data) = field_non_null_data(&resp.data, &field.name) {
                baseline_payload = Some(data.to_string());
                break;
            }
        }

        let Some(baseline) = baseline_payload else {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
            continue;
        };

        let mutated_values = vec![
            "\"1\"".to_string(),
            "\"2\"".to_string(),
            "\"3\"".to_string(),
        ];

        let mut candidate_confirmed = false;
        for mutated in mutated_values {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), mutated);
            let query = build_operation_query(schema, op, field, &overrides, true);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms)?;

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
        // COPILOT: Generate GraphQL PoC for a confirmed IDOR candidate.
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

fn probe_ssrf(
    schema: &GqlSchema,
    url: &str,
    client: &Client,
    extra_headers: &[String],
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
    confirmed: &mut Vec<AuditFinding>,
    unconfirmed: &mut Vec<AuditFinding>,
) -> Result<(), String> {
    let ssrf_finding = passive_findings.iter().find(|f| f.id == "GQL-014");
    let Some(ssrf) = ssrf_finding else {
        return Ok(());
    };

    let headers = effective_headers(extra_headers, Some(config.session.auth_header.as_str()), true);
    let mut confirmed_labels: Vec<String> = Vec::new();
    let mut inconclusive_labels: Vec<String> = Vec::new();

    for candidate in &ssrf.affected {
        let Some((root, field_name, arg_name)) = parse_candidate(candidate) else {
            continue;
        };
        let Some(field) = find_root_field(schema, root.as_str(), field_name.as_str()) else {
            continue;
        };
        let op = if root == "Mutation" { "mutation" } else { "query" };

        let mut baseline_overrides = HashMap::new();
        baseline_overrides.insert(arg_name.clone(), "\"https://example.com/\"".to_string());
        let baseline_query = build_operation_query(schema, op, field, &baseline_overrides, false);
        let baseline_resp = post_graphql(client, url, &headers, &baseline_query, rate_limit_ms)?;
        let baseline_ms = baseline_resp.elapsed_ms;

        let payloads = [
            "\"http://169.254.169.254/latest/meta-data/\"",
            "\"http://127.0.0.1:80\"",
        ];

        let mut suspicious = false;
        for payload in payloads {
            let mut overrides = HashMap::new();
            overrides.insert(arg_name.clone(), payload.to_string());
            let query = build_operation_query(schema, op, field, &overrides, false);
            let resp = post_graphql(client, url, &headers, &query, rate_limit_ms)?;

            let delayed = resp.elapsed_ms > baseline_ms + 1500;
            let aws_keywords = ["meta-data", "instance-id", "ami-id", "security-credentials"]
                .iter()
                .any(|k| resp.raw_text.to_lowercase().contains(k));

            if delayed || aws_keywords {
                suspicious = true;
                break;
            }
        }

        if suspicious {
            confirmed_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        } else {
            inconclusive_labels.push(format!("{}.{}({})", root, field_name, arg_name));
        }
    }

    if !confirmed_labels.is_empty() {
        confirmed.push(AuditFinding {
            id: "AUD-003",
            severity: Severity::High,
            title: "SSRF Behavior Suspected/Confirmed",
            description: format!(
                "{} operation(s) showed timing/content indicators consistent with SSRF payload handling.",
                confirmed_labels.len()
            ),
            affected: confirmed_labels,
            remediation: "Block internal destinations (loopback, link-local, RFC1918), enforce URL allow-lists, and isolate outbound fetch logic.",
            evidence: "confirmed",
            poc: None,
        });
    }

    if !inconclusive_labels.is_empty() {
        unconfirmed.push(AuditFinding {
            id: "AUD-003",
            severity: Severity::Medium,
            title: "SSRF Probe Inconclusive",
            description: format!(
                "{} SSRF candidate(s) did not show clear SSRF indicators under default payload probes.",
                inconclusive_labels.len()
            ),
            affected: inconclusive_labels,
            remediation: "Try operation-specific payload shaping and monitor egress logs for outbound callbacks.",
            evidence: "inconclusive",
            poc: None,
        });
    }

    Ok(())
}
