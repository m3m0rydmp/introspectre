pub mod probes;
pub mod utils;

use crate::audit::probes::{
    probe_alias_dos, probe_batching, probe_complexity, probe_idor, probe_ssrf, probe_typename,
    probe_unauth_access, probe_verbose_error_disclosure,
};
use crate::audit::utils::build_client;
use crate::config::AppConfig;
use crate::types::{Finding, GqlSchema, Severity};
use colored::Colorize;
use serde::Serialize;

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

pub async fn run_audit(
    schema: &GqlSchema,
    url: &str,
    extra_headers: &[String],
    timeout_secs: u64,
    rate_limit_ms: u64,
    config: &AppConfig,
    passive_findings: &[Finding],
    idor_payloads: &[String],
    batch_probes: bool,
    batch_size: u32,
) -> Result<AuditReport, String> {
    let client = build_client(timeout_secs)?;
    let mut confirmed: Vec<AuditFinding> = Vec::new();
    let mut unconfirmed: Vec<AuditFinding> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if batch_probes {
        warnings.push(
            "Batch probing enabled: multiple safe probe operations will be combined into single requests."
                .to_string(),
        );
    }

    probe_typename(
        &client,
        url,
        extra_headers,
        rate_limit_ms,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;

    probe_verbose_error_disclosure(
        schema,
        url,
        &client,
        extra_headers,
        rate_limit_ms,
        batch_probes,
        batch_size,
        &mut confirmed,
        &mut unconfirmed,
    )
    .await?;

    if config.audit.test_unauth {
        probe_unauth_access(
            schema,
            url,
            &client,
            extra_headers,
            rate_limit_ms,
            batch_probes,
            batch_size,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
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
            idor_payloads,
        )
        .await?;
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
        )
        .await?;
    }

    if config.audit.test_complexity {
        probe_complexity(
            &client,
            url,
            extra_headers,
            rate_limit_ms,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
    }

    if config.audit.test_batching {
        probe_batching(
            &client,
            url,
            extra_headers,
            rate_limit_ms,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
    }

    if config.audit.test_alias_dos {
        probe_alias_dos(
            schema,
            url,
            &client,
            extra_headers,
            rate_limit_ms,
            &mut confirmed,
            &mut unconfirmed,
        )
        .await?;
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
    println!(
        "  {}  {}",
        "introspectre".bold().bright_white(),
        "active audit".bright_black()
    );
    println!(
        "  {} {}",
        "Target:".bright_black(),
        report.source.bright_white()
    );
    println!(
        "  {} {}",
        "Candidates:".bright_black(),
        report.passive_total_findings
    );
    println!();

    if !report.warnings.is_empty() {
        println!("  {}", "Warnings".bold().yellow());
        for w in &report.warnings {
            println!("  {} {}", "!".yellow().bold(), w.yellow());
        }
        println!();
    }

    println!("  {}", "Confirmed Findings".bold().white());
    if report.confirmed.is_empty() {
        println!("  {} No confirmed active findings.", "✓".green().bold());
    } else {
        for f in &report.confirmed {
            println!(
                "  {} {} {}",
                "✖".red().bold(),
                f.title.bold().white(),
                format!("[{}]", f.id).bright_black()
            );
            println!("      {}", f.description.bright_white());
            print_limited_affected_text(&f.affected, max_affected);
            if verbose {
                if let Some(poc) = &f.poc {
                    println!("      {}", "PoC:".bright_black());
                    for line in poc.lines() {
                        println!("        {}", line.bright_white());
                    }
                }
            }
            println!();
        }
    }

    println!("  {}", "Unconfirmed / Inconclusive".bold().white());
    if report.unconfirmed.is_empty() {
        println!("  {} No unconfirmed probe outcomes.", "✓".green().bold());
    } else {
        for f in &report.unconfirmed {
            println!(
                "  {} {} {}",
                "ℹ".cyan().bold(),
                f.title.bold().white(),
                format!("[{}]", f.id).bright_black()
            );
            println!("      {}", f.description.bright_white());
            print_limited_affected_text(&f.affected, max_affected);
            println!();
        }
    }
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
    println!(
        "- Passive candidate findings: {}",
        report.passive_total_findings
    );
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
            format!(
                "... and {} more (use --max-affected 0 to show all)",
                remaining
            )
            .bright_black()
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
        println!(
            "- ... and {} more (use --max-affected 0 to show all)",
            remaining
        );
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
    let keyword = if root == "Mutation" {
        "mutation"
    } else {
        "query"
    };
    Some(format!(
        "# Probe: IDOR on {}.{}\n{} {{\n  {}({}: \"VICTIM_ID\") {{\n    __typename\n  }}\n}}",
        root, operation, keyword, operation, arg
    ))
}
