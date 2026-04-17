mod analysis;
mod cli;
mod io_ops;
mod report;
mod types;

use clap::Parser;
use colored::Colorize;

use analysis::analyze;
use cli::{Cli, Commands, OutputFormat};
use io_ops::{
    discover_auth_requirements, fetch_introspection, load_schema_from_file, probe_graphql_endpoint,
};
use report::{print_json_report, print_text_report, write_html_report};
use types::ReportMeta;

fn main() {
    let cli = Cli::parse();

    let mut offline = false;
    let mut static_only = true;
    let mut auth_discovery_performed = false;
    let mut auth_discovery = None;

    let (schema, source) = match &cli.command {
        Commands::Scan {
            url,
            headers,
            timeout,
            static_only: scan_static_only,
            rate_limit_ms,
            discover_auth,
            probe_first,
            probe_only,
        } => {
            static_only = *scan_static_only;

            let mut probe_result = None;
            if *probe_first || *probe_only {
                if cli.format == OutputFormat::Text {
                    eprintln!(
                        "  {} Probing endpoint behavior with minimal __typename query...",
                        "→".blue().bold(),
                    );
                }
                match probe_graphql_endpoint(
                    url,
                    headers,
                    *timeout,
                    *rate_limit_ms,
                    cli.token.as_deref(),
                ) {
                    Ok(r) => {
                        if cli.format == OutputFormat::Text {
                            let marker = if r.graphql_confirmed { "✓".green().bold() } else { "!".yellow().bold() };
                            eprintln!("  {} {} (HTTP {})", marker, r.summary, r.http_status);
                        }
                        probe_result = Some(r);
                    }
                    Err(e) => {
                        if cli.format == OutputFormat::Text {
                            eprintln!("{} {}", "  ! Probe failed:".yellow().bold(), e);
                        }
                    }
                }
            }

            if *probe_only {
                if let Some(r) = probe_result {
                    if r.graphql_confirmed {
                        std::process::exit(0);
                    }
                    std::process::exit(2);
                }
                std::process::exit(2);
            }

            if cli.format == OutputFormat::Text {
                eprintln!(
                    "  {} Fetching introspection from {}...",
                    "→".blue().bold(),
                    url.bright_white()
                );
                eprintln!(
                    "  {} Strategy: static-first (Look, Don't Touch).",
                    "✓".green().bold(),
                );
            }

            let schema = match fetch_introspection(
                url,
                headers,
                *timeout,
                *rate_limit_ms,
                cli.token.as_deref(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    if let Some(probe) = &probe_result {
                        if probe.graphql_confirmed {
                            eprintln!(
                                "{} {}",
                                "  ! Note:".yellow().bold(),
                                "GraphQL appears to be running, but introspection could not be retrieved."
                            );
                            if probe.auth_likely_required {
                                eprintln!(
                                    "{} {}",
                                    "  ! Hint:".yellow().bold(),
                                    "Endpoint may be auth-gated. Retry with --token <JWT>."
                                );
                            }
                            eprintln!(
                                "{} {}",
                                "  ! Hint:".yellow().bold(),
                                "If this is expected, use `file <schema.json>` mode for offline static analysis."
                            );
                        } else if probe.content_type_or_json_issue {
                            eprintln!(
                                "{} {}",
                                "  ! Hint:".yellow().bold(),
                                "Probe received non-GraphQL JSON behavior. Re-check endpoint path and required headers."
                            );
                        }
                    }
                    eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if *discover_auth {
                auth_discovery_performed = true;
                if cli.format == OutputFormat::Text {
                    eprintln!(
                        "  {} Discovering auth guards with unauthenticated knock probes...",
                        "→".blue().bold()
                    );
                }
                match discover_auth_requirements(&schema, url, headers, *timeout, *rate_limit_ms) {
                    Ok(r) => auth_discovery = Some(r),
                    Err(e) => {
                        if cli.format == OutputFormat::Text {
                            eprintln!(
                                "{} {}",
                                "  ! Auth discovery skipped:".yellow().bold(),
                                e
                            );
                        }
                    }
                }
            }

            (schema, url.clone())
        }
        Commands::File { path } => {
            offline = true;
            let src = path.display().to_string();
            if cli.format == OutputFormat::Text {
                eprintln!(
                    "  {} Loading schema from {}...",
                    "→".blue().bold(),
                    src.bright_white()
                );
            }
            match load_schema_from_file(path) {
                Ok(s) => (s, src),
                Err(e) => {
                    eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
    };

    let (mut findings, stats) = analyze(&schema);

    if let Some(min) = &cli.min_severity {
        findings.retain(|f| &f.severity >= min);
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));

    let meta = ReportMeta {
        source,
        offline,
        static_only,
        auth_discovery_performed,
        auth_discovery,
    };

    match cli.format {
        OutputFormat::Text => print_text_report(&stats, &findings, &meta),
        OutputFormat::Json => print_json_report(&stats, &findings, &meta),
    }

    if cli.html_report {
        if let Err(e) = write_html_report(&cli.html_path, &stats, &findings, &meta) {
            eprintln!("{} {}", "  ✗ Error:".red().bold(), e);
            std::process::exit(1);
        }
        if cli.format == OutputFormat::Text {
            eprintln!(
                "  {} HTML report written to {}",
                "✓".green().bold(),
                cli.html_path.display().to_string().bright_white()
            );
        }
    }

    if findings
        .iter()
        .any(|f| f.severity == crate::types::Severity::High)
    {
        std::process::exit(1);
    }
}
