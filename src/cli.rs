use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::types::Severity;

#[derive(Parser)]
#[command(
    name = "gql-analyzer",
    about = "GraphQL Security Analyzer — introspection-based vulnerability scanner",
    version,
    long_about = "Analyzes GraphQL schemas (from a live endpoint or a JSON file) and reports security issues: exposed sensitive fields, missing auth directives, circular type references, large attack surfaces, deprecated fields, and more."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text", global = true)]
    pub format: OutputFormat,

    /// Show only findings at or above this level: low | medium | high
    #[arg(long, global = true)]
    pub min_severity: Option<Severity>,

    /// Optional bearer token used for authenticated introspection requests
    #[arg(short = 't', long, global = true)]
    pub token: Option<String>,

    /// Generate an HTML report file in addition to console output
    #[arg(long, default_value_t = false, global = true)]
    pub html_report: bool,

    /// HTML report output path
    #[arg(long, default_value = "gql-analyzer-report.html", global = true)]
    pub html_path: PathBuf,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Fetch schema via live introspection query
    Scan {
        /// GraphQL endpoint URL
        url: String,

        /// Extra request headers as key=value pairs (repeatable)
        /// Example: --header "Authorization=Bearer token"
        #[arg(short = 'H', long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,

        /// Timeout in seconds for the HTTP request
        #[arg(long, default_value_t = 15)]
        timeout: u64,

        /// Safety recommendation mode: avoid active exploit payload probes
        #[arg(long, default_value_t = true)]
        static_only: bool,

        /// Client-side delay before issuing requests (milliseconds)
        #[arg(long, default_value_t = 750)]
        rate_limit_ms: u64,

        /// Discover which root fields are protected vs public using unauthenticated knock probes
        #[arg(long, default_value_t = true)]
        discover_auth: bool,

        /// Run a lightweight GraphQL endpoint probe before introspection
        #[arg(long, default_value_t = true)]
        probe_first: bool,

        /// Only run endpoint probing (no introspection or vulnerability analysis)
        #[arg(long, default_value_t = false)]
        probe_only: bool,
    },

    /// Analyze a schema already saved to a JSON file
    File {
        /// Path to the introspection JSON file
        path: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}
