use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::types::Severity;

#[derive(Parser)]
#[command(
    name = "introspectre",
    about = "GraphQL Security Analyzer — introspection-based vulnerability scanner",
    version,
    long_about = "Analyzes GraphQL schemas (from a live endpoint or a JSON file) and reports security issues: exposed sensitive fields, missing auth directives, circular type references, large attack surfaces, deprecated fields, and more."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to TOML config file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Merge additional words from file into patterns: <type>=<path> (repeatable)
    #[arg(long, global = true, value_name = "TYPE=PATH")]
    pub wordlist: Vec<String>,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text", global = true)]
    pub format: OutputFormat,

    /// Max affected entries shown per finding in text/markdown output (0 = no limit)
    #[arg(long, default_value_t = 30, global = true)]
    pub max_affected: usize,

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
    #[arg(long, default_value = "introspectre-report.html", global = true)]
    pub html_path: PathBuf,

    /// Show verbose details in text output (includes PoC blocks when available)
    #[arg(long, default_value_t = false, global = true)]
    pub verbose: bool,
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

    /// Active probing audit flow using schema-derived candidates
    Audit {
        /// GraphQL endpoint URL
        url: String,

        /// Extra request headers as key=value pairs (repeatable)
        /// Example: --header "Authorization=Bearer token"
        #[arg(short = 'H', long = "header", value_name = "KEY=VALUE")]
        headers: Vec<String>,

        /// Timeout in seconds for each HTTP request
        #[arg(long, default_value_t = 15)]
        timeout: u64,

        /// Client-side delay before issuing requests (milliseconds)
        #[arg(long, default_value_t = 750)]
        rate_limit_ms: u64,

        /// Enable batching of safe probes (verbose disclosure, unauthenticated access) into single requests
        #[arg(long, default_value_t = false)]
        batch_probes: bool,

        /// Maximum number of operations per batched request (only when --batch-probes is enabled)
        #[arg(long, default_value_t = 5)]
        batch_size: u32,

        /// Custom candidate IDs for IDOR probing (comma-separated or repeatable)
        #[arg(long, value_delimiter = ',')]
        idor_payloads: Vec<String>,
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
    Markdown,
}
