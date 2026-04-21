# introspectre

A GraphQL security analyzer that identifies vulnerabilities in GraphQL APIs through schema introspection and active probing.

## Features

- **Passive Analysis**: Examines GraphQL schema to identify security issues including:
  - Exposed sensitive fields (email, password, ssn, etc.)
  - Missing authentication directives
  - Unvalidated user input in mutation arguments
  - Deprecated and removed fields
  - Circular type references
  - Large attack surfaces
  - Unused types and fields

- **Active Auditing**: Performs live endpoint testing:
  - Unauthenticated access detection
  - Insecure Direct Object References (IDOR)
  - Query injection vulnerabilities
  - Authentication boundary mapping
  - PoC generation for confirmed findings

- **Multi-Format Reporting**: Text, JSON, Markdown, and HTML output formats

- **Configurable Analysis**: TOML-based pattern and probe configuration

## Installation

### Requirements
- Rust 1.56 or later (install from [rustup.rs](https://rustup.rs/))

The build and install workflow below applies to both Linux and Windows.

### Build from Source (Linux and Windows)

```bash
git clone https://github.com/m3m0rydmp/graphql-tester.git
cd graphql-tester
cargo build --release
```

Compiled binary paths:
- Linux: `target/release/introspectre`
- Windows: `target/release/introspectre.exe`

### Install Binary (Linux and Windows)

```bash
cargo install --path .
```

This installs the binary to your `~/.cargo/bin/` directory. Ensure this directory is in your `$PATH`.

On Windows, the command is the same. Rust installs binaries to `%USERPROFILE%\\.cargo\\bin`; ensure that directory is in your `PATH`.

### Windows Quick Start (PowerShell)

```powershell
git clone https://github.com/m3m0rydmp/graphql-tester.git
cd graphql-tester
cargo install --path .
introspectre --help
```

## Quick Start

### Analyze a Live Endpoint

```bash
introspectre scan https://api.example.com/graphql
```

### Analyze with Authentication

```bash
introspectre scan https://api.example.com/graphql --token "Bearer YOUR_TOKEN"
```

### Run Active Audit

```bash
introspectre audit https://api.example.com/graphql
```

### Analyze from JSON File

```bash
introspectre file schema.json
```

## Usage

### Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--config` | PATH | None | Path to TOML configuration file |
| `--format` | text\|json\|markdown | text | Output format |
| `--max-affected` | NUMBER | 30 | Max affected entries shown per finding (0 = no limit) |
| `--min-severity` | low\|medium\|high | None | Only show findings at or above this level |
| `--html-report` | BOOL | false | Generate HTML report |
| `--html-path` | PATH | introspectre-report.html | HTML report output location |
| `--verbose` | BOOL | false | Show PoC blocks in text output |
| `--token` | STRING | None | Bearer token for authenticated requests |

### Scan Subcommand

Fetch schema via introspection and analyze for vulnerabilities.

```bash
introspectre scan <URL> [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--header` | KEY=VALUE | None | Extra request headers (repeatable) |
| `--timeout` | SECONDS | 15 | HTTP request timeout |
| `--static-only` | BOOL | true | Skip active exploit probes |
| `--rate-limit-ms` | MILLISECONDS | 750 | Delay before issuing requests |
| `--discover-auth` | BOOL | true | Probe for auth protection per field |
| `--probe-first` | BOOL | true | Run endpoint probe before introspection |
| `--probe-only` | BOOL | false | Only run endpoint probes (no analysis) |

### Audit Subcommand

Run active security probes against a live endpoint using schema-derived candidates.

```bash
introspectre audit <URL> [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--header` | KEY=VALUE | None | Extra request headers (repeatable) |
| `--timeout` | SECONDS | 15 | Timeout per request |
| `--rate-limit-ms` | MILLISECONDS | 750 | Delay before issuing requests |

### File Subcommand

Analyze a previously saved introspection JSON file.

```bash
introspectre file <PATH>
```

## Examples

### Scan with custom headers

```bash
introspectre scan https://api.example.com/graphql \
  --header "Authorization=Bearer token123" \
  --header "X-API-Key=secret"
```

### Generate JSON report

```bash
introspectre scan https://api.example.com/graphql --format json > report.json
```

### Create HTML report

```bash
introspectre scan https://api.example.com/graphql \
  --html-report \
  --html-path security-report.html
```

### Run audit with verbose PoC output

```bash
introspectre audit https://api.example.com/graphql --verbose
```

### Filter by severity level

```bash
introspectre scan https://api.example.com/graphql --min-severity high
```

## Configuration

The `config.toml` file will customize you analysis patterns. Either modify the existing file, or create your own:

```toml
# Sensitive field patterns
[patterns.sensitive_fields]
fields = ["password", "ssn", "credit_card", "api_key"]

# SSRF argument patterns
[patterns.ssrf_args]
arguments = ["url", "uri", "endpoint"]

# IDOR mutation patterns
[patterns.idor_mutations]
mutations = ["update", "delete", "assign"]

# Query/field patterns to avoid
[patterns.debug_types]
types = ["Debug", "Internal", "Dev"]

# Session and audit settings
[session]
auth_header = "Authorization"
owned_ids = ["userId", "accountId"]

[audit]
test_unauth = true
test_idor = true
test_injection = true
```

## Output Examples

### Text Output (default)

```
Finding: GQL-003 — Exposed Sensitive Fields
Severity: HIGH | Confidence: CONFIRMED
Found 2 sensitive fields in public queries:
  • User.password (String!)
  • Account.ssn (String)

Remediation: Implement field-level authorization directives
```

### JSON Output

```json
{
  "findings": [
    {
      "id": "GQL-003",
      "title": "Exposed Sensitive Fields",
      "severity": "HIGH",
      "confidence": "CONFIRMED",
      "affected": ["User.password", "Account.ssn"],
      "poc": null
    }
  ]
}
```

## Development

```bash
# Build debug binary
cargo build

# Run tests
cargo test

# Check code without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

## Contributing

Bug reports and feature requests are welcome. Please open an issue on the repository.

## License

MIT License. See LICENSE file for details.
