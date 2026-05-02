# introspectre

`introspectre` is a powerful security analysis and auditing tool for GraphQL schemas. It combines static schema analysis with active probing to identify vulnerabilities like IDOR, Mass Assignment, Sensitive Data Exposure, and Denial of Service (DoS) risks.

## Commands

```text
Usage: introspectre [OPTIONS] <COMMAND>

Commands:
  scan   Fetch schema via live introspection query and perform static analysis
  audit  Active probing audit flow using schema-derived candidates
  file   Analyze a schema already saved to a JSON file
  help   Print this message or the help of the given subcommand(s)
```

### Scan Options (`introspectre scan --help`)
*   `--discover-auth`: Discover which root fields are protected vs public using unauthenticated knock probes.
*   `--static-only`: Avoid active exploit payload probes (recommended for initial assessment).
*   `--probe-first`: Run a lightweight GraphQL endpoint probe before introspection.
*   `--rate-limit-ms <MS>`: Client-side delay before issuing requests (default: 750ms).

### Audit Options (`introspectre audit --help`)
*   `--idor-payloads <IDS>`: Custom candidate IDs for IDOR probing.
*   `--rate-limit-ms <MS>`: Important for avoiding WAF triggers during active probing.

## Use Cases

### 🟢 Safe / Passive Analysis
Perfect for quick assessments or CI/CD pipelines where you don't want to trigger WAFs or affect server state.
```bash
# Analyze a schema file locally without making any network requests
introspectre file schema.json

# Perform introspection and static analysis on a live endpoint (read-only)
introspectre scan https://api.example.com/graphql --static-only
```

### 🟡 Informed / Active Discovery
Probes the endpoint to understand authentication guards and endpoint behavior.
```bash
# Discover which fields require authentication and check for basic DoS vectors
introspectre scan https://api.example.com/graphql --discover-auth --probe-first
```

### 🔴 Destructive / Active Auditing (Use with Caution)
Performs active probing using generated payloads. This may trigger alerts, modify data (if mutations are probed), or cause high load.
```bash
# Actively probe for IDOR, SSRF, and complexity-based DoS vulnerabilities
introspectre audit https://api.example.com/graphql --rate-limit-ms 1000 --idor-payloads "1,100,2024"
```

## Configuration
Use a `config.toml` to customize sensitivity patterns and wordlists:
```bash
introspectre --config custom_config.toml scan <URL>
```

For more technical details, see [ARCHITECTURE.md](./ARCHITECTURE.md).
