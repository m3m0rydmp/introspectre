# Introspectre: Technical Architecture

This document provides a technical overview of the internal design, performance optimizations, and security heuristics employed by Introspectre.

## 1. Data Collection and Introspection

Introspectre retrieves the GraphQL schema directly from the target server using the Introspection Engine.

### Introspection Query
The tool utilizes a comprehensive query to extract types, fields, arguments, enums, unions, and directives. To ensure compatibility with legacy or strictly configured servers, a fragmented query structure is implemented:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name isDeprecated deprecationReason
        type { ...TypeRef }
        args { name type { ...TypeRef } }
      }
      inputFields { name type { ...TypeRef } }
      # Additional schema details
    }
  }
}
```

## 2. Performance Optimizations

Scanning large schemas containing thousands of types requires efficient data structures. Introspectre optimizes this process by constructing an in-memory index immediately after schema retrieval, avoiding inefficient linear searches.

### Indexing Strategy
The tool utilizes hash maps to facilitate constant-time resolution of types during analysis:

```rust
// Implementation example in src/analysis/information_exposure.rs
let type_map: HashMap<&str, &GqlType> = schema.types.iter()
    .filter_map(|t| t.name.as_deref().map(|n| (n, t)))
    .collect();
```

This indexing strategy allows for instantaneous resolution of `INPUT_OBJECT` references during Mass Assignment checks, eliminating the need to re-scan the type list for every mutation.

## 3. Security Heuristics

### Mass Assignment Detection (`GQL-017`)
This heuristic identifies mutations that accept complex objects containing internal fields that match sensitive keywords.

**Detection Methodology:**
1. Enumerate all fields within the `Mutation` root.
2. Resolve the `INPUT_OBJECT` type for each argument.
3. Recursively examine the input type for fields matching sensitive patterns (e.g., `isAdmin`, `role`, or `status`).

```rust
for f in &mutation_fields {
    for arg in args {
        if let Some(input_type) = type_map.get(input_type_name) {
            if let Some(input_fields) = &input_type.input_fields {
                for input_field in input_fields {
                    if matches_pattern(&input_field.name, &patterns.sensitive_fields.names) {
                        // Potential Mass Assignment identified
                    }
                }
            }
        }
    }
}
```

### Denial of Service (DoS) Analysis
Introspectre identifies structural weaknesses that could facilitate query complexity attacks.

*   **Circular References (`GQL-003`)**: Detected by constructing a graph of type relationships and identifying cycles (e.g., `User` -> `Posts` -> `User`).
*   **List Inflation (`GQL-DOS-001`)**: Identifies fields returning lists of objects that themselves contain list-returning fields.

### IDOR / BOLA Discovery (`GQL-013`)
The tool employs an extensive prefix list to identify fields that accept identifiers.

```rust
let idor_arg_matches = |arg_name: &str| {
    let lower = arg_name.to_lowercase();
    matches!(lower.as_str(), "id" | "uuid" | "userid")
        || lower.ends_with("id")
        || lower.ends_with("_id")
};
```

## 4. Active Probing Lifecycle

The `audit` command initiates an active discovery phase:

1.  **Endpoint Verification (Knock Probe)**: Executes a single `__typename` query to confirm endpoint availability and assess basic Web Application Firewall (WAF) behavior.
2.  **Authentication Discovery**: Issues throttled requests for root fields without credentials. The resulting error responses are analyzed for authorization failure patterns.
3.  **Complexity Probing**: Executes multiple aliased queries to determine if the server returns cost-related headers or JSON extensions, revealing internal throttling thresholds.

## 5. Technology Stack
*   **Rust**: Provides memory safety, performance, and high concurrency.
*   **Tokio**: Serving as the asynchronous runtime for parallel network operations.
*   **Reqwest**: Utilized as the HTTP client for its support of custom headers and timeouts.
*   **Clap**: Employed for robust command-line argument parsing.
