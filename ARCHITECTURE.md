# introspectre: Technical Architecture

This document provides an in-depth look at the internal design, performance optimizations, and security heuristics used by `introspectre`.

## 1. Data Collection & Introspection

The tool relies on retrieving the schema directly from the GraphQL server. This is achieved through the **Introspection Engine**.

### Introspection Query
We use a robust query that retrieves types, fields, arguments, enums, unions, and directives. To maintain compatibility with older or strictly configured servers, we use a fragmented query structure:

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
      # ... other schema details
    }
  }
}
```

## 2. Performance Optimizations ($O(1)$ Lookups)

Scanning large schemas (often containing thousands of types) can be slow if implemented with naive $O(n^2)$ loops. `introspectre` optimizes this by building an in-memory index of the schema immediately after retrieval.

### Indexing Strategy
We use `HashMap` collections to allow constant-time resolution of types during analysis:

```rust
// In src/analysis/information_exposure.rs
let type_map: HashMap<&str, &GqlType> = schema.types.iter()
    .filter_map(|t| t.name.as_deref().map(|n| (n, t)))
    .collect();
```

This map allows the tool to instantly resolve `INPUT_OBJECT` references during Mass Assignment checks without re-scanning the entire type list for every mutation.

## 3. Core Security Heuristics

### Mass Assignment Detection (`GQL-017`)
This heuristic identifies mutations that accept complex objects where internal fields match sensitive keywords.

**Detection Logic:**
1. Identify all `Mutation` fields.
2. Resolve the `INPUT_OBJECT` type of each argument.
3. Recursively check if that input type contains fields like `isAdmin`, `role`, or `status`.

```rust
for f in &mutation_fields {
    for arg in args {
        if let Some(input_type) = type_map.get(input_type_name) {
            if let Some(input_fields) = &input_type.input_fields {
                for input_field in input_fields {
                    if matches_pattern(&input_field.name, &patterns.sensitive_fields.names) {
                        // Flag potential Mass Assignment
                    }
                }
            }
        }
    }
}
```

### Denial of Service (DoS) Analysis
We detect structural weaknesses that can be exploited for "Query Complexity" attacks.

*   **Circular References (`GQL-003`)**: Detected by building a graph of type relationships and looking for cycles (e.g., `User` -> `Posts` -> `User`).
*   **List Inflation (`GQL-DOS-001`)**: Identifies fields that return lists of objects which *also* contain list-returning fields.

### IDOR / BOLA Discovery (`GQL-013`)
The tool leverages an enriched prefix list (from HackerOne data) to identify every field that accepts an identifier.

```rust
let idor_arg_matches = |arg_name: &str| {
    let lower = arg_name.to_lowercase();
    matches!(lower.as_str(), "id" | "uuid" | "userid")
        || lower.ends_with("id")
        || lower.ends_with("_id")
};
```

## 4. Active Probing Lifecycle

When running the `audit` command, the tool enters an active discovery phase:

1.  **Knock Probe**: A single query for `__typename` to verify the endpoint and check for basic WAF presence.
2.  **Auth Discovery**: Sequentially (but with throttled concurrency) requests every root field without a token. It parses the `errors` array for common authorization failure patterns.
3.  **Complexity Probe**: Issues multiple aliased queries to see if the server returns cost/complexity headers or JSON extensions, which reveals internal throttling limits.

## 5. Technology Stack
*   **Rust**: For memory safety, speed, and concurrency.
*   **Tokio**: Asynchronous runtime for parallel network probing.
*   **Reqwest**: HTTP client with support for custom headers and timeouts.
*   **Clap**: Robust CLI argument parsing.
