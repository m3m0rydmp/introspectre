# introspectre: Technical Architecture

This document describes the internal workings and security heuristics of `introspectre`.

## 1. Data Collection Phase

### Introspection Engine
The tool uses a standard `IntrospectionQuery` to retrieve the full schema from a target endpoint. It handles various server implementations by gracefully degrading the query if certain modern features (like `isRepeatable` on directives) are missing.

### Endpoint Probing
Before full introspection, `introspectre` can perform a "knock" probe. It sends a minimal `query { __typename }` request to:
1.  Confirm GraphQL is actually hosted at the URL.
2.  Determine if introspection is enabled or if it requires a token.
3.  Detect the underlying server technology (Apollo, Yoga, etc.) via HTTP headers.

## 2. Analysis Engine (Static)

The static analysis engine operates on the retrieved JSON schema and applies several heuristic-based modules:

### Information Exposure
*   **Sensitive Field Detection**: Uses regex and keyword matching (enriched by HackerOne data) to identify fields like `password`, `token`, `secret`, `ssn`, etc.
*   **Mass Assignment**: Specifically looks for mutations where the `INPUT_OBJECT` contains fields that match sensitive patterns (e.g., `isAdmin`, `role`).
*   **Leakage Heuristics**: Identifies types that combine user-specific data (e.g., `myProfile`) with broad organizational data, signaling potential tenant isolation issues.

### Denial of Service (DoS) Detection
*   **Recursive Structures**: Scans for circular references (A -> B -> A) and self-referencing fields.
*   **List Inflation**: Detects list-returning fields that nested additional lists, creating an exponential response size risk.
*   **Pagination Gaps**: Flags list fields that do not accept common pagination arguments (`first`, `limit`, `offset`), which can be used to scrape large datasets.

### Access Control Review
*   **Auth Directives**: Checks if mutations and sensitive fields have declarative protection (`@auth`, `@hasRole`).
*   **IDOR Candidates**: Automatically identifies every field/mutation that accepts an `ID` or `UUID` argument.

## 3. Audit Engine (Active)

The `audit` command moves beyond static analysis by issuing actual requests to the target:

### Authentication Guard Discovery
Sends a series of requests to every root query/mutation field without a token. It analyzes the HTTP status (401/403) and GraphQL error messages (e.g., "Not Authorized") to map the "Protected vs Public" boundary of the API.

### Complexity & Cost Probing
Issues a query with multiple aliased `__typename` calls. It inspects the `extensions` field in the response to see if the server returns complexity scores or cost metrics, which helps an attacker understand the cost limits of the system.

## 4. Performance Optimizations
The tool is written in Rust for high performance:
*   **O(1) Lookups**: Uses `HashMap` and `HashSet` for schema traversal, ensuring even massive schemas (10k+ fields) are analyzed in milliseconds.
*   **Asynchronous I/O**: Uses `tokio` and `reqwest` to perform network probes in parallel while respecting user-defined rate limits.
