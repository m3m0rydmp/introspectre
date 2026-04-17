use std::collections::HashMap;

use crate::types::{EvidenceLevel, Finding, GqlField, GqlSchema, GqlType, GqlTypeRef, SchemaStats, Severity};

const SENSITIVE_PATTERNS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "auth", "credential",
    "private", "ssn", "credit", "card", "cvv", "otp", "pin", "hash", "salt", "session",
    "cookie", "bearer", "key",
];

fn matches_sensitive(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p))
}

pub fn unwrap_type_name(t: &GqlTypeRef) -> Option<String> {
    if let Some(name) = &t.name {
        if !name.is_empty() {
            return Some(name.clone());
        }
    }
    if let Some(inner) = &t.of_type {
        return unwrap_type_name(inner);
    }
    None
}

fn user_types(schema: &GqlSchema) -> Vec<&GqlType> {
    schema
        .types
        .iter()
        .filter(|t| t.name.as_deref().map(|n| !n.starts_with("__")).unwrap_or(false))
        .collect()
}

pub fn fields_for_type<'a>(schema: &'a GqlSchema, type_name: Option<&str>) -> Vec<&'a GqlField> {
    let name = match type_name {
        Some(n) => n,
        None => return vec![],
    };
    schema
        .types
        .iter()
        .find(|t| t.name.as_deref() == Some(name))
        .and_then(|t| t.fields.as_ref())
        .map(|v| v.iter().collect())
        .unwrap_or_default()
}

pub fn analyze(schema: &GqlSchema) -> (Vec<Finding>, SchemaStats) {
    let mut findings: Vec<Finding> = Vec::new();
    let types = user_types(schema);

    let query_name = schema.query_type.as_ref().map(|t| t.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|t| t.name.as_str());
    let subscription_name = schema.subscription_type.as_ref().map(|t| t.name.as_str());

    let directives = schema.directives.as_deref().unwrap_or(&[]);

    let total_fields: usize = types
        .iter()
        .map(|t| t.fields.as_ref().map(|f| f.len()).unwrap_or(0))
        .sum();

    let deprecated_fields: usize = types
        .iter()
        .flat_map(|t| t.fields.iter().flat_map(|v| v.iter()))
        .filter(|f| f.is_deprecated.unwrap_or(false))
        .count();

    let stats = SchemaStats {
        total_types: types.len(),
        object_types: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("OBJECT"))
            .count(),
        queries: fields_for_type(schema, query_name).len(),
        mutations: fields_for_type(schema, mutation_name).len(),
        subscriptions: fields_for_type(schema, subscription_name).len(),
        enums: types.iter().filter(|t| t.kind.as_deref() == Some("ENUM")).count(),
        interfaces: types
            .iter()
            .filter(|t| t.kind.as_deref() == Some("INTERFACE"))
            .count(),
        unions: types.iter().filter(|t| t.kind.as_deref() == Some("UNION")).count(),
        total_fields,
        deprecated_fields,
    };

    let has_introspection = schema
        .types
        .iter()
        .any(|t| t.name.as_deref().map(|n| n.starts_with("__")).unwrap_or(false));
    if has_introspection {
        findings.push(Finding {
            id: "GQL-001",
            severity: Severity::High,
            title: "Introspection Enabled",
            description: "GraphQL introspection is enabled. Attackers can enumerate all types, fields, queries, and mutations — essentially a free schema map for targeting attacks.".into(),
            affected: vec!["__schema".into(), "__type".into()],
            remediation: "Disable introspection in production (set `introspection: false` in your server config). Allow-list only via internal tooling or developer environments.",
            references: vec!["CWE-200: Information Exposure", "OWASP API Security Top 10"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let mut sensitive: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if matches_sensitive(&f.name) {
                    sensitive.push(format!("{}.{}", type_name, f.name));
                }
            }
        }
        if let Some(input_fields) = &t.input_fields {
            for f in input_fields {
                if matches_sensitive(&f.name) {
                    sensitive.push(format!("{}(input).{}", type_name, f.name));
                }
            }
        }
    }
    if !sensitive.is_empty() {
        findings.push(Finding {
            id: "GQL-002",
            severity: Severity::High,
            title: "Sensitive Field Names Exposed",
            description: format!(
                "{} field(s) with names suggesting sensitive data (passwords, tokens, secrets, keys, etc.) are present in the schema. These may be accessible without authorization.",
                sensitive.len()
            ),
            affected: sensitive.into_iter().take(25).collect(),
            remediation: "Add field-level authorization for all sensitive fields. Consider masking, omitting from schema entirely, or using opaque identifiers.",
            references: vec!["OWASP API3: Excessive Data Exposure", "CWE-312: Cleartext Storage"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let type_map: HashMap<&str, &GqlType> = types
        .iter()
        .filter_map(|t| t.name.as_deref().map(|n| (n, *t)))
        .collect();

    let mut circular: Vec<String> = Vec::new();
    for t in &types {
        let type_name = match t.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if let Some(ref_name) = unwrap_type_name(tr) {
                        if ref_name == type_name {
                            circular.push(format!("{}.{} → {}", type_name, f.name, ref_name));
                        }
                    }
                }
            }
        }
    }

    for t in &types {
        let type_name = match t.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if let Some(ref_name) = unwrap_type_name(tr) {
                        if ref_name != type_name {
                            if let Some(other) = type_map.get(ref_name.as_str()) {
                                if let Some(other_fields) = &other.fields {
                                    for of in other_fields {
                                        if let Some(ref otr) = of.field_type {
                                            if unwrap_type_name(otr).as_deref() == Some(type_name) {
                                                let entry = format!(
                                                    "{} ↔ {} (mutual recursion)",
                                                    type_name, ref_name
                                                );
                                                if !circular.contains(&entry) {
                                                    circular.push(entry);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !circular.is_empty() {
        findings.push(Finding {
            id: "GQL-003",
            severity: Severity::High,
            title: "Circular / Recursive Type References (DoS Risk)",
            description: format!(
                "{} circular or mutually-recursive type reference(s) found. Attackers can craft deeply nested queries that exhaust CPU and memory (unbounded query depth attack).",
                circular.len()
            ),
            affected: circular.into_iter().take(15).collect(),
            remediation: "Implement query depth limiting (recommended max: 7-10 levels). Use graphql-depth-limit, graphql-query-complexity, or built-in server options. Set a hard timeout on query execution.",
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let mut dos_list_inflation: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    let is_listish = tr.kind.as_deref() == Some("LIST") || tr.kind.as_deref() == Some("NON_NULL");
                    if is_listish {
                        if let Some(inner_name) = unwrap_type_name(tr) {
                            let nested_list_count = fields_for_type(schema, Some(&inner_name))
                                .iter()
                                .filter(|nf| {
                                    nf.field_type
                                        .as_ref()
                                        .map(|nt| nt.kind.as_deref() == Some("LIST"))
                                        .unwrap_or(false)
                                })
                                .count();

                            if nested_list_count > 0 {
                                dos_list_inflation.push(format!(
                                    "{}.{} returns {}, with {} nested list field(s)",
                                    type_name, f.name, inner_name, nested_list_count
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if !dos_list_inflation.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-001",
            severity: Severity::Medium,
            title: "Nested List Inflation Risk",
            description: format!(
                "{} list-returning field(s) fan out into additional list fields on related types. This enables exponential response growth from a single query.",
                dos_list_inflation.len()
            ),
            affected: dos_list_inflation.into_iter().take(20).collect(),
            remediation: "Implement strict pagination limits and query-cost analysis. Cap result sizes and enforce maximum complexity per request.",
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let mut self_recursive_fields: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if unwrap_type_name(tr).as_deref() == Some(type_name) {
                        self_recursive_fields.push(format!("{}.{}", type_name, f.name));
                    }
                }
            }
        }
    }

    if !self_recursive_fields.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-002",
            severity: Severity::High,
            title: "Unbounded Recursive Relationship",
            description: format!(
                "{} self-referencing field(s) detected. Without max depth checks, attackers can submit deeply nested queries that exhaust CPU and memory.",
                self_recursive_fields.len()
            ),
            affected: self_recursive_fields.into_iter().take(20).collect(),
            remediation: "Enforce a max query depth rule (commonly 5-10), apply complexity scoring, and enforce execution timeouts.",
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let auth_directive_names = &[
        "auth",
        "authenticated",
        "authorized",
        "isAuthenticated",
        "requiresAuth",
        "hasRole",
        "permission",
        "authorize",
    ];
    let has_auth_directives = directives.iter().any(|d| {
        auth_directive_names
            .iter()
            .any(|a| d.name.to_lowercase().contains(&a.to_lowercase()))
    });

    let mutation_fields = fields_for_type(schema, mutation_name);
    if !mutation_fields.is_empty() && !has_auth_directives {
        findings.push(Finding {
            id: "GQL-004",
            severity: Severity::Medium,
            title: "No Authorization Directives Found on Mutations",
            description: format!(
                "{} mutation(s) are present but no authorization directives (@auth, @isAuthenticated, @hasRole, etc.) appear in the schema. Mutations may lack declarative access control.",
                mutation_fields.len()
            ),
            affected: mutation_fields
                .iter()
                .map(|f| format!("Mutation.{}", f.name))
                .take(20)
                .collect(),
            remediation: "Use schema-level auth directives (graphql-shield, graphql-authz, or server-specific auth plugins). Every mutation that modifies data should require explicit authorization.",
            references: vec![
                "OWASP API1: Broken Object Level Authorization",
                "OWASP API5: Broken Function Level Authorization",
            ],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let sub_fields = fields_for_type(schema, subscription_name);
    if !sub_fields.is_empty() {
        findings.push(Finding {
            id: "GQL-005",
            severity: Severity::Medium,
            title: "Subscriptions Exposed",
            description: format!(
                "{} subscription(s) found. Unauthenticated or rate-unlimited subscriptions allow attackers to maintain persistent WebSocket connections, drain server resources, or exfiltrate streaming data.",
                sub_fields.len()
            ),
            affected: sub_fields
                .iter()
                .map(|f| format!("Subscription.{}", f.name))
                .collect(),
            remediation: "Require authentication for all subscriptions. Enforce per-user connection limits and rate-limit subscription creation. Validate all subscription filter payloads server-side.",
            references: vec!["CWE-770: Allocation of Resources Without Limits"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    if mutation_fields.len() > 20 {
        findings.push(Finding {
            id: "GQL-006",
            severity: Severity::Medium,
            title: "Large Mutation Attack Surface",
            description: format!(
                "{} mutations are exposed. A large mutation surface increases the probability of missing access controls, mass-assignment vulnerabilities, and IDOR issues.",
                mutation_fields.len()
            ),
            affected: vec![format!("{} total mutations", mutation_fields.len())],
            remediation: "Audit each mutation for authorization requirements. Consider splitting schemas by role/context, or use persisted/allow-listed queries to limit operations.",
            references: vec!["OWASP API6: Mass Assignment", "CWE-915: Improperly Controlled Modification"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let deprecated: Vec<String> = types
        .iter()
        .flat_map(|t| {
            let type_name = t.name.as_deref().unwrap_or("?").to_string();
            t.fields.iter().flat_map(move |fields| {
                let tn = type_name.clone();
                fields
                    .iter()
                    .filter(|f| f.is_deprecated.unwrap_or(false))
                    .map(move |f| {
                        let reason = f.deprecation_reason.as_deref().unwrap_or("no reason");
                        format!("{}.{} ({})", tn, f.name, reason)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    if !deprecated.is_empty() {
        findings.push(Finding {
            id: "GQL-007",
            severity: Severity::Low,
            title: "Deprecated Fields Still Queryable",
            description: format!(
                "{} deprecated field(s) remain accessible. These may have weaker validation, outdated authorization logic, or expose legacy data paths.",
                deprecated.len()
            ),
            affected: deprecated.into_iter().take(20).collect(),
            remediation: "Remove deprecated fields or block access server-side. If kept for backward compatibility, ensure they have equivalent security controls to new fields.",
            references: vec!["CWE-477: Use of Obsolete Function"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let sensitive_enums: Vec<String> = types
        .iter()
        .filter(|t| t.kind.as_deref() == Some("ENUM"))
        .filter(|t| {
            let name_sensitive = t.name.as_deref().map(matches_sensitive).unwrap_or(false);
            let values_sensitive = t
                .enum_values
                .as_ref()
                .map(|vs| vs.iter().any(|v| matches_sensitive(&v.name)))
                .unwrap_or(false);
            name_sensitive || values_sensitive
        })
        .map(|t| {
            let values = t
                .enum_values
                .as_ref()
                .map(|vs| vs.iter().map(|v| v.name.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            format!("{}: [{}]", t.name.as_deref().unwrap_or("?"), values)
        })
        .collect();

    if !sensitive_enums.is_empty() {
        findings.push(Finding {
            id: "GQL-008",
            severity: Severity::Low,
            title: "Enums With Sensitive Values Exposed",
            description: format!(
                "{} enum type(s) expose names suggesting internal roles, permissions, or states. Attackers can enumerate valid states to assist privilege escalation or IDOR attacks.",
                sensitive_enums.len()
            ),
            affected: sensitive_enums,
            remediation: "Avoid exposing internal role/permission enums publicly. Use opaque identifiers and validate enum values strictly server-side.",
            references: vec!["CWE-200: Information Exposure"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let bloated: Vec<String> = types
        .iter()
        .filter(|t| t.kind.as_deref() == Some("OBJECT"))
        .filter(|t| {
            let n = t.name.as_deref().unwrap_or("");
            !["Query", "Mutation", "Subscription"].contains(&n)
                && t.fields.as_ref().map(|f| f.len() > 30).unwrap_or(false)
        })
        .map(|t| {
            format!(
                "{} ({} fields)",
                t.name.as_deref().unwrap_or("?"),
                t.fields.as_ref().map(|f| f.len()).unwrap_or(0)
            )
        })
        .collect();

    if !bloated.is_empty() {
        findings.push(Finding {
            id: "GQL-009",
            severity: Severity::Low,
            title: "Over-Exposed Object Types (Field Bloat)",
            description: format!(
                "{} object type(s) expose more than 30 fields. Overly wide types increase the risk of unintentional data exposure and make authorization auditing harder.",
                bloated.len()
            ),
            affected: bloated,
            remediation: "Apply principle of least privilege to schema design. Split types by role (e.g. UserPublic vs UserAdmin). Add field-level resolvers with auth checks.",
            references: vec!["OWASP API3: Excessive Data Exposure"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let query_fields = fields_for_type(schema, query_name);
    let list_queries: Vec<String> = query_fields
        .iter()
        .filter(|f| {
            let n = f.name.to_lowercase();
            n.starts_with("list")
                || n.starts_with("all")
                || n.starts_with("search")
                || n.starts_with("find")
                || n.ends_with('s')
                || f
                    .field_type
                    .as_ref()
                    .and_then(unwrap_type_name)
                    .map(|n| n.contains("Connection") || n.contains("List"))
                    .unwrap_or(false)
        })
        .map(|f| format!("Query.{}", f.name))
        .collect();

    if list_queries.len() > 4 {
        findings.push(Finding {
            id: "GQL-010",
            severity: Severity::Low,
            title: "Batch / List Query Abuse Surface",
            description: format!(
                "{} list or search queries detected. Attackers can send a single GraphQL request with many aliased list queries to enumerate data in bulk, bypassing REST-style per-endpoint rate limits.",
                list_queries.len()
            ),
            affected: list_queries.into_iter().take(15).collect(),
            remediation: "Implement complexity-aware rate limiting that accounts for GraphQL aliasing. Limit the number of aliases per request. Add pagination limits with enforced maximums.",
            references: vec!["CWE-770: Resource Exhaustion", "OWASP API4: Lack of Resources"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let untyped_mutations: Vec<String> = mutation_fields
        .iter()
        .filter(|f| {
            f.args
                .as_ref()
                .map(|args| {
                    args.iter().any(|a| {
                        a.arg_type
                            .as_ref()
                            .and_then(unwrap_type_name)
                            .map(|n| n == "String" || n == "ID")
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
        .map(|f| format!("Mutation.{}", f.name))
        .collect();

    if !untyped_mutations.is_empty() {
        findings.push(Finding {
            id: "GQL-011",
            severity: Severity::Low,
            title: "Mutations Accept Raw String / ID Arguments",
            description: format!(
                "{} mutation(s) accept raw String or ID arguments. Without custom scalars or input validation, these are potential injection vectors (SQLi, NoSQLi, SSRF).",
                untyped_mutations.len()
            ),
            affected: untyped_mutations.into_iter().take(20).collect(),
            remediation: "Replace generic String/ID arguments with typed Input objects and custom scalars (e.g. EmailAddress, URL, UUID). Validate all inputs server-side regardless of scalar type.",
            references: vec!["CWE-20: Improper Input Validation", "OWASP API8: Injection"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    let debug_patterns = &[
        "debug", "internal", "admin", "private", "test", "dev", "staging", "root",
    ];
    let debug_types: Vec<String> = types
        .iter()
        .filter(|t| {
            t.name
                .as_deref()
                .map(|n| {
                    let lower = n.to_lowercase();
                    debug_patterns.iter().any(|p| lower.contains(p))
                })
                .unwrap_or(false)
        })
        .map(|t| t.name.as_deref().unwrap_or("?").to_string())
        .collect();

    if !debug_types.is_empty() {
        findings.push(Finding {
            id: "GQL-012",
            severity: Severity::Medium,
            title: "Debug / Admin / Internal Types Exposed",
            description: format!(
                "{} type name(s) suggest internal, debug, or admin functionality is exposed in the public schema. These are high-value targets for attackers.",
                debug_types.len()
            ),
            affected: debug_types,
            remediation: "Remove internal/debug types from the public schema. Use schema stitching or type visibility rules to expose only what external clients need.",
            references: vec!["CWE-489: Active Debug Code", "OWASP API7: Security Misconfiguration"],
            evidence_level: EvidenceLevel::Inferred,
        });
    }

    (findings, stats)
}
