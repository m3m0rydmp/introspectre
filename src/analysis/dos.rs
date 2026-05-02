use crate::analysis::utils::user_types;
use crate::types::{Confidence, EvidenceLevel, Finding, GqlSchema, GqlType, Severity};
use std::collections::{HashMap, HashSet};

pub fn check_dos(schema: &GqlSchema, findings: &mut Vec<Finding>) {
    let types = user_types(schema);
    let type_map: HashMap<&str, &GqlType> = types
        .iter()
        .filter_map(|t| t.name.as_deref().map(|n| (n, *t)))
        .collect();

    let mut circular_set: HashSet<String> = HashSet::new();
    for t in &types {
        let type_name = match t.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if let Some(ref_name) = tr.unwrap_type_name() {
                        if ref_name == type_name {
                            circular_set.insert(format!("{}.{} → {}", type_name, f.name, ref_name));
                        } else if let Some(other) = type_map.get(ref_name.as_str()) {
                            if let Some(other_fields) = &other.fields {
                                for of in other_fields {
                                    if let Some(ref otr) = of.field_type {
                                        if otr.unwrap_type_name().as_deref() == Some(type_name) {
                                            let mut pair = [type_name, ref_name.as_str()];
                                            pair.sort();
                                            circular_set.insert(format!(
                                                "{} ↔ {} (mutual recursion)",
                                                pair[0], pair[1]
                                            ));
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

    if !circular_set.is_empty() {
        findings.push(Finding {
            id: "GQL-003",
            severity: Severity::High,
            title: "Circular / Recursive Type References (DoS Risk)",
            description: format!(
                "{} circular or mutually-recursive type reference(s) found. Attackers can craft deeply nested queries that exhaust CPU and memory (unbounded query depth attack).",
                circular_set.len()
            ),
            affected: circular_set.into_iter().take(15).collect(),
            remediation: "Implement query depth limiting (recommended max: 7-10 levels). Use graphql-depth-limit, graphql-query-complexity, or built-in server options. Set a hard timeout on query execution.",
            references: vec!["CWE-400: Uncontrolled Resource Consumption", "OWASP API4: Lack of Resources"],
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mut dos_list_inflation: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("?");
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    let is_listish = tr.kind.as_deref() == Some("LIST")
                        || tr.kind.as_deref() == Some("NON_NULL");
                    if is_listish {
                        if let Some(inner_name) = tr.unwrap_type_name() {
                            let nested_list_count = schema
                                .fields_for_type(Some(&inner_name))
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
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
                    if tr.unwrap_type_name().as_deref() == Some(type_name) {
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let query_fields = schema.fields_for_type(query_name);
    let list_queries: Vec<String> = query_fields
        .iter()
        .filter(|f| {
            let n = f.name.to_lowercase();
            n.starts_with("list")
                || n.starts_with("all")
                || n.starts_with("search")
                || n.starts_with("find")
                || n.ends_with('s')
                || f.field_type
                    .as_ref()
                    .and_then(|t| t.unwrap_type_name())
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mut unpaginated_lists: Vec<String> = Vec::new();
    for t in &types {
        let type_name = t.name.as_deref().unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        if let Some(fields) = &t.fields {
            for f in fields {
                if let Some(ref tr) = f.field_type {
                    if tr.kind.as_deref() == Some("LIST") {
                        let mut has_pagination = false;
                        if let Some(args) = &f.args {
                            for arg in args {
                                let arg_lower = arg.name.to_lowercase();
                                if [
                                    "first", "last", "limit", "offset", "after", "before", "page",
                                    "size",
                                ]
                                .iter()
                                .any(|&p| arg_lower.contains(p))
                                {
                                    has_pagination = true;
                                    break;
                                }
                            }
                        }
                        if !has_pagination {
                            unpaginated_lists.push(format!("{}.{}", type_name, f.name));
                        }
                    }
                }
            }
        }
    }

    if !unpaginated_lists.is_empty() {
        findings.push(Finding {
            id: "GQL-DOS-003",
            severity: Severity::Medium,
            title: "Unpaginated List Field",
            description: format!(
                "{} field(s) return a list but lack common pagination arguments (first, limit, offset, etc.). This can lead to resource exhaustion if the underlying dataset is large.",
                unpaginated_lists.len()
            ),
            affected: unpaginated_lists.into_iter().take(20).collect(),
            remediation: "Enforce pagination on all list-returning fields. Use Cursor-based pagination (Relay) or Offset-based pagination with a strictly enforced maximum 'limit' (e.g. 100).",
            references: vec!["OWASP API4: Lack of Resources", "CWE-770: Allocation of Resources Without Limits"],
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}
