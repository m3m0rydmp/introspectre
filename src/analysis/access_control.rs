use crate::analysis::utils::matches_pattern;
use crate::config::PatternConfig;
use crate::types::{Confidence, EvidenceLevel, Finding, GqlSchema, Severity};
use std::collections::HashSet;

pub fn check_access_control(
    schema: &GqlSchema,
    patterns: &PatternConfig,
    findings: &mut Vec<Finding>,
) {
    let query_name = schema.query_type.as_ref().map(|q| q.name.as_str());
    let mutation_name = schema.mutation_type.as_ref().map(|m| m.name.as_str());
    let subscription_name = schema.subscription_type.as_ref().map(|s| s.name.as_str());

    let directives = schema.directives.as_deref().unwrap_or(&[]);
    let has_auth_directives = directives.iter().any(|d| {
        patterns
            .auth_directives
            .names
            .iter()
            .any(|a| d.name.to_lowercase().contains(&a.to_lowercase()))
    });

    let mutation_fields = schema.fields_for_type(mutation_name);
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let sub_fields = schema.fields_for_type(subscription_name);
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
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
            confidence: Confidence::Theoretical,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let idor_arg_matches = |arg_name: &str| {
        let lower = arg_name.to_lowercase();
        matches!(lower.as_str(), "id" | "uuid" | "userid" | "documentid")
            || lower.ends_with("id")
            || lower.ends_with("_id")
    };

    let mut idor_candidates: HashSet<String> = HashSet::new();
    let query_fields = schema.fields_for_type(query_name);
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if idor_arg_matches(&arg.name) {
                        idor_candidates
                            .insert(format!("{}.{}({})", root_name, field.name, arg.name));
                    }
                }
            }
        }
    }

    if !idor_candidates.is_empty() {
        let mut sorted_candidates: Vec<String> = idor_candidates.into_iter().collect();
        sorted_candidates.sort();
        findings.push(Finding {
            id: "GQL-013",
            severity: Severity::Medium,
            title: "IDOR Candidate Detection",
            description: format!(
                "{} query/mutation argument(s) appear to accept object identifiers. These are potential BOLA/IDOR candidates if ownership checks are missing server-side.",
                sorted_candidates.len()
            ),
            affected: sorted_candidates.into_iter().take(30).collect(),
            remediation: "Enforce object-level authorization on every resolver that accepts identifiers (id, uuid, *Id, *_id). Validate caller ownership before returning or mutating records.",
            references: vec!["OWASP API1: Broken Object Level Authorization", "CWE-639: Authorization Bypass Through User-Controlled Key"],
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }

    let mut ssrf_candidates: HashSet<String> = HashSet::new();
    for (root_name, fields) in [("Query", &query_fields), ("Mutation", &mutation_fields)] {
        for field in fields {
            if let Some(args) = &field.args {
                for arg in args {
                    if matches_pattern(&arg.name, &patterns.ssrf_args.names) {
                        ssrf_candidates
                            .insert(format!("{}.{}({})", root_name, field.name, arg.name));
                    }
                }
            }
        }
    }

    if !ssrf_candidates.is_empty() {
        let mut sorted_candidates: Vec<String> = ssrf_candidates.into_iter().collect();
        sorted_candidates.sort();
        findings.push(Finding {
            id: "GQL-014",
            severity: Severity::Medium,
            title: "SSRF Candidate Detection",
            description: format!(
                "{} query/mutation argument(s) match SSRF-related URL/webhook patterns. If backend services fetch these values, SSRF may be possible.",
                sorted_candidates.len()
            ),
            affected: sorted_candidates.into_iter().take(30).collect(),
            remediation: "Block internal network destinations, enforce strict URL allow-lists, and isolate outbound fetchers. Never allow resolver-controlled requests to metadata or loopback addresses.",
            references: vec!["OWASP API8: Injection", "CWE-918: Server-Side Request Forgery (SSRF)"],
            confidence: Confidence::Possible,
            evidence_level: EvidenceLevel::Inferred,
            poc: None,
        });
    }
}
