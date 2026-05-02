use crate::config::PatternConfig;
use crate::types::{Confidence, EvidenceLevel, Finding, Severity};
use base64::prelude::*;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

fn decode_b64(input: &str) -> Option<Vec<u8>> {
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    BASE64_URL_SAFE.decode(&padded).ok()
}

fn matches_pattern(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_lowercase();
    patterns.iter().any(|p| {
        let candidate = p.trim().to_lowercase();
        !candidate.is_empty() && lower.contains(&candidate)
    })
}

pub fn check_jwt(token: Option<&str>, patterns: &PatternConfig, findings: &mut Vec<Finding>) {
    let token = match token {
        Some(t) => t,
        None => return,
    };

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header_bytes = match decode_b64(parts[0]) {
        Some(b) => b,
        None => return,
    };
    let payload_bytes = match decode_b64(parts[1]) {
        Some(b) => b,
        None => return,
    };

    let header: Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let payload: Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(alg) = header.get("alg").and_then(|v| v.as_str()) {
        if alg.to_lowercase() == "none" {
            findings.push(Finding {
                id: "JWT-001",
                severity: Severity::High,
                title: "JWT Algorithm None",
                description: "The provided JWT specifies the 'none' algorithm. This may indicate the server accepts unsigned tokens, allowing full authentication bypass.".to_string(),
                affected: vec!["Provided Session Token (Header)".to_string()],
                remediation: "Ensure your JWT library requires an explicit algorithm and rejects 'none'.",
                references: vec!["RFC 8725", "OWASP API Security Top 10"],
                confidence: Confidence::Confirmed,
                evidence_level: EvidenceLevel::Executed,
                poc: None,
            });
        }
    }

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if exp < now {
            findings.push(Finding {
                id: "JWT-002",
                severity: Severity::Low,
                title: "Provided JWT is Expired",
                description: "The provided JWT has an 'exp' claim in the past. Probes may fail or yield false negatives due to authentication errors.".to_string(),
                affected: vec!["Provided Session Token (Payload)".to_string()],
                remediation: "Provide a fresh token to ensure accurate active probing.",
                references: vec![],
                confidence: Confidence::Confirmed,
                evidence_level: EvidenceLevel::Executed,
                poc: None,
            });
        }
    }

    let mut sensitive_claims = Vec::new();
    if let Some(obj) = payload.as_object() {
        for key in obj.keys() {
            if matches_pattern(key, &patterns.sensitive_fields.names) {
                sensitive_claims.push(key.clone());
            }
        }
    }

    if !sensitive_claims.is_empty() {
        findings.push(Finding {
            id: "JWT-003",
            severity: Severity::Medium,
            title: "Sensitive Data in JWT Claims",
            description: "The JWT payload contains claims with names suggesting sensitive data. JWTs are merely encoded (not encrypted), so anyone possessing the token can read these fields.".to_string(),
            affected: sensitive_claims.iter().map(|k| format!("JWT Payload Claim: {}", k)).collect(),
            remediation: "Remove sensitive information from JWTs. Use them only for opaque user identifiers and roles, loading sensitive data server-side.",
            references: vec!["CWE-312: Cleartext Storage of Sensitive Information"],
            confidence: Confidence::Confirmed,
            evidence_level: EvidenceLevel::Executed,
            poc: None,
        });
    }
}
