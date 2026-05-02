#[cfg(test)]
mod tests {
    use crate::analysis::jwt::check_jwt;
    use crate::config::PatternConfig;
    use crate::types::Severity;

    #[test]
    fn test_jwt_alg_none() {
        // {"alg":"none","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "JWT-001");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_jwt_expired() {
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"123","exp":1000} (Expired in 1970)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjEwMDB9.sig";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        // Might be more than 1 if "sig" matches a sensitive pattern (unlikely but possible)
        assert!(findings.iter().any(|f| f.id == "JWT-002"));
    }

    #[test]
    fn test_jwt_sensitive_claims() {
        // Payload: {"sub":"123","password":"secret_value"}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJwYXNzd29yZCI6InNlY3JldF92YWx1ZSJ9.sig";
        let mut patterns = PatternConfig::default();
        patterns.sensitive_fields.names = vec!["password".to_string()];
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);

        assert!(findings.iter().any(|f| f.id == "JWT-003"));
        assert!(findings
            .iter()
            .any(|f| f.affected.iter().any(|a| a.contains("password"))));
    }

    #[test]
    fn test_jwt_invalid_format() {
        let token = "invalid.token";
        let patterns = PatternConfig::default();
        let mut findings = Vec::new();

        check_jwt(Some(token), &patterns, &mut findings);
        assert_eq!(findings.len(), 0);
    }
}
