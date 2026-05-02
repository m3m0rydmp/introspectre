use crate::types::{GqlSchema, GqlType};

pub fn matches_pattern(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_lowercase();
    patterns.iter().any(|p| {
        let candidate = p.trim().to_lowercase();
        !candidate.is_empty() && lower.contains(&candidate)
    })
}

pub fn user_types(schema: &GqlSchema) -> Vec<&GqlType> {
    schema
        .types
        .iter()
        .filter(|t| {
            t.name
                .as_deref()
                .map(|n| !n.starts_with("__"))
                .unwrap_or(false)
        })
        .collect()
}
