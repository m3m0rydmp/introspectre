#![allow(dead_code)]

use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub patterns: PatternConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

impl AppConfig {
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;

        toml::from_str::<Self>(&content)
            .map_err(|e| format!("Failed to parse TOML config {}: {}", path.display(), e))
    }

    pub fn merge_wordlists(&mut self, specs: &[String]) -> Result<(), String> {
        for spec in specs {
            let (kind, path) = parse_wordlist_spec(spec)?;
            let entries = read_wordlist_entries(path)?;
            match kind {
                WordlistType::SensitiveFields => {
                    merge_unique(&mut self.patterns.sensitive_fields.names, entries)
                }
                WordlistType::SsrfArgs => merge_unique(&mut self.patterns.ssrf_args.names, entries),
                WordlistType::IdorMutations => {
                    merge_unique(&mut self.patterns.idor_mutations.prefixes, entries)
                }
                WordlistType::OperationNames => {
                    merge_unique(&mut self.patterns.operation_names.names, entries)
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternConfig {
    #[serde(default = "default_sensitive_fields")]
    pub sensitive_fields: PatternNames,
    #[serde(default = "default_ssrf_args")]
    pub ssrf_args: PatternNames,
    #[serde(default = "default_idor_mutations")]
    pub idor_mutations: PatternPrefixes,
    #[serde(default = "default_debug_types")]
    pub debug_types: PatternNames,
    #[serde(default)]
    pub operation_names: PatternNames,
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            sensitive_fields: default_sensitive_fields(),
            ssrf_args: default_ssrf_args(),
            idor_mutations: default_idor_mutations(),
            debug_types: default_debug_types(),
            operation_names: PatternNames::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatternNames {
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternPrefixes {
    #[serde(default)]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SessionConfig {
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub owned_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub test_unauth: bool,
    #[serde(default = "default_true")]
    pub test_idor: bool,
    #[serde(default)]
    pub test_injection: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            test_unauth: true,
            test_idor: true,
            test_injection: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_sensitive_fields() -> PatternNames {
    PatternNames {
        names: vec![
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "auth",
            "credential",
            "private",
            "ssn",
            "credit",
            "card",
            "cvv",
            "otp",
            "pin",
            "hash",
            "salt",
            "session",
            "cookie",
            "bearer",
            "key",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
    }
}

fn default_ssrf_args() -> PatternNames {
    PatternNames {
        names: vec!["url", "webhook", "callback", "redirect", "endpoint", "image_url"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

fn default_idor_mutations() -> PatternPrefixes {
    PatternPrefixes {
        prefixes: vec!["delete", "remove", "update", "download", "export"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

fn default_debug_types() -> PatternNames {
    PatternNames {
        names: vec![
            "debug",
            "internal",
            "admin",
            "private",
            "test",
            "dev",
            "staging",
            "root",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
    }
}

#[derive(Debug, Clone, Copy)]
enum WordlistType {
    SensitiveFields,
    SsrfArgs,
    IdorMutations,
    OperationNames,
}

fn parse_wordlist_spec(spec: &str) -> Result<(WordlistType, &Path), String> {
    let mut parts = spec.splitn(2, '=');
    let raw_type = parts.next().unwrap_or("").trim();
    let raw_path = parts.next().unwrap_or("").trim();

    if raw_type.is_empty() || raw_path.is_empty() {
        return Err(format!(
            "Invalid --wordlist value '{}'. Expected format TYPE=PATH.",
            spec
        ));
    }

    let kind = match raw_type {
        "sensitive_fields" => WordlistType::SensitiveFields,
        "ssrf_args" => WordlistType::SsrfArgs,
        "idor_mutations" => WordlistType::IdorMutations,
        "operation_names" => WordlistType::OperationNames,
        _ => {
            return Err(format!(
                "Unsupported wordlist type '{}'. Supported: sensitive_fields, ssrf_args, idor_mutations, operation_names.",
                raw_type
            ))
        }
    };

    Ok((kind, Path::new(raw_path)))
}

fn read_wordlist_entries(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read wordlist {}: {}", path.display(), e))?;

    Ok(content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect())
}

fn merge_unique(target: &mut Vec<String>, mut additions: Vec<String>) {
    let mut seen: HashSet<String> = target.iter().map(|s| s.to_lowercase()).collect();
    additions.retain(|v| {
        let normalized = v.to_lowercase();
        if normalized.is_empty() || seen.contains(&normalized) {
            false
        } else {
            seen.insert(normalized);
            true
        }
    });
    target.extend(additions);
}