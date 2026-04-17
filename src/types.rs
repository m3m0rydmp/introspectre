use serde::{Deserialize, Serialize};

pub const INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    directives { name locations }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name isDeprecated deprecationReason
        type { ...TypeRef }
        args { name type { ...TypeRef } }
      }
      inputFields { name type { ...TypeRef } }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name isDeprecated }
      possibleTypes { ...TypeRef }
    }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
"#;

#[derive(Debug, Deserialize)]
pub struct IntrospectionResponse {
    pub data: Option<IntrospectionData>,
    pub errors: Option<Vec<GqlError>>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectionData {
    #[serde(rename = "__schema")]
    pub schema: GqlSchema,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlSchema {
    pub query_type: Option<NamedRef>,
    pub mutation_type: Option<NamedRef>,
    pub subscription_type: Option<NamedRef>,
    pub directives: Option<Vec<GqlDirective>>,
    pub types: Vec<GqlType>,
}

#[derive(Debug, Deserialize)]
pub struct NamedRef {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct GqlDirective {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlType {
    pub kind: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub fields: Option<Vec<GqlField>>,
    pub input_fields: Option<Vec<GqlInputField>>,
    pub enum_values: Option<Vec<GqlEnumValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlField {
    pub name: String,
    pub is_deprecated: Option<bool>,
    pub deprecation_reason: Option<String>,
    #[serde(rename = "type")]
    pub field_type: Option<GqlTypeRef>,
    pub args: Option<Vec<GqlArg>>,
}

#[derive(Debug, Deserialize)]
pub struct GqlArg {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: Option<GqlTypeRef>,
}

#[derive(Debug, Deserialize)]
pub struct GqlInputField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: Option<GqlTypeRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GqlEnumValue {
    pub name: String,
    pub is_deprecated: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GqlTypeRef {
    pub kind: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "ofType")]
    pub of_type: Option<Box<GqlTypeRef>>,
}

#[derive(Debug, Deserialize)]
pub struct GqlError {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            other => Err(format!("Unknown severity: {}", other)),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum EvidenceLevel {
    #[serde(rename = "executed")]
    Executed,
    #[serde(rename = "inferred")]
    Inferred,
    #[serde(rename = "inconclusive")]
    Inconclusive,
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevel::Executed => write!(f, "Executed"),
            EvidenceLevel::Inferred => write!(f, "Inferred"),
            EvidenceLevel::Inconclusive => write!(f, "Inconclusive"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: String,
    pub affected: Vec<String>,
    pub remediation: &'static str,
    pub references: Vec<&'static str>,
    pub evidence_level: EvidenceLevel,
}

#[derive(Debug, Serialize)]
pub struct SchemaStats {
    pub total_types: usize,
    pub object_types: usize,
    pub queries: usize,
    pub mutations: usize,
    pub subscriptions: usize,
    pub enums: usize,
    pub interfaces: usize,
    pub unions: usize,
    pub total_fields: usize,
    pub deprecated_fields: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthDiscoveryResult {
    pub protected: Vec<String>,
    pub public: Vec<String>,
    pub inconclusive: Vec<String>,
}

impl AuthDiscoveryResult {
    pub fn new() -> Self {
        Self {
            protected: Vec::new(),
            public: Vec::new(),
            inconclusive: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportMeta {
    pub source: String,
    pub offline: bool,
    pub static_only: bool,
    pub auth_discovery_performed: bool,
    pub auth_discovery: Option<AuthDiscoveryResult>,
}
