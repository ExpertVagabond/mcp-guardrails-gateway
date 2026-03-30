use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    /// Tools that are explicitly allowed. If non-empty, only these tools can be called.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Tools that are explicitly denied. Checked after allowed_tools.
    #[serde(default)]
    pub denied_tools: Vec<String>,

    /// String patterns that cause immediate rejection if found in content.
    #[serde(default)]
    pub deny_patterns: Vec<String>,

    /// Whether to scan for credential patterns (API keys, tokens, etc.)
    #[serde(default = "default_true")]
    pub credential_scanning: bool,

    /// Maximum content length in characters. 0 means unlimited.
    #[serde(default)]
    pub max_content_length: usize,
}

fn default_true() -> bool {
    true
}

pub struct Policy {
    allowed: HashSet<String>,
    denied: HashSet<String>,
    deny_patterns: Vec<String>,
    pub credential_scanning: bool,
    pub max_content_length: usize,
}

impl Policy {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: PolicyConfig = serde_yaml::from_str(&content)?;
        Ok(Self {
            allowed: config.allowed_tools.into_iter().collect(),
            denied: config.denied_tools.into_iter().collect(),
            deny_patterns: config.deny_patterns,
            credential_scanning: config.credential_scanning,
            max_content_length: config.max_content_length,
        })
    }

    pub fn is_tool_allowed(&self, tool: &str) -> bool {
        // If denied list has the tool, reject
        if self.denied.contains(tool) {
            return false;
        }
        // If allowed list is non-empty, tool must be in it
        if !self.allowed.is_empty() {
            return self.allowed.contains(tool);
        }
        // Default: allow
        true
    }

    pub fn deny_patterns(&self) -> &[String] {
        &self.deny_patterns
    }

    pub fn tools_allowed(&self) -> usize {
        self.allowed.len()
    }

    pub fn tools_denied(&self) -> usize {
        self.denied.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_all_when_empty() {
        let policy = Policy {
            allowed: HashSet::new(),
            denied: HashSet::new(),
            deny_patterns: vec![],
            credential_scanning: true,
            max_content_length: 0,
        };
        assert!(policy.is_tool_allowed("any_tool"));
    }

    #[test]
    fn test_allowlist_restricts() {
        let policy = Policy {
            allowed: ["read_file".to_string()].into_iter().collect(),
            denied: HashSet::new(),
            deny_patterns: vec![],
            credential_scanning: true,
            max_content_length: 0,
        };
        assert!(policy.is_tool_allowed("read_file"));
        assert!(!policy.is_tool_allowed("delete_file"));
    }

    #[test]
    fn test_denylist_blocks() {
        let policy = Policy {
            allowed: HashSet::new(),
            denied: ["rm_rf".to_string()].into_iter().collect(),
            deny_patterns: vec![],
            credential_scanning: true,
            max_content_length: 0,
        };
        assert!(!policy.is_tool_allowed("rm_rf"));
        assert!(policy.is_tool_allowed("read_file"));
    }

    #[test]
    fn test_deny_overrides_allow() {
        let policy = Policy {
            allowed: ["dangerous".to_string()].into_iter().collect(),
            denied: ["dangerous".to_string()].into_iter().collect(),
            deny_patterns: vec![],
            credential_scanning: true,
            max_content_length: 0,
        };
        assert!(!policy.is_tool_allowed("dangerous"));
    }
}
