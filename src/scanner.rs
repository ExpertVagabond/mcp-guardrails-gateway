use regex::Regex;

pub struct CredentialScanner {
    patterns: Vec<(String, Regex)>,
}

impl CredentialScanner {
    pub fn new() -> Self {
        let patterns = vec![
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
            ("AWS Secret Key", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
            ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
            ("GitHub Classic Token", r"ghp_[A-Za-z0-9]{36}"),
            ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
            ("Stripe Key", r"sk_live_[0-9a-zA-Z]{24,99}"),
            ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,99}"),
            ("OpenAI API Key", r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
            ("Generic API Key", r#"(?i)(api[_\-]?key|apikey|api_secret)\s*[:=]\s*['"]?[A-Za-z0-9\-_.]{20,}['"]?"#),
            ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*"),
            ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-]{20,}"),
            ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
            ("Solana Private Key", r"[1-9A-HJ-NP-Za-km-z]{87,88}"),
        ];

        Self {
            patterns: patterns
                .into_iter()
                .map(|(name, pat)| (name.to_string(), Regex::new(pat).unwrap()))
                .collect(),
        }
    }

    pub fn scan(&self, content: &str) -> Option<Vec<String>> {
        let mut findings = Vec::new();
        for (name, regex) in &self.patterns {
            if regex.is_match(content) {
                findings.push(name.clone());
            }
        }
        if findings.is_empty() {
            None
        } else {
            Some(findings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_aws_key() {
        let scanner = CredentialScanner::new();
        let content = "Here's the key: AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("AWS")));
    }

    #[test]
    fn test_detects_github_token() {
        let scanner = CredentialScanner::new();
        let content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("GitHub")));
    }

    #[test]
    fn test_detects_private_key() {
        let scanner = CredentialScanner::new();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("Private Key")));
    }

    #[test]
    fn test_clean_content_passes() {
        let scanner = CredentialScanner::new();
        let content = "Hello, please read the file at /tmp/test.txt";
        assert!(scanner.scan(content).is_none());
    }

    #[test]
    fn test_detects_jwt() {
        let scanner = CredentialScanner::new();
        let content = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("JWT")));
    }

    #[test]
    fn test_detects_stripe_key() {
        let scanner = CredentialScanner::new();
        let content = "sk_live_51234567890abcdefghijklmnop";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("Stripe")));
    }

    #[test]
    fn test_detects_anthropic_key() {
        let scanner = CredentialScanner::new();
        let content = "key: sk-ant-abcdefghijklmnopqrstuvwx";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("Anthropic")));
    }

    #[test]
    fn test_detects_google_key() {
        let scanner = CredentialScanner::new();
        let content = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
        let findings = scanner.scan(content).unwrap();
        assert!(findings.iter().any(|f| f.contains("Google")));
    }
}
