mod policy;
mod scanner;
mod types;

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use clap::Parser;
use tracing::{error, info, warn};

use crate::policy::Policy;
use crate::scanner::CredentialScanner;
use crate::types::*;

#[derive(Parser)]
#[command(name = "mcp-guardrails", about = "MCP tool-call guardrails webhook for agentgateway")]
struct Cli {
    /// Path to the policy YAML file
    #[arg(short, long, default_value = "policy.yaml")]
    policy: String,

    /// Address to bind the server to
    #[arg(short, long, default_value = "0.0.0.0:8090")]
    bind: String,
}

struct AppState {
    policy: Policy,
    scanner: CredentialScanner,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcp_guardrails=info".into()),
        )
        .json()
        .init();

    let cli = Cli::parse();

    let policy = match Policy::load(&cli.policy) {
        Ok(p) => {
            info!(tools_allowed = p.tools_allowed(), tools_denied = p.tools_denied(), "policy loaded");
            p
        }
        Err(e) => {
            error!(path = %cli.policy, error = %e, "failed to load policy");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState {
        policy,
        scanner: CredentialScanner::new(),
    });

    let app = Router::new()
        .route("/request", post(handle_request))
        .route("/response", post(handle_response))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.unwrap();
    info!(addr = %cli.bind, "mcp-guardrails listening");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_request(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GuardrailsPromptRequest>,
) -> (StatusCode, Json<GuardrailsPromptResponse>) {
    let mut violations: Vec<String> = Vec::new();

    for msg in &req.body.messages {
        let content = &msg.content;

        // Check for tool calls in the content
        if let Some(tool_name) = extract_tool_call(content) {
            // Tool-level RBAC
            if !state.policy.is_tool_allowed(&tool_name) {
                warn!(tool = %tool_name, "tool call denied by policy");
                violations.push(format!("tool '{}' is not allowed by policy", tool_name));
            }
        }

        // Credential scanning
        if let Some(findings) = state.scanner.scan(content) {
            for finding in &findings {
                warn!(pattern = %finding, "credential pattern detected in prompt");
                violations.push(format!("credential pattern detected: {}", finding));
            }
        }

        // Deny pattern matching
        for pattern in state.policy.deny_patterns() {
            if content.contains(pattern) {
                warn!(pattern = %pattern, "deny pattern matched in prompt");
                violations.push(format!("content matches deny pattern: {}", pattern));
            }
        }
    }

    if violations.is_empty() {
        info!("request passed all guardrails");
        (
            StatusCode::OK,
            Json(GuardrailsPromptResponse {
                action: RequestAction::Pass(PassAction {
                    reason: Some("all guardrails passed".to_string()),
                }),
            }),
        )
    } else {
        let reason = violations.join("; ");
        warn!(violations = %reason, "request rejected");
        (
            StatusCode::OK,
            Json(GuardrailsPromptResponse {
                action: RequestAction::Reject(RejectAction {
                    body: format!("Request blocked by MCP guardrails: {}", reason),
                    status_code: 403,
                    reason: Some(reason),
                }),
            }),
        )
    }
}

async fn handle_response(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GuardrailsResponseRequest>,
) -> (StatusCode, Json<GuardrailsResponseResponse>) {
    let mut violations: Vec<String> = Vec::new();

    for choice in &req.body.choices {
        let content = &choice.message.content;

        // Scan response for leaked credentials
        if let Some(findings) = state.scanner.scan(content) {
            for finding in &findings {
                warn!(pattern = %finding, "credential pattern detected in response");
                violations.push(format!("credential leak in response: {}", finding));
            }
        }
    }

    if violations.is_empty() {
        (
            StatusCode::OK,
            Json(GuardrailsResponseResponse {
                action: ResponseAction::Pass(PassAction {
                    reason: Some("response passed all guardrails".to_string()),
                }),
            }),
        )
    } else {
        let reason = violations.join("; ");
        warn!(violations = %reason, "response rejected");
        (
            StatusCode::OK,
            Json(GuardrailsResponseResponse {
                action: ResponseAction::Reject(RejectAction {
                    body: format!("Response blocked by MCP guardrails: {}", reason),
                    status_code: 403,
                    reason: Some(reason),
                }),
            }),
        )
    }
}

fn extract_tool_call(content: &str) -> Option<String> {
    // Look for tool_use patterns in the content (both MCP and tool_call formats)
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            return Some(name.to_string());
        }
        if let Some(name) = val.get("tool").and_then(|n| n.as_str()) {
            return Some(name.to_string());
        }
    }
    // Check for tool_use blocks in the text
    if content.contains("tool_use") || content.contains("tool_call") {
        // Try to extract tool name from JSON-like content
        if let Some(start) = content.find("\"name\"") {
            let rest = &content[start..];
            if let Some(colon) = rest.find(':') {
                let after = rest[colon + 1..].trim();
                let after = after.trim_start_matches('"');
                if let Some(end) = after.find('"') {
                    return Some(after[..end].to_string());
                }
            }
        }
    }
    None
}
