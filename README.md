# mcp-guardrails

MCP tool-call guardrails webhook for [agentgateway](https://github.com/agentgateway/agentgateway). Scans prompts and responses for credential leaks, enforces tool-level RBAC, and blocks dangerous content patterns.

Built for [MCP_HACK//26](https://aihackathon.dev/) Track 2: Secure & Govern MCP.

## What it does

`mcp-guardrails` runs as a standalone HTTP server that integrates with agentgateway's [webhook guardrails policy](https://agentgateway.dev/). When configured as a guardrails backend, agentgateway forwards every prompt and response through this server for validation before it reaches the MCP server or the client.

**Credential scanning** — detects 15+ secret patterns (AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, Anthropic/OpenAI API keys, Solana private keys, and more) in both prompts and responses.

**Tool-level RBAC** — allowlist/denylist for MCP tool names. Block dangerous tools (`shell_exec`, `rm_rf`) or restrict to a known-safe set.

**Deny patterns** — block content containing SQL injection patterns, dangerous shell commands, or custom strings.

**Structured audit logging** — JSON-formatted logs with tracing for every decision (pass/reject) for compliance and debugging.

## Quick start

```bash
cargo build --release

# Run with default policy
./target/release/mcp-guardrails --policy policy.yaml --bind 0.0.0.0:8090
```

## agentgateway integration

Add a webhook guardrails policy to your agentgateway config:

```yaml
apiVersion: gateway.agentgateway.dev/v1
kind: LLMRoute
metadata:
  name: my-route
spec:
  rules:
    - backendRefs:
        - name: my-llm
      guardrails:
        - webhook:
            url: http://mcp-guardrails:8090
```

The server exposes two endpoints matching the agentgateway webhook protocol:
- `POST /request` — validates prompts before they reach the LLM/MCP server
- `POST /response` — validates responses before they reach the client
- `GET /health` — health check

## Policy configuration

Edit `policy.yaml`:

```yaml
# Only allow these tools (empty = allow all)
allowed_tools:
  - read_file
  - search
  - list_directory

# Always block these tools
denied_tools:
  - shell_exec
  - delete_all

# Block content matching these patterns
deny_patterns:
  - "DROP TABLE"
  - "sudo rm -rf /"

# Scan for credential patterns
credential_scanning: true
```

## Tests

```bash
cargo test
# 12 tests: policy RBAC (4) + credential scanner (8)
```

## Architecture

```
Client → agentgateway → mcp-guardrails (webhook) → agentgateway → MCP Server
              ↓                                          ↑
         forwards prompt                          forwards if passed
         to /request                              blocks if rejected
```

The guardrails server is stateless and horizontally scalable. Deploy multiple replicas behind a load balancer for high-throughput MCP deployments.

## License

Apache-2.0
