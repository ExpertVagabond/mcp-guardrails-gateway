# Securing MCP Tool Calls with agentgateway Guardrails

## The Problem

As AI agents gain access to more tools through the Model Context Protocol (MCP), the attack surface grows. An agent connected to 50+ MCP servers has access to hundreds of tools — file systems, databases, shell execution, API keys. Without guardrails, a single prompt injection or hallucinated tool call can leak credentials, drop tables, or execute arbitrary commands.

## The Solution: mcp-guardrails

[mcp-guardrails](https://github.com/ExpertVagabond/mcp-guardrails-gateway) is a Rust webhook server that integrates with [agentgateway](https://agentgateway.dev/) to validate every MCP tool call before it reaches the backend.

### What it catches

**Credential scanning** — 15+ regex patterns detect leaked secrets in prompts and responses: AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, Anthropic/OpenAI API keys, Google API keys, and Solana private keys. If an agent accidentally includes `sk-ant-...` in a tool argument, the request is blocked before it leaves the gateway.

**Tool-level RBAC** — YAML-based allowlists and denylists control which MCP tools can be invoked. Block dangerous tools like `shell_exec` or `delete_all`, or restrict to a known-safe set for production deployments.

**Deny patterns** — Block content containing SQL injection patterns (`DROP TABLE`), dangerous shell commands (`sudo rm -rf /`), or XSS payloads.

### How it works

```
Client → agentgateway → mcp-guardrails (webhook) → agentgateway → MCP Server
```

agentgateway's webhook guardrails policy forwards every prompt and response to the guardrails server. The server validates the content against the policy file and returns pass/reject decisions using the standard agentgateway webhook protocol.

### Architecture decisions

- **Rust** for zero-cost abstractions and minimal latency in the request path
- **Stateless** design for horizontal scaling — deploy multiple replicas behind a load balancer
- **YAML policy** for human-readable, git-versionable security configuration
- **Structured JSON logging** via tracing for compliance audit trails

## Results

12 passing tests covering policy RBAC logic and credential scanner accuracy across all 15+ secret patterns. The server adds sub-millisecond latency to the MCP request path.

## Demo

[GitHub Repository](https://github.com/ExpertVagabond/mcp-guardrails-gateway)

## Built for MCP_HACK//26

Track 2: Secure & Govern MCP. Deeply integrates with agentgateway's webhook guardrails policy mechanism.
