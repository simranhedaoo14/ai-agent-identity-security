# AI Agent Identity & JIT Access Security Platform

An AI security platform designed to secure **AI agents and other Non-Human Identities (NHIs)** through identity discovery, risk assessment, least-privilege authorization, and Just-In-Time (JIT) access control.

## Problem

AI agents increasingly interact with APIs, databases, files, MCP servers, and other enterprise resources. Using static, long-lived credentials for these agents creates significant security risks because a compromised credential or manipulated agent can inherit all of its permissions.

This project explores how **IAM principles can be applied to AI agents** by treating them as first-class identities with controlled, temporary, and auditable access.

## Security Lifecycle

**Discover → Assess → Authenticate → Authorize → Grant → Monitor → Revoke**

## Planned Capabilities

### NHI Inventory & Risk Scanner

* Detect hardcoded API keys, tokens, and service credentials
* Identify AI-agent and MCP configurations
* Analyze credential lifetime and permission scope
* Calculate identity risk and potential blast radius

### Identity & RBAC Policy Engine

* Assign identities to AI agents
* Define roles and permissions
* Enforce least-privilege access
* Prevent unauthorized privilege escalation

### Just-In-Time Access Broker

* Accept task-specific access requests from AI agents
* Validate identity and authorization policies
* Issue short-lived, scoped access tokens
* Track active grants
* Support early token revocation

### Protected Mock APIs

* Simulated ticketing, customer, document, and administrative services
* Enforce access policies on every request
* Provide a controlled environment for security testing

### Audit & Detection

* Record access requests, grants, denials, and revocations
* Detect unusual resource-access patterns
* Track identity risk changes
* Generate security alerts

### Adversarial Testing

The platform will include simulated compromised-agent scenarios such as:

* Privilege escalation attempts
* Unauthorized resource access
* Expired-token replay
* Revoked-token usage
* Excessive resource enumeration

## Technology Stack

* Python
* FastAPI
* LangChain
* PostgreSQL
* Redis
* Semgrep
* Streamlit
* Docker
* Pytest

## Project Status

Currently implementing the **NHI Inventory & Risk Scanner**.

### Completed

* Initial project structure
* Repository scanning
* API credential detection
* OpenAI API key detection
* GitHub token detection
* AWS access-key detection
* Duplicate finding prevention

### In Progress

* AI-agent configuration detection
* MCP configuration analysis
* NHI risk scoring
* Blast-radius calculation

## Architecture

The final architecture will connect NHI discovery and risk assessment with an identity-aware JIT access control system.

```text
NHI Scanner
     │
     ▼
Identity Inventory
     │
     ▼
Risk Assessment
     │
     ▼
Agent Identity
     │
     ▼
RBAC Policy Engine
     │
     ▼
JIT Access Broker
     │
     ▼
Short-Lived Access
     │
     ▼
Protected APIs
     │
     ▼
Audit + Detection
     │
     ▼
Revocation
```

## Security Focus

This project focuses on the intersection of:

* AI Security
* Identity & Access Management (IAM)
* Non-Human Identity (NHI) Security
* Least Privilege
* Just-In-Time Access
* Credential Security
* Authorization
* Security Monitoring
* Adversarial Testing
