from scanner.policy.rbac_engine import (
    RBACPolicyEngine
)

from broker.models import AccessRequest

from broker.service import (
    JITAccessBroker
)


# --------------------------------------
# Setup
# --------------------------------------

policy_engine = RBACPolicyEngine(
    "config/rbac.yaml"
)

broker = JITAccessBroker(
    policy_engine
)


# --------------------------------------
# Request legitimate access
# --------------------------------------

request = AccessRequest(
    agent_name="customer-support-agent",
    role="support-agent",
    permission="ticket:read",
    task_id="ticket-123",
    duration_minutes=5
)

grant = broker.request_access(
    request
)

print("\n1. ACCESS GRANTED")
print(
    f"Grant ID: {grant.grant_id}"
)


# --------------------------------------
# Validate token
# --------------------------------------

authorized = broker.authorize_token(
    grant.token
)

print("\n2. TOKEN VALIDATION")
print(
    f"Authorized: {authorized}"
)


# --------------------------------------
# Revoke access
# --------------------------------------

revoked = broker.revoke_access(
    grant.grant_id
)

print("\n3. TOKEN REVOKED")
print(
    f"Revocation successful: {revoked}"
)


# --------------------------------------
# Try using revoked token
# --------------------------------------

authorized_after_revoke = (
    broker.authorize_token(
        grant.token
    )
)

print("\n4. REUSE REVOKED TOKEN")
print(
    f"Authorized: {authorized_after_revoke}"
)