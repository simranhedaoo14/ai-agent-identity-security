from fastapi import FastAPI, HTTPException

from broker.models import AccessRequest
from broker.service import JITAccessBroker

from scanner.policy.rbac_engine import (
    RBACPolicyEngine
)


app = FastAPI(
    title="AI Agent JIT Access Broker",
    version="1.0.0"
)


# --------------------------------------
# IAM Components
# --------------------------------------

policy_engine = RBACPolicyEngine(
    "config/rbac.yaml"
)

broker = JITAccessBroker(
    policy_engine
)


# --------------------------------------
# Request Access
# --------------------------------------

@app.post("/access/request")
def request_access(
    request: AccessRequest
):

    grant = broker.request_access(
        request
    )

    if not grant:

        raise HTTPException(
            status_code=403,
            detail="Access denied by RBAC policy"
        )

    return grant


# --------------------------------------
# Revoke Access
# --------------------------------------

@app.post("/access/revoke/{grant_id}")
def revoke_access(
    grant_id: str
):

    success = broker.revoke_access(
        grant_id
    )

    if not success:

        raise HTTPException(
            status_code=404,
            detail="Grant not found"
        )

    return {
        "grant_id": grant_id,
        "status": "revoked"
    }