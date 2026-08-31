from fastapi import FastAPI, Header, HTTPException

from scanner.policy.rbac_engine import RBACPolicyEngine
from broker.service import JITAccessBroker


app = FastAPI(
    title="AI Agent Protected API",
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
# Token Authorization Helper
# --------------------------------------

def require_permission(
    authorization: str,
    required_permission: str
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )

    if not authorization.startswith(
        "Bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format"
        )

    token = authorization.split(
        " ",
        1
    )[1]

    try:
        payload = broker.token_service.validate_token(
            token
        )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    # ----------------------------------
    # Check revocation
    # ----------------------------------

    if not broker.authorize_token(token):
        raise HTTPException(
            status_code=401,
            detail="Token revoked or inactive"
        )

    # ----------------------------------
    # Check scope
    # ----------------------------------

    token_scope = payload.get("scope")

    if token_scope != required_permission:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Token does not grant "
                f"{required_permission}"
            )
        )

    return payload


# --------------------------------------
# Ticket API
# --------------------------------------

@app.get("/tickets/{ticket_id}")
def get_ticket(
    ticket_id: str,
    authorization: str = Header(default="")
):

    payload = require_permission(
        authorization,
        "ticket:read"
    )

    return {
        "message": "Ticket access granted",
        "ticket_id": ticket_id,
        "agent": payload["sub"],
        "task_id": payload["task_id"]
    }


# --------------------------------------
# Customer Read API
# --------------------------------------

@app.get("/customers/{customer_id}")
def get_customer(
    customer_id: str,
    authorization: str = Header(default="")
):

    payload = require_permission(
        authorization,
        "customer:read"
    )

    return {
        "message": "Customer access granted",
        "customer_id": customer_id,
        "agent": payload["sub"],
        "task_id": payload["task_id"]
    }


# --------------------------------------
# Customer Write API
# --------------------------------------

@app.post("/customers/{customer_id}")
def update_customer(
    customer_id: str,
    authorization: str = Header(default="")
):

    payload = require_permission(
        authorization,
        "customer:write"
    )

    return {
        "message": "Customer update granted",
        "customer_id": customer_id,
        "agent": payload["sub"],
        "task_id": payload["task_id"]
    }