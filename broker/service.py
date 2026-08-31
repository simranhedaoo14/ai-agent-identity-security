import json
from datetime import datetime, timedelta
from uuid import uuid4

from broker.models import (
    AccessRequest,
    AccessGrant
)

from broker.audit import log_event
from broker.token_service import TokenService
from broker.revocation import RevocationStore

class JITAccessBroker:

    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.token_service = TokenService()
        self.revocation_store = RevocationStore()

        self.redis = self.revocation_store.redis
        self.active_grants = {}

    def request_access(
        self,
        request: AccessRequest
    ):

        # ----------------------------------
        # Authorization check
        # ----------------------------------

        allowed = self.policy_engine.is_allowed(
            request.role,
            request.permission
        )

        if not allowed:

            log_event(
                event_type="ACCESS_REQUEST",
                agent_name=request.agent_name,
                permission=request.permission,
                task_id=request.task_id,
                result="DENIED",
                reason="RBAC policy denied permission"
            )

            return None

        # ----------------------------------
        # Create temporary grant
        # ----------------------------------

        now = datetime.utcnow()

        expires_at = (
            now +
            timedelta(
                minutes=request.duration_minutes
            )
        )

        grant_id = str(uuid4())

        token, token_expires_at = (
            self.token_service.issue_token(
                agent_name=request.agent_name,
                permission=request.permission,
                task_id=request.task_id,
                grant_id=grant_id,
                duration_minutes=request.duration_minutes
            )
        )

        grant = AccessGrant(
            grant_id=grant_id,
            agent_name=request.agent_name,
            permission=request.permission,
            task_id=request.task_id,
            issued_at=now.isoformat(),
            expires_at=token_expires_at.isoformat(),
            token=token
        )

        self.redis.set(
            f"grant:{grant_id}",
            grant.model_dump_json(),
            ex=(
                request.duration_minutes * 60
            )
        )

        self.active_grants[grant_id] = grant

        log_event(
            event_type="ACCESS_GRANT",
            agent_name=request.agent_name,
            permission=request.permission,
            task_id=request.task_id,
            result="GRANTED",
            reason="RBAC policy allowed permission"
        )

        return grant

    def revoke_access(
        self,
        grant_id: str
    ) -> bool:

        grant = self.active_grants.get(
            grant_id
        )

        if not grant:
            return False

        grant.status = "revoked"

        self.redis.set(
            f"grant:{grant_id}",
            grant.model_dump_json()
        )

        self.revocation_store.revoke(
            grant_id
        )

        log_event(
            event_type="ACCESS_REVOKE",
            agent_name=grant.agent_name,
            permission=grant.permission,
            task_id=grant.task_id,
            result="REVOKED",
            reason="Grant manually revoked"
        )

        return True


    def authorize_token(
        self,
        token: str
    ) -> bool:

        try:
            payload = self.token_service.validate_token(
                token
            )

        except Exception:
            return False

        grant_id = payload.get("grant_id")

        if not grant_id:
            return False

        # Check centralized revocation state
        if self.revocation_store.is_revoked(
            grant_id
        ):
            return False

        # Check centralized grant state
        grant_data = self.redis.get(
            f"grant:{grant_id}"
        )

        if not grant_data:
            return False

        grant = AccessGrant.model_validate_json(
            grant_data
        )

        if grant.status != "active":
            return False

        return True