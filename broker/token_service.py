from datetime import datetime, timedelta, timezone
import os
import jwt


class TokenService:

    def __init__(self):
        self.secret_key = os.getenv(
            "JWT_SECRET",
            "development-secret-change-me"
        )

        self.algorithm = "HS256"

    def issue_token(
        self,
        agent_name: str,
        permission: str,
        task_id: str,
        grant_id: str,
        duration_minutes: int
    ) -> tuple[str, datetime]:

        now = datetime.now(timezone.utc)

        expires_at = (
            now +
            timedelta(minutes=duration_minutes)
        )

        payload = {
            "sub": agent_name,
            "scope": permission,
            "task_id": task_id,
            "grant_id": grant_id,
            "iat": now,
            "exp": expires_at
        }

        token = jwt.encode(
            payload,
            self.secret_key,
            algorithm=self.algorithm
        )

        return token, expires_at

    def validate_token(
        self,
        token: str
    ) -> dict:

        payload = jwt.decode(
            token,
            self.secret_key,
            algorithms=[self.algorithm]
        )

        return payload