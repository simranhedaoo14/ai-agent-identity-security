from pydantic import BaseModel, Field
from typing import Optional


class AccessRequest(BaseModel):
    agent_name: str
    role: str
    permission: str

    task_id: str

    duration_minutes: int = Field(
        default=5,
        ge=1,
        le=60
    )


class AccessGrant(BaseModel):
    grant_id: str

    agent_name: str
    permission: str

    task_id: str

    issued_at: str
    expires_at: str

    status: str = "active"

    token: Optional[str] = None