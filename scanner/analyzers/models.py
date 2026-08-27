from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    identity_type: str
    provider: Optional[str] = None
    file_path: str
    line_number: int
    description: str

    credential_risk: int = 0
    privilege_risk: int = 0
    exposure_risk: int = 0
    blast_radius: int = 0

    risk_score: int = 0