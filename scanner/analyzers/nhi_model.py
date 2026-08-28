from pydantic import BaseModel, Field
from typing import List


class Tool(BaseModel):
    name: str
    permissions: List[str] = Field(default_factory=list)


class Credential(BaseModel):
    name: str
    provider: str
    identity_type: str
    file_path: str
    line_number: int


class NHIProfile(BaseModel):
    name: str
    identity_type: str
    role: str

    credential_references: List[str] = Field(default_factory=list)
    credentials: List[Credential] = Field(default_factory=list)
    tools: List[Tool] = Field(default_factory=list)

    risk_score: int = 0