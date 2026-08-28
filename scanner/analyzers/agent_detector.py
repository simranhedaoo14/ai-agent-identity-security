from pathlib import Path
import yaml

from scanner.analyzers.nhi_model import NHIProfile, Tool


def detect_agent_config(file_path: Path):
    profiles = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

    except Exception:
        return profiles

    if not isinstance(data, dict):
        return profiles

    agent = data.get("agent")

    if not isinstance(agent, dict):
        return profiles

    agent_name = agent.get("name", "unknown-agent")
    agent_type = agent.get("type", "unknown")
    role = agent.get("role", "unknown")

    credential_references = agent.get("credentials", [])

    if not isinstance(credential_references, list):
        credential_references = []

    if not isinstance(credential_references, list):
        credential_references = []

    tools = []

    for tool in agent.get("tools", []):

        if not isinstance(tool, dict):
            continue

        permissions = tool.get("permissions", [])

        if not isinstance(permissions, list):
            permissions = []

        tools.append(
            Tool(
                name=tool.get("name", "unknown-tool"),
                permissions=permissions
            )
        )

    profile = NHIProfile(
        name=agent_name,
        identity_type=agent_type,
        role=role,
        credential_references=credential_references,
        tools=tools
    )

    profiles.append(profile)

    return profiles