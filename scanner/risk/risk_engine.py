from scanner.analyzers.nhi_model import NHIProfile


def calculate_privilege_risk(agent: NHIProfile) -> int:
    permissions = []

    for tool in agent.tools:
        permissions.extend(tool.permissions)

    if not permissions:
        return 0

    if any("admin" in permission or "delete" in permission
           for permission in permissions):
        return 30

    if any(":write" in permission for permission in permissions):
        return 18

    if any(
        keyword in permission
        for permission in permissions
        for keyword in ["customer", "payment", "credential"]
    ):
        return 24

    return 8


def calculate_blast_radius(agent: NHIProfile) -> int:
    tool_count = len(agent.tools)

    permission_count = sum(
        len(tool.permissions)
        for tool in agent.tools
    )

    score = 0

    score += min(tool_count * 4, 10)
    score += min(permission_count * 3, 10)

    if permission_count >= 5:
        score += 5

    return min(score, 25)


def calculate_risk(agent: NHIProfile) -> int:
    credential_risk = 0
    privilege_risk = calculate_privilege_risk(agent)
    exposure_risk = 10
    blast_radius = calculate_blast_radius(agent)

    total = (
        credential_risk
        + privilege_risk
        + exposure_risk
        + blast_radius
    )

    return min(total, 100)


if __name__ == "__main__":
    from pathlib import Path
    from scanner.analyzers.agent_detector import detect_agent_config

    agents = detect_agent_config(
        Path("test-target/agent_config.yaml")
    )

    for agent in agents:
        score = calculate_risk(agent)

        print(f"Agent: {agent.name}")
        print(f"Risk Score: {score}/100")