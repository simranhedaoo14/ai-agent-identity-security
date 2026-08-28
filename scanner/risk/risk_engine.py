from scanner.analyzers.nhi_model import NHIProfile


def calculate_credential_risk(agent: NHIProfile) -> int:
    """
    Calculate risk associated with credentials assigned to an NHI.

    Maximum score: 25
    """

    if not agent.credentials:
        return 0

    score = 0

    for credential in agent.credentials:

        # Current scanner cannot determine credential
        # expiration, so we treat lifetime as unknown.
        score += 10

        # Cloud/service credentials generally have
        # greater potential blast radius.
        if credential.provider in ["AWS", "GitHub"]:
            score += 5

    return min(score, 25)


def calculate_privilege_risk(agent: NHIProfile) -> int:
    """
    Calculate the risk associated with permissions.

    Maximum score: 30
    """

    permissions = []

    for tool in agent.tools:
        permissions.extend(tool.permissions)

    if not permissions:
        return 0

    # Administrative or destructive permissions
    if any(
        "admin" in permission.lower()
        or "delete" in permission.lower()
        for permission in permissions
    ):
        return 30

    # Write access
    if any(
        ":write" in permission.lower()
        for permission in permissions
    ):
        return 18

    # Sensitive resources
    sensitive_keywords = [
        "customer",
        "payment",
        "credential",
        "secret",
        "user"
    ]

    if any(
        keyword in permission.lower()
        for permission in permissions
        for keyword in sensitive_keywords
    ):
        return 24

    # Read-only access
    return 8


def calculate_exposure_risk(agent: NHIProfile) -> int:
    """
    Calculate credential exposure risk.

    Maximum score: 20

    Currently credentials detected in repository files
    receive a repository-exposure score.
    """

    if not agent.credentials:
        return 0

    return 15


def calculate_blast_radius(agent: NHIProfile) -> int:
    """
    Estimate how much of the system the NHI can affect.

    Maximum score: 25.
    """

    tool_count = len(agent.tools)

    permission_count = sum(
        len(tool.permissions)
        for tool in agent.tools
    )

    score = 0

    # Number of tools
    score += min(tool_count * 4, 10)

    # Number of permissions
    score += min(permission_count * 2, 10)

    # Multiple credentials increase potential reach
    if len(agent.credentials) > 1:
        score += 5

    return min(score, 25)


def calculate_risk(agent: NHIProfile) -> dict:
    """
    Calculate the complete NHI risk assessment.
    """

    credential_risk = calculate_credential_risk(agent)
    privilege_risk = calculate_privilege_risk(agent)
    exposure_risk = calculate_exposure_risk(agent)
    blast_radius = calculate_blast_radius(agent)

    total_score = (
        credential_risk
        + privilege_risk
        + exposure_risk
        + blast_radius
    )

    total_score = min(total_score, 100)

    if total_score >= 75:
        severity = "CRITICAL"

    elif total_score >= 50:
        severity = "HIGH"

    elif total_score >= 25:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "credential_risk": credential_risk,
        "privilege_risk": privilege_risk,
        "exposure_risk": exposure_risk,
        "blast_radius": blast_radius,
        "total_score": total_score,
        "severity": severity
    }