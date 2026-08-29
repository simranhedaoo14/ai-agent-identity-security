from scanner.analyzers.nhi_model import NHIProfile

from scanner.risk.resource_sensitivity import (
    get_resource_sensitivity
)

def get_all_permissions(agent: NHIProfile) -> list[str]:
    """Return direct tool + MCP permissions for an NHI."""

    permissions = []

    # Direct agent tools
    for tool in agent.tools:
        permissions.extend(tool.permissions)

    # MCP server permissions
    for server in agent.mcp_servers:
        permissions.extend(server.permissions)

    return permissions


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

    permissions = get_all_permissions(agent)

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
    Calculate blast radius based on:
    - Number of tools
    - Number of permissions
    - Resource sensitivity
    - Write/admin capabilities

    Maximum score: 25
    """

    permissions = get_all_permissions(agent)

    if not permissions:
        return 0

    tool_count = len(agent.tools)

    permission_count = len(permissions)

    score = 0

    # --------------------------------------
    # Tool breadth
    # --------------------------------------

    score += min(tool_count * 3, 6)

    # --------------------------------------
    # Permission breadth
    # --------------------------------------

    score += min(permission_count * 2, 8)

    # --------------------------------------
    # Resource sensitivity
    # --------------------------------------

    sensitivity_scores = [
        get_resource_sensitivity(permission)
        for permission in permissions
    ]

    max_sensitivity = max(
        sensitivity_scores
    )

    if max_sensitivity == 5:
        score += 7

    elif max_sensitivity == 4:
        score += 5

    elif max_sensitivity == 3:
        score += 3

    else:
        score += 1

    # --------------------------------------
    # Write / destructive capabilities
    # --------------------------------------

    if any(
        ":write" in permission.lower()
        for permission in permissions
    ):
        score += 2

    if any(
        "delete" in permission.lower()
        or "admin" in permission.lower()
        for permission in permissions
    ):
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