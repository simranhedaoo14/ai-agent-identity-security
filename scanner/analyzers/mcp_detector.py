from pathlib import Path
import yaml


def detect_mcp_config(file_path: Path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    mcp_servers = data.get("mcp_servers")

    if not isinstance(mcp_servers, dict):
        return findings

    for server_name, server_config in mcp_servers.items():

        if not isinstance(server_config, dict):
            continue

        permissions = server_config.get("permissions", [])

        findings.append({
            "type": "MCP Server",
            "name": server_name,
            "permissions": permissions,
            "file": str(file_path)
        })

    return findings