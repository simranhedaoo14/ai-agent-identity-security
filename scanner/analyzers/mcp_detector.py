from pathlib import Path
import yaml

from scanner.analyzers.nhi_model import MCPServer


def detect_mcp_config(file_path: Path):
    servers = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            data = yaml.safe_load(file)

    except Exception:
        return servers

    if not isinstance(data, dict):
        return servers

    mcp_servers = data.get("mcp_servers")

    if not isinstance(mcp_servers, dict):
        return servers

    for server_name, server_config in mcp_servers.items():

        if not isinstance(server_config, dict):
            continue

        permissions = server_config.get(
            "permissions",
            []
        )

        if not isinstance(permissions, list):
            permissions = []

        allowed_agents = server_config.get(
            "allowed_agents",
            []
        )

        if not isinstance(allowed_agents, list):
            allowed_agents = []

        server = {
            "server": MCPServer(
                name=server_name,
                permissions=permissions
            ),
            "allowed_agents": allowed_agents,
            "file": str(file_path)
        }

        servers.append(server)

    return servers