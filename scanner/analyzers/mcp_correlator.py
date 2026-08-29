from scanner.analyzers.nhi_model import NHIProfile


def correlate_mcp_servers(
    profiles: list[NHIProfile],
    mcp_servers
) -> list[NHIProfile]:

    for server_data in mcp_servers:

        mcp_server = server_data["server"]
        allowed_agents = server_data["allowed_agents"]

        for profile in profiles:

            if profile.name in allowed_agents:

                # Avoid duplicate MCP assignments
                already_exists = any(
                    server.name == mcp_server.name
                    for server in profile.mcp_servers
                )

                if not already_exists:
                    profile.mcp_servers.append(
                        mcp_server
                    )

    return profiles