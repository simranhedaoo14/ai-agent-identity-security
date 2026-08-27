from pathlib import Path

from scanner.analyzers.secret_detector import scan_file
from scanner.analyzers.agent_detector import detect_agent_config
from scanner.analyzers.mcp_detector import detect_mcp_config


def scan_directory(directory: str):
    path = Path(directory)

    if not path.exists():
        print(f"Directory does not exist: {directory}")
        return

    print(f"Scanning: {path.resolve()}\n")

    total_findings = 0

    for file in path.rglob("*"):

        if not file.is_file():
            continue

        # -------------------------
        # Secret / Credential Scan
        # -------------------------
        findings = scan_file(file)

        for finding in findings:
            total_findings += 1

            print(
                f"[FOUND] {finding.provider} "
                f"{finding.identity_type}"
            )

            print(f"  File: {finding.file_path}")
            print(f"  Line: {finding.line_number}")
            print(f"  {finding.description}")
            print()

        # -------------------------
        # AI Agent & MCP Detection
        # -------------------------
        if file.suffix.lower() in [".yaml", ".yml"]:

            # AI Agent Detection
            agents = detect_agent_config(file)

            for agent in agents:
                total_findings += 1

                print("[FOUND] AI Agent")
                print(f"  Name: {agent['name']}")
                print(f"  Type: {agent['agent_type']}")
                print(f"  File: {agent['file']}")
                print()

            # MCP Server Detection
            mcp_servers = detect_mcp_config(file)

            for server in mcp_servers:
                total_findings += 1

                print("[FOUND] MCP Server")
                print(f"  Name: {server['name']}")
                print(f"  Permissions: {server['permissions']}")
                print(f"  File: {server['file']}")
                print()

    print("--------------------------------")
    print(f"Scan complete. Findings: {total_findings}")


if __name__ == "__main__":
    scan_directory("test-target")