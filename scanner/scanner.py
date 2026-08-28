from pathlib import Path

from scanner.analyzers.secret_detector import scan_file
from scanner.analyzers.agent_detector import detect_agent_config
from scanner.analyzers.mcp_detector import detect_mcp_config
from scanner.analyzers.nhi_correlator import correlate_credentials


def scan_directory(directory: str):
    path = Path(directory)

    if not path.exists():
        print(f"Directory does not exist: {directory}")
        return

    print(f"Scanning: {path.resolve()}\n")

    total_findings = 0
    credential_findings = []
    nhi_profiles = []

    # ==========================================
    # Phase 1: Scan repository
    # ==========================================

    for file in path.rglob("*"):

        if not file.is_file():
            continue

        # --------------------------------------
        # Secret / Credential Detection
        # --------------------------------------

        findings = scan_file(file)

        for finding in findings:
            total_findings += 1
            credential_findings.append(finding)

            print(
                f"[FOUND] {finding.provider} "
                f"{finding.identity_type}"
            )

            print(f"  File: {finding.file_path}")
            print(f"  Line: {finding.line_number}")
            print(f"  {finding.description}")
            print()

        # --------------------------------------
        # AI Agent + MCP Detection
        # --------------------------------------

        if file.suffix.lower() in [".yaml", ".yml"]:

            # AI Agent Detection
            agents = detect_agent_config(file)

            for agent in agents:
                total_findings += 1
                nhi_profiles.append(agent)

                print("[FOUND] NHI")
                print(f"  Name: {agent.name}")
                print(f"  Type: {agent.identity_type}")
                print(f"  Role: {agent.role}")

                if agent.credential_references:
                    print(
                        f"  Credential References: "
                        f"{agent.credential_references}"
                    )

                if agent.tools:
                    print("  Tools:")

                    for tool in agent.tools:
                        print(
                            f"    - {tool.name}: "
                            f"{tool.permissions}"
                        )

                print()

            # MCP Detection
            mcp_servers = detect_mcp_config(file)

            for server in mcp_servers:
                total_findings += 1

                print("[FOUND] MCP Server")
                print(f"  Name: {server['name']}")
                print(
                    f"  Permissions: "
                    f"{server['permissions']}"
                )
                print(f"  File: {server['file']}")
                print()

    # ==========================================
    # Phase 2: Correlate credentials with NHIs
    # ==========================================

    nhi_profiles = correlate_credentials(
        nhi_profiles,
        credential_findings
    )

    # ==========================================
    # Phase 3: Display NHI Profiles
    # ==========================================

    print("=" * 50)
    print("NHI IDENTITY PROFILES")
    print("=" * 50)
    print()

    for profile in nhi_profiles:

        print(f"Identity: {profile.name}")
        print(f"Role: {profile.role}")

        if profile.credentials:
            print("Credentials:")

            for credential in profile.credentials:
                print(
                    f"  - {credential.name} "
                    f"({credential.provider})"
                )

                print(
                    f"    Location: "
                    f"{credential.file_path}:"
                    f"{credential.line_number}"
                )

        else:
            print("Credentials: None correlated")

        print("Tools:")

        for tool in profile.tools:
            print(
                f"  - {tool.name}: "
                f"{tool.permissions}"
            )

        print()
        
    # ==========================================
    # Final Summary
    # ==========================================

    print("-" * 50)
    print(f"Scan complete. Findings: {total_findings}")
    print(f"NHIs discovered: {len(nhi_profiles)}")
    print("-" * 50)


if __name__ == "__main__":
    scan_directory("test-target")