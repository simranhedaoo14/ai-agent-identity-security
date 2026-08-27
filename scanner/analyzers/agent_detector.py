from pathlib import Path
import yaml


def detect_agent_config(file_path: Path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    agent = data.get("agent")

    if isinstance(agent, dict):

        agent_name = agent.get("name", "unknown-agent")
        agent_type = agent.get("type", "unknown")

        findings.append({
            "type": "AI Agent",
            "name": agent_name,
            "agent_type": agent_type,
            "file": str(file_path)
        })

    return findings