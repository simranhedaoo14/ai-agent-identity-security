from pathlib import Path

from scanner.analyzers.models import Finding
from scanner.rules.secret_rules import SECRET_RULES


def scan_file(file_path: Path) -> list[Finding]:
    findings = []

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except Exception:
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):

        matched = False

        for rule_name, rule in SECRET_RULES.items():

            match = rule["pattern"].search(line)

            if match:
                findings.append(
                    Finding(
                        identity_type=rule["identity_type"],
                        provider=rule["provider"],
                        file_path=str(file_path),
                        line_number=line_number,
                        description=rule["description"],
                    )
                )

                matched = True
                break

    return findings