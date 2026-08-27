from pathlib import Path

from scanner.analyzers.secret_detector import scan_file


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

    print(f"Scan complete. Findings: {total_findings}")


if __name__ == "__main__":
    scan_directory("test-target")