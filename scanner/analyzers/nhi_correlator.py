from scanner.analyzers.nhi_model import NHIProfile, Credential


def correlate_credentials(
    profiles: list[NHIProfile],
    credential_findings
) -> list[NHIProfile]:

    credential_map = {}

    for finding in credential_findings:

        # Use the credential name from the environment variable
        # when available. Otherwise fall back to provider/type.
        name = finding.metadata.get(
            "credential_name",
            f"{finding.provider}_{finding.identity_type}"
        )

        credential_map[name] = Credential(
            name=name,
            provider=finding.provider,
            identity_type=finding.identity_type,
            file_path=finding.file_path,
            line_number=finding.line_number
        )

    for profile in profiles:

        for reference in profile.credential_references:

            credential = credential_map.get(reference)

            if credential:
                profile.credentials.append(credential)

    return profiles