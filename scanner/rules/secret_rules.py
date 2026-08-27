import re


SECRET_RULES = {
    "openai_api_key": {
        "pattern": re.compile(r'(?i)(sk-[a-zA-Z0-9_-]{20,})'),
        "identity_type": "API Key",
        "provider": "OpenAI",
        "description": "Potential hardcoded OpenAI API key",
    },

    "github_token": {
        "pattern": re.compile(r'(?i)(gh[pousr]_[a-zA-Z0-9]{20,})'),
        "identity_type": "API Token",
        "provider": "GitHub",
        "description": "Potential hardcoded GitHub token",
    },

    "aws_access_key": {
        "pattern": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "identity_type": "Cloud Credential",
        "provider": "AWS",
        "description": "Potential hardcoded AWS access key",
    },

    "generic_secret": {
        "pattern": re.compile(
            r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)'
            r'\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'
        ),
        "identity_type": "Secret",
        "provider": "Unknown",
        "description": "Potential hardcoded secret",
    },
}