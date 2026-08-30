from pathlib import Path
import yaml


class RBACPolicyEngine:

    def __init__(self, policy_file: str):
        self.policy_file = Path(policy_file)
        self.roles = self._load_policy()

    def _load_policy(self):
        try:
            with open(
                self.policy_file,
                "r",
                encoding="utf-8"
            ) as file:
                data = yaml.safe_load(file)

        except Exception as error:
            raise RuntimeError(
                f"Failed to load RBAC policy: {error}"
            )

        if not isinstance(data, dict):
            return {}

        return data.get("roles", {})

    def get_role_permissions(
        self,
        role: str
    ) -> list[str]:

        role_config = self.roles.get(role)

        if not role_config:
            return []

        permissions = role_config.get(
            "permissions",
            []
        )

        return permissions

    def is_allowed(
        self,
        role: str,
        permission: str
    ) -> bool:

        allowed_permissions = (
            self.get_role_permissions(role)
        )

        return permission in allowed_permissions