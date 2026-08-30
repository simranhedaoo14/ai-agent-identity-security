from scanner.policy.rbac_engine import RBACPolicyEngine


engine = RBACPolicyEngine(
    "config/rbac.yaml"
)


tests = [
    (
        "support-agent",
        "ticket:read"
    ),
    (
        "support-agent",
        "customer:write"
    ),
    (
        "research-agent",
        "document:read"
    ),
    (
        "research-agent",
        "ticket:write"
    ),
    (
        "admin-agent",
        "customer:write"
    ),
]


for role, permission in tests:

    result = engine.is_allowed(
        role,
        permission
    )

    status = "ALLOW" if result else "DENY"

    print(
        f"{role:20} "
        f"{permission:20} "
        f"{status}"
    )