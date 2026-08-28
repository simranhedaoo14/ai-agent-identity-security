RESOURCE_SENSITIVITY = {
    "search": 1,
    "web": 1,

    "document": 2,

    "ticket": 3,

    "customer": 4,

    "payment": 5,
    "credential": 5,
    "secret": 5,
    "user": 5,
    "admin": 5,
}


SENSITIVITY_LABELS = {
    1: "PUBLIC",
    2: "INTERNAL",
    3: "CONFIDENTIAL",
    4: "SENSITIVE",
    5: "CRITICAL",
}


def get_resource_sensitivity(permission: str) -> int:
    """
    Determine the sensitivity of a resource
    based on the permission string.

    Example:
        customer:read → 4
        document:read → 2
        search:read → 1
    """

    resource = permission.split(":")[0].lower()

    return RESOURCE_SENSITIVITY.get(
        resource,
        2
    )


def get_sensitivity_label(permission: str) -> str:
    score = get_resource_sensitivity(permission)

    return SENSITIVITY_LABELS[score]