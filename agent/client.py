import requests


BROKER_URL = "http://127.0.0.1:8001"
API_URL = "http://127.0.0.1:8002"


def request_access(
    agent_name: str,
    role: str,
    permission: str,
    task_id: str,
    duration_minutes: int = 5
):
    return requests.post(
        f"{BROKER_URL}/access/request",
        json={
            "agent_name": agent_name,
            "role": role,
            "permission": permission,
            "task_id": task_id,
            "duration_minutes": duration_minutes
        }
    )


def call_ticket_api(
    token: str,
    ticket_id: str
):
    return requests.get(
        f"{API_URL}/tickets/{ticket_id}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )


if __name__ == "__main__":

    print("AI Agent Simulator")
    print("=" * 40)

    # ======================================
    # 1. Legitimate JIT Access Request
    # ======================================

    response = request_access(
        agent_name="customer-support-agent",
        role="support-agent",
        permission="ticket:read",
        task_id="ticket-123"
    )

    print("\nAccess Request:")
    print(response.status_code)

    if response.status_code != 200:
        print(response.text)
        exit()

    grant = response.json()

    token = grant["token"]

    print("JIT access granted.")

    print(
        f"Grant ID: {grant['grant_id']}"
    )

    print(
        f"Expires: {grant['expires_at']}"
    )

    # ======================================
    # 2. Legitimate API Request
    # ======================================

    api_response = call_ticket_api(
        token,
        "ticket-123"
    )

    print("\nProtected API:")
    print(api_response.status_code)
    print(api_response.text)

    # ======================================
    # 3. Privilege Escalation Test
    # ======================================

    print("\n" + "=" * 40)
    print("ADVERSARIAL TEST")
    print("=" * 40)

    malicious_response = request_access(
        agent_name="customer-support-agent",
        role="support-agent",
        permission="customer:write",
        task_id="ticket-123"
    )

    print("\nPrivilege Escalation Attempt:")

    print(
        f"Status Code: "
        f"{malicious_response.status_code}"
    )

    print(
        f"Response: "
        f"{malicious_response.text}"
    )

    # ======================================
    # 4. Token Scope Abuse Test
    # ======================================

    print("\n" + "=" * 40)
    print("TOKEN SCOPE ABUSE TEST")
    print("=" * 40)

    scope_abuse_response = requests.post(
        f"{API_URL}/customers/123",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    print("\nUsing ticket:read token")

    print(
        "Attempting customer:write operation"
    )

    print(
        f"Status Code: "
        f"{scope_abuse_response.status_code}"
    )

    print(
        f"Response: "
        f"{scope_abuse_response.text}"
    )

    # ======================================
    # 5. Repeated Privilege Escalation Test
    # ======================================

    print("\n" + "=" * 40)
    print("REPEATED PRIVILEGE ESCALATION TEST")
    print("=" * 40)

    attack_permissions = [
        "customer:write",
        "user:write",
        "admin:write"
    ]

    for permission in attack_permissions:

        attack_response = request_access(
            agent_name="customer-support-agent",
            role="support-agent",
            permission=permission,
            task_id="ticket-123"
        )

        print(
            f"\n{permission}: "
            f"{attack_response.status_code}"
        )

        print(
            f"Response: "
            f"{attack_response.text}"
        )

    # ======================================
    # 6. Real-Time Revocation Test
    # ======================================

    print("\n" + "=" * 40)
    print("REAL-TIME REVOCATION TEST")
    print("=" * 40)

    # --------------------------------------
    # Verify token works before revocation
    # --------------------------------------

    before_revoke = call_ticket_api(
        token,
        "ticket-123"
    )

    print("\nBefore revocation:")

    print(
        f"Status Code: "
        f"{before_revoke.status_code}"
    )

    print(
        f"Response: "
        f"{before_revoke.text}"
    )

    # --------------------------------------
    # Revoke the grant
    # --------------------------------------

    revoke_response = requests.post(
        f"{BROKER_URL}/access/revoke/"
        f"{grant['grant_id']}"
    )

    print("\nRevoking grant:")

    print(
        f"Status Code: "
        f"{revoke_response.status_code}"
    )

    print(
        f"Response: "
        f"{revoke_response.text}"
    )

    # --------------------------------------
    # Try using same JWT after revocation
    # --------------------------------------

    after_revoke = call_ticket_api(
        token,
        "ticket-123"
    )

    print("\nAfter revocation:")

    print(
        f"Status Code: "
        f"{after_revoke.status_code}"
    )

    print(
        f"Response: "
        f"{after_revoke.text}"
    )