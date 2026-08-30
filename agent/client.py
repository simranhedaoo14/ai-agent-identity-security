import requests


BROKER_URL = "http://127.0.0.1:8001"
API_URL = "http://127.0.0.1:8000"


def request_access(
    agent_name: str,
    role: str,
    permission: str,
    task_id: str,
    duration_minutes: int = 5
):

    response = requests.post(
        f"{BROKER_URL}/access/request",
        json={
            "agent_name": agent_name,
            "role": role,
            "permission": permission,
            "task_id": task_id,
            "duration_minutes": duration_minutes
        }
    )

    return response


def call_ticket_api(
    token: str,
    ticket_id: str
):

    response = requests.get(
        f"{API_URL}/tickets/{ticket_id}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    return response


if __name__ == "__main__":

    print("AI Agent Simulator")
    print("=" * 40)

    response = request_access(
        agent_name="customer-support-agent",
        role="support-agent",
        permission="ticket:read",
        task_id="ticket-123"
    )

    print("\nAccess Request:")
    print(response.status_code)
    print(response.text)

# --------------------------------------
# Adversarial Test: Privilege Escalation
# --------------------------------------

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