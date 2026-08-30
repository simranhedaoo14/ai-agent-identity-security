from datetime import datetime


def log_event(
    event_type: str,
    agent_name: str,
    permission: str,
    task_id: str,
    result: str,
    reason: str
):

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "agent": agent_name,
        "permission": permission,
        "task_id": task_id,
        "result": result,
        "reason": reason
    }

    print(
        "[AUDIT]",
        event
    )

    return event