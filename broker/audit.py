import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests


AUDIT_LOG_FILE = Path("logs/audit.jsonl")

SPLUNK_HEC_URL = os.getenv(
    "SPLUNK_HEC_URL",
    ""
)

SPLUNK_HEC_TOKEN = os.getenv(
    "SPLUNK_HEC_TOKEN",
    ""
)


def log_event(
    event_type: str,
    agent_name: str,
    permission: str,
    task_id: str,
    result: str,
    reason: str,
    grant_id: str | None = None
):

    event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "event_type": event_type,

        "agent": agent_name,

        "permission": permission,

        "task_id": task_id,

        "result": result,

        "reason": reason
    }

    if grant_id:
        event["grant_id"] = grant_id

    # ----------------------------------
    # Local JSONL logging
    # ----------------------------------

    AUDIT_LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        AUDIT_LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(event) + "\n"
        )

    # ----------------------------------
    # Console logging
    # ----------------------------------

    print(
        "[AUDIT]",
        json.dumps(event)
    )

    # ----------------------------------
    # Optional Splunk HEC
    # ----------------------------------

    if SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN:

        try:

            response = requests.post(
                SPLUNK_HEC_URL,
                headers={
                    "Authorization":
                        f"Splunk {SPLUNK_HEC_TOKEN}",
                    "Content-Type":
                        "application/json"
                },
                json={
                    "event": event
                },
                timeout=3,
                verify=False
            )

            if response.status_code >= 300:

                print(
                    "[AUDIT] Splunk rejected event:",
                    response.status_code,
                    response.text
                )

        except requests.RequestException as error:

            print(
                "[AUDIT] Splunk unavailable:",
                error
            )

    return event