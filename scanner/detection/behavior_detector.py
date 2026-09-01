import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


DENIAL_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60


def load_audit_events(
    log_file: str
) -> list[dict]:

    path = Path(log_file)

    if not path.exists():
        return []

    events = []

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:
                continue

    return events


def detect_privilege_escalation(
    events: list[dict]
) -> list[dict]:

    denied_by_agent = defaultdict(list)

    # --------------------------------------
    # Collect denied authorization events
    # --------------------------------------

    for event in events:

        if event.get("result") != "DENIED":
            continue

        agent = event.get(
            "agent",
            "unknown"
        )

        timestamp = event.get(
            "timestamp"
        )

        if not timestamp:
            continue

        try:

            event_time = datetime.fromisoformat(
                timestamp
            )

        except ValueError:

            continue

        denied_by_agent[
            agent
        ].append(
            {
                "event": event,
                "timestamp": event_time
            }
        )

    alerts = []

    # --------------------------------------
    # Analyze each NHI
    # --------------------------------------

    for agent, denied_events in denied_by_agent.items():

        denied_events.sort(
            key=lambda item: item["timestamp"]
        )

        for index in range(
            len(denied_events)
        ):

            start_time = denied_events[
                index
            ]["timestamp"]

            window_end = (
                start_time
                + timedelta(
                    seconds=TIME_WINDOW_SECONDS
                )
            )

            window_events = [
                item
                for item in denied_events[
                    index:
                ]
                if item["timestamp"]
                <= window_end
            ]

            if len(window_events) >= DENIAL_THRESHOLD:

                permissions = [
                    item["event"].get(
                        "permission",
                        "unknown"
                    )
                    for item in window_events
                ]

                alerts.append(
                    {
                        "alert_type":
                            "PRIVILEGE_ESCALATION",

                        "severity":
                            "HIGH",

                        "agent":
                            agent,

                        "denied_requests":
                            len(window_events),

                        "time_window_seconds":
                            TIME_WINDOW_SECONDS,

                        "permissions":
                            permissions,

                        "message":
                            (
                                f"NHI '{agent}' generated "
                                f"{len(window_events)} denied "
                                "authorization requests "
                                f"within "
                                f"{TIME_WINDOW_SECONDS} seconds."
                            )
                    }
                )

                # Avoid generating duplicate
                # alerts for the same window.
                break

    return alerts