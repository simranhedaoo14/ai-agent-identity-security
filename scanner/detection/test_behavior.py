from scanner.detection.behavior_detector import (
    load_audit_events,
    detect_privilege_escalation
)


events = load_audit_events(
    "logs/audit.jsonl"
)

alerts = detect_privilege_escalation(
    events
)


print("\nBehavioral Detection")
print("=" * 50)

if not alerts:

    print(
        "No suspicious NHI behavior detected."
    )

else:

    for alert in alerts:

        print(
            f"[ALERT] "
            f"{alert['alert_type']}"
        )

        print(
            f"  Severity: "
            f"{alert['severity']}"
        )

        print(
            f"  Agent: "
            f"{alert['agent']}"
        )

        print(
            f"  Denied Requests: "
            f"{alert['denied_requests']}"
        )

        print(
            f"  Permissions: "
            f"{alert['permissions']}"
        )

        print(
            f"  {alert['message']}"
        )