
from windows_event_parser import parse_windows_events
from detection import detect_threats


def convert_windows_events(events):
    """Convert parsed Windows events into the existing detection format."""
    converted = []

    for event in events:
        event_id = event.get("event_id")

        if event_id not in (4624, 4625):
            continue

        # Ignore successful logons for now; they are useful context,
        # but should not independently trigger failed-login detection.
        if event_id == 4624:
            continue

        converted.append({
            "event_type": "LOGIN",
            "status": "FAILED",
            "source_ip": event.get("source_ip", ""),
            "username": event.get("username", ""),
            "timestamp": event.get("timestamp", ""),
            "event_id": event_id,
        })

    return converted


def analyze_windows_events():
    events = parse_windows_events()
    normalized_events = convert_windows_events(events)

    # The existing detection engine groups events by source IP.
    alerts = detect_threats(normalized_events)

    return {
        "total_windows_events": len(events),
        "failed_logon_events": len(normalized_events),
        "alerts": alerts,
    }


if __name__ == "__main__":
    result = analyze_windows_events()

    print(f"Windows events read: {result['total_windows_events']}")
    print(f"Failed logon events: {result['failed_logon_events']}")
    print(f"Alerts generated: {len(result['alerts'])}")
    
    print("\n--- Testing detection with simulated events ---")

    test_events = [
        {
            "event_id": 4625,
            "source_ip": "192.0.2.10",
            "username": "testuser",
            "timestamp": "2026-10-16 22:15:00",
        }
        for _ in range(5)
    ]

    test_normalized = convert_windows_events(test_events)
    test_alerts = detect_threats(test_normalized)

    print(f"Simulated failed logons: {len(test_normalized)}")
    print(f"Test alerts generated: {len(test_alerts)}")

    for alert in test_alerts:
        print(alert)


    for alert in result["alerts"]:
        print(alert)
