
from datetime import datetime, timedelta
from collections import defaultdict

from severity import get_severity
from windows_event_parser import parse_windows_events


WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 5
REPEATED_FAILURE_THRESHOLD = 3



def detect_windows_threats(events):
    """Detect repeated failed logons within a rolling time window."""
    failed_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_id") != 4625:
            continue

        source_ip = event.get("source_ip", "").strip()

        if not source_ip or source_ip in {"-", "127.0.0.1", "::1"}:
            continue

        try:
            timestamp = datetime.fromisoformat(event["timestamp"])
        except (ValueError, TypeError, KeyError):
            continue

        failed_by_ip[source_ip].append(timestamp)

    alerts = []

    for source_ip, timestamps in failed_by_ip.items():
        timestamps.sort()

        # Sliding window: find the maximum failures in any 5 minutes.
        left = 0
        max_count = 0

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > timedelta(
                minutes=WINDOW_MINUTES
            ):
                left += 1

            max_count = max(max_count, right - left + 1)

        if max_count >= BRUTE_FORCE_THRESHOLD:
            alert_type = "Possible Brute-Force Attack"
        elif max_count >= REPEATED_FAILURE_THRESHOLD:
            alert_type = "Repeated Failed Login Attempts"
        else:
            continue

        alerts.append({
            "alert_type": alert_type,
            "severity": get_severity(alert_type),
            "source_ip": source_ip,
            "failed_attempts": max_count,
            "successful_logins": 0,
            "description": (
                f"{max_count} failed Windows logon events from {source_ip} "
                f"within {WINDOW_MINUTES} minutes"
            ),
        })

    return alerts

if __name__ == "__main__":
    base_time = datetime(2026, 10, 16, 22, 15, 0)

    for test_name, event_count, source_ip in [
        ("Test 1: Three failures", 3, "192.0.2.10"),
        ("Test 2: Five failures", 5, "192.0.2.20"),
    ]:
        print(f"\n=== {test_name} ===")

        test_events = [
            {
                "event_id": 4625,
                "timestamp": (
                    base_time + timedelta(seconds=i * 30)
                ).isoformat(sep=" "),
                "source_ip": source_ip,
            }
            for i in range(event_count)
        ]

        print("Test events created:", len(test_events))

        alerts = detect_windows_threats(test_events)

        print("Alerts detected:", len(alerts))

        for alert in alerts:
            print(alert)

        if event_count == 3:
            assert alerts[0]["failed_attempts"] == 3
            assert alerts[0]["severity"] == "MEDIUM"
        else:
            assert alerts[0]["failed_attempts"] == 5
            assert alerts[0]["severity"] == "HIGH"

    print("\nAll tests passed!")
