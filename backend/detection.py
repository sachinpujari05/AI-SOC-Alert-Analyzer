from collections import defaultdict
from severity import get_severity


def detect_threats(logs):
    alerts = []

    # Group failed login events by source IP
    failed_logins = defaultdict(list)

    # Group all login events by source IP
    login_events = defaultdict(list)

    for log in logs:

        source_ip = log.get("source_ip", "")
        event_type = log.get("event_type", "").upper()
        status = log.get("status", "").upper()

        if event_type == "LOGIN":

            login_events[source_ip].append(log)

            if status == "FAILED":
                failed_logins[source_ip].append(log)

    # ------------------------------------------------
    # RULE 1 + RULE 2
    # Failed login count
    # ------------------------------------------------

    for source_ip, events in failed_logins.items():

        failed_count = len(events)

        if failed_count >= 5:

            alert_type = "Possible Brute-Force Attack"

            alerts.append({
                "alert_type": alert_type,
                "severity": get_severity(alert_type),
                "source_ip": source_ip,
                "failed_attempts": failed_count,
                "description": (
                    f"{failed_count} failed login attempts "
                    f"detected from {source_ip}"
                )
            })

        elif failed_count >= 3:

            alert_type = "Repeated Failed Login Attempts"

            alerts.append({
                "alert_type": alert_type,
                "severity": get_severity(alert_type),
                "source_ip": source_ip,
                "failed_attempts": failed_count,
                "description": (
                    f"{failed_count} failed login attempts "
                    f"detected from {source_ip}"
                )
            })

    # ------------------------------------------------
    # RULE 3
    # Failed login followed by successful login
    # ------------------------------------------------

    for source_ip, events in login_events.items():

        failed_count = sum(
            1 for event in events
            if event.get("status", "").upper() == "FAILED"
        )

        successful_count = sum(
            1 for event in events
            if event.get("status", "").upper() == "SUCCESS"
        )

        if failed_count > 0 and successful_count > 0:

            alert_type = "Suspicious Authentication Activity"

            alerts.append({
                "alert_type": alert_type,
                "severity": get_severity(alert_type),
                "source_ip": source_ip,
                "failed_attempts": failed_count,
                "successful_logins": successful_count,
                "description": (
                    f"{source_ip} had {failed_count} failed "
                    f"login attempt(s) followed by "
                    f"{successful_count} successful login(s)"
                )
            })

    return alerts