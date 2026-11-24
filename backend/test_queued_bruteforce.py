
from datetime import datetime, timedelta

from database import (
    create_tables,
    enqueue_windows_event,
    get_connection,
    get_pending_windows_events,
    mark_queued_windows_event_processed,
    save_alert,
)
from windows_time_detection import detect_windows_threats

TEST_COMPUTER = "SOC-SYNTHETIC-TEST"
TEST_IP = "192.0.2.55"  # Documentation-only IP address

create_tables()

connection = get_connection()
try:
    # Ensure this test starts with no leftover test records.
    connection.execute("""
        DELETE FROM windows_event_queue
        WHERE computer_name = ?
    """, (TEST_COMPUTER,))
    connection.commit()
finally:
    connection.close()

base_time = datetime.now().replace(microsecond=0)
test_events = []

for i in range(5):
    test_events.append({
        "computer": TEST_COMPUTER,
        "record_id": 900000001 + i,
        "event_id": 4625,
        "timestamp": (base_time + timedelta(seconds=i * 20)).isoformat(),
        "source_ip": TEST_IP,
        "username": "synthetic_test_user",
        "logon_type": "3",
        "status": "0xC000006A",
    })

try:
    inserted = sum(
        enqueue_windows_event(event)
        for event in test_events
    )
    print("Synthetic events inserted:", inserted)

    pending = get_pending_windows_events(limit=500)
    test_pending = [
        event for event in pending
        if event.get("computer") == TEST_COMPUTER
    ]

    print("Synthetic events pending:", len(test_pending))

    alerts = detect_windows_threats(test_pending)
    print("Alerts detected:", len(alerts))

    for alert in alerts:
        print("Alert type:", alert["alert_type"])
        print("Severity:", alert["severity"])
        print("Failed attempts:", alert["failed_attempts"])
        print("Source IP:", alert["source_ip"])

    saved = sum(save_alert(alert) for alert in alerts)
    print("Alerts saved:", saved)

    for event in test_pending:
        mark_queued_windows_event_processed(
            event["computer"],
            event["record_id"],
        )

finally:
    # Remove only this test's queue records.
    connection = get_connection()
    try:
        connection.execute("""
            DELETE FROM windows_event_queue
            WHERE computer_name = ?
        """, (TEST_COMPUTER,))
        connection.commit()
    finally:
        connection.close()
