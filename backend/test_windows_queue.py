
from database import (
    create_tables,
    enqueue_windows_event,
    get_pending_windows_events,
    mark_queued_windows_event_processed,
)

create_tables()

test_event = {
    "computer": "QUEUE-TEST-PC",
    "record_id": 987654321,
    "event_id": 4625,
    "timestamp": "2026-10-18 06:00:00",
    "source_ip": "192.0.2.10",
    "username": "queue_test_user",
    "logon_type": "3",
    "status": "0xC000006A",
}

try:
    inserted = enqueue_windows_event(test_event)
    print("Inserted:", inserted)

    pending = get_pending_windows_events()
    found = any(
        event.get("computer") == "QUEUE-TEST-PC"
        and event.get("record_id") == 987654321
        for event in pending
    )
    print("Found in pending queue:", found)

    marked = mark_queued_windows_event_processed(
        "QUEUE-TEST-PC", 987654321
    )
    print("Marked processed:", marked)

    remaining = get_pending_windows_events()
    still_pending = any(
        event.get("computer") == "QUEUE-TEST-PC"
        and event.get("record_id") == 987654321
        for event in remaining
    )
    print("Still pending:", still_pending)

finally:
    # Cleanup the temporary test event only.
    from database import get_connection

    connection = get_connection()
    connection.execute("""
        DELETE FROM windows_event_queue
        WHERE computer_name = ? AND record_id = ?
    """, ("QUEUE-TEST-PC", 987654321))
    connection.commit()
    connection.close()
