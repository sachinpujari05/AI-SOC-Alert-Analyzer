from datetime import datetime, timedelta

from database import (
    create_tables,
    enqueue_windows_event,
    get_connection,
    get_pending_windows_events,
)

from windows_soc_worker import process_pending_events


TEST_COMPUTER = "SOC-WORKER-TEST"
TEST_IP = "192.0.2.99"


def cleanup():
    connection = get_connection()

    try:
        connection.execute(
            """
            DELETE FROM windows_event_queue
            WHERE computer_name = ?
            """,
            (TEST_COMPUTER,),
        )

        connection.execute(
            """
            DELETE FROM alerts
            WHERE source_ip = ?
            """,
            (TEST_IP,),
        )

        connection.commit()

    finally:
        connection.close()


def main():
    create_tables()

    cleanup()

    base_time = datetime.now().replace(microsecond=0)

    test_events = []

    for i in range(5):
        test_events.append(
            {
                "computer": TEST_COMPUTER,
                "record_id": 990000001 + i,
                "event_id": 4625,
                "timestamp": (
                    base_time + timedelta(seconds=i * 20)
                ).isoformat(),
                "event_type": "Failed Logon",
                "username": "worker_test_user",
                "source_ip": TEST_IP,
                "logon_type": "3",
                "status": "0xC000006A",
                "process": "",
            }
        )

    print("=" * 60)
    print("WORKER BRUTE-FORCE INTEGRATION TEST")
    print("=" * 60)

    inserted = 0

    for event in test_events:
        if enqueue_windows_event(event):
            inserted += 1

    print(f"Synthetic events inserted: {inserted}")

    pending_before = [
        event
        for event in get_pending_windows_events(limit=500)
        if event.get("computer") == TEST_COMPUTER
    ]

    print(f"Pending before worker: {len(pending_before)}")

    print("\nRunning SOC worker processing...")

    pending_processed, alerts_detected, alerts_saved = (
        process_pending_events()
    )

    print(f"Pending processed: {pending_processed}")
    print(f"Alerts detected: {alerts_detected}")
    print(f"Alerts saved: {alerts_saved}")

    connection = get_connection()

    try:
        alert = connection.execute(
            """
            SELECT
                alert_type,
                severity,
                source_ip,
                failed_attempts
            FROM alerts
            WHERE source_ip = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (TEST_IP,),
        ).fetchone()

        queue_status = connection.execute(
            """
            SELECT
                status,
                COUNT(*) AS count
            FROM windows_event_queue
            WHERE computer_name = ?
            GROUP BY status
            """,
            (TEST_COMPUTER,),
        ).fetchall()

    finally:
        connection.close()

    print("\nDetection result:")

    if alert:
        print(f"Alert type: {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Source IP: {alert['source_ip']}")
    else:
        print("ERROR: No alert found.")

    print("\nQueue result:")

    if queue_status:
        for row in queue_status:
            print(
                f"{row['status']}: {row['count']}"
            )
    else:
        print("ERROR: No queue records found.")

    success = (
        inserted == 5
        and pending_processed == 5
        and alerts_detected >= 1
        and alert is not None
        and alert["alert_type"] == "Possible Brute-Force Attack"
        and alert["severity"] == "HIGH"
        and alert["failed_attempts"] == 5
    )

    print("\n" + "=" * 60)

    if success:
        print("TEST PASSED")
        print("Worker successfully:")
        print("1. Read queued Windows events")
        print("2. Detected the brute-force attack")
        print("3. Generated a HIGH severity alert")
        print("4. Saved the alert")
        print("5. Processed the queued events")
    else:
        print("TEST FAILED")

    print("=" * 60)

    cleanup()

    print("\nSynthetic worker test data cleaned up.")


if __name__ == "__main__":
    main()