import argparse
import json
import time
from datetime import datetime, timedelta

from database import (
    create_tables,
    enqueue_windows_event,
    get_connection,
    get_pending_windows_events,
    mark_queued_windows_event_processed,
    save_alert,
)

from windows_live_collector import collect_recent_logons
from windows_time_detection import detect_windows_threats


POLL_INTERVAL_SECONDS = 10
LOOKBACK_MINUTES = 10


def collect_and_queue():
    events = collect_recent_logons()

    queued = 0
    duplicates = 0

    for event in events:
        if event.get("event_id") not in (4624, 4625):
            continue

        if event.get("record_id") is None:
            continue

        if not event.get("computer"):
            continue

        if enqueue_windows_event(event):
            queued += 1
        else:
            duplicates += 1

    return events, queued, duplicates


def get_recent_event_history():
    """
    Read stored Windows events and use the actual Windows event timestamp
    for the detection lookback window.

    queued_at is NOT used to decide whether an event belongs to the
    detection window.
    """

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT event_json
            FROM windows_event_queue
            ORDER BY id DESC
            LIMIT 5000
            """
        ).fetchall()

    finally:
        connection.close()

    cutoff = datetime.now() - timedelta(minutes=LOOKBACK_MINUTES)

    events = []

    for row in rows:
        try:
            event = json.loads(row["event_json"])

            timestamp = event.get("timestamp")

            if not timestamp:
                continue

            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "")
            )

            if event_time >= cutoff:
                events.append(event)

        except (json.JSONDecodeError, ValueError, TypeError):
            continue

    events.reverse()

    return events


def process_pending_events():
    pending = get_pending_windows_events(limit=500)

    if not pending:
        return 0, 0, 0

    recent_events = get_recent_event_history()

    alerts = detect_windows_threats(recent_events)

    saved_alerts = 0

    for alert in alerts:
        if save_alert(alert):
            saved_alerts += 1

            print(
                f"[ALERT] {alert['severity']} | "
                f"{alert['alert_type']} | "
                f"Source: {alert['source_ip']} | "
                f"Failures: {alert['failed_attempts']}"
            )

    processed = 0

    for event in pending:
        computer = event.get("computer")
        record_id = event.get("record_id")

        if computer and record_id is not None:
            mark_queued_windows_event_processed(
                computer,
                record_id,
            )
            processed += 1

    return len(pending), len(alerts), saved_alerts


def run_once():
    events, queued, duplicates = collect_and_queue()

    pending_count, detected_count, saved_count = (
        process_pending_events()
    )

    failed = sum(
        1
        for event in events
        if event.get("event_id") == 4625
    )

    successful = sum(
        1
        for event in events
        if event.get("event_id") == 4624
    )

    print(
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
        f"Collected={len(events)} "
        f"4624={successful} "
        f"4625={failed} "
        f"Queued={queued} "
        f"Duplicates={duplicates} "
        f"Processed={pending_count} "
        f"Alerts={detected_count} "
        f"Saved={saved_count}"
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one collection and detection cycle.",
    )

    args = parser.parse_args()

    create_tables()

    if args.once:
        run_once()
        return

    print("=" * 60)
    print("AI-POWERED SOC WINDOWS WORKER")
    print("=" * 60)
    print(f"Polling interval : {POLL_INTERVAL_SECONDS} seconds")
    print(f"Detection window : {LOOKBACK_MINUTES} minutes")
    print("Monitoring Windows Security Events...")
    print("Press CTRL+C to stop.")
    print("=" * 60)

    while True:
        try:
            run_once()

        except KeyboardInterrupt:
            print("\nSOC Worker stopped.")
            break

        except Exception as exc:
            print(
                f"[WORKER ERROR] "
                f"{type(exc).__name__}: {exc}"
            )

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()