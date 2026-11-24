
import sqlite3
from pathlib import Path
import json


# Find the main project folder
BASE_DIR = Path(__file__).resolve().parent.parent

# Database location
DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "soc.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    connection = get_connection()

    # Create alerts table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            successful_logins INTEGER DEFAULT 0,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'NEW',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Track Windows events that have already been processed
    connection.execute("""
        CREATE TABLE IF NOT EXISTS processed_windows_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            computer_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(computer_name, record_id)
        )
    """)

    # Add timestamp column to existing databases if missing
    columns = connection.execute(
        "PRAGMA table_info(alerts)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    if "created_at" not in column_names:
        connection.execute("""
            ALTER TABLE alerts
            ADD COLUMN created_at TEXT
        """)

        # Existing alerts receive the migration time.
        connection.execute("""
            UPDATE alerts
            SET created_at = CURRENT_TIMESTAMP
            WHERE created_at IS NULL
        """)

    
    # Durable queue for collected Windows events
    connection.execute("""
        CREATE TABLE IF NOT EXISTS windows_event_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            computer_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            event_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            queued_at TEXT DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT,
            UNIQUE(computer_name, record_id)
        )
    """)


    connection.commit()
    connection.close()


def save_alert(alert):
    connection = get_connection()

    existing_alert = connection.execute("""
        SELECT id
        FROM alerts
        WHERE alert_type = ?
        AND source_ip = ?
        AND failed_attempts = ?
        AND successful_logins = ?
    """, (
        alert.get("alert_type"),
        alert.get("source_ip"),
        alert.get("failed_attempts", 0),
        alert.get("successful_logins", 0)
    )).fetchone()

    if existing_alert:
        connection.close()
        return False

    connection.execute("""
        INSERT INTO alerts (
            alert_type,
            severity,
            source_ip,
            failed_attempts,
            successful_logins,
            description,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        alert.get("alert_type"),
        alert.get("severity"),
        alert.get("source_ip"),
        alert.get("failed_attempts", 0),
        alert.get("successful_logins", 0),
        alert.get("description"),
        "NEW"
    ))

    connection.commit()
    connection.close()

    return True


def update_alert_status(alert_id, new_status):
    connection = get_connection()

    try:
        cursor = connection.execute("""
            UPDATE alerts
            SET status = ?
            WHERE id = ?
        """, (new_status, alert_id))

        connection.commit()

        return cursor.rowcount > 0

    finally:
        connection.close()


def is_windows_event_processed(computer_name, record_id):
    """Check whether a Windows event has already been processed."""
    connection = get_connection()

    row = connection.execute("""
        SELECT 1
        FROM processed_windows_events
        WHERE computer_name = ? AND record_id = ?
    """, (computer_name, record_id)).fetchone()

    connection.close()
    return row is not None


def mark_windows_event_processed(computer_name, record_id, event_id):
    """Record a Windows event as processed, without creating duplicates."""
    connection = get_connection()

    cursor = connection.execute("""
        INSERT OR IGNORE INTO processed_windows_events (
            computer_name, record_id, event_id
        )
        VALUES (?, ?, ?)
    """, (computer_name, record_id, event_id))

    connection.commit()
    inserted = cursor.rowcount == 1
    connection.close()

    return inserted


def enqueue_windows_event(event):
    """Store a Windows event in the durable queue without duplicates."""
    connection = get_connection()

    try:
        cursor = connection.execute("""
            INSERT OR IGNORE INTO windows_event_queue (
                computer_name,
                record_id,
                event_id,
                event_json
            )
            VALUES (?, ?, ?, ?)
        """, (
            event["computer"],
            int(event["record_id"]),
            int(event["event_id"]),
            json.dumps(event),
        ))

        connection.commit()
        return cursor.rowcount == 1

    finally:
        connection.close()


def get_pending_windows_events(limit=500):
    """Return pending Windows events in queue order."""
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT event_json
            FROM windows_event_queue
            WHERE status = 'PENDING'
            ORDER BY id ASC
            LIMIT ?
        """, (limit,)).fetchall()

        return [json.loads(row["event_json"]) for row in rows]

    finally:
        connection.close()


def mark_queued_windows_event_processed(computer_name, record_id):
    """Mark a queued Windows event as processed."""
    connection = get_connection()

    try:
        cursor = connection.execute("""
            UPDATE windows_event_queue
            SET status = 'PROCESSED',
                processed_at = CURRENT_TIMESTAMP
            WHERE computer_name = ?
              AND record_id = ?
              AND status = 'PENDING'
        """, (computer_name, int(record_id)))

        connection.commit()
        return cursor.rowcount == 1

    finally:
        connection.close()
