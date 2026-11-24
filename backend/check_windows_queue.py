
from database import get_connection

connection = get_connection()

try:
    total = connection.execute("""
        SELECT COUNT(*) AS count
        FROM windows_event_queue
    """).fetchone()["count"]

    pending = connection.execute("""
        SELECT COUNT(*) AS count
        FROM windows_event_queue
        WHERE status = 'PENDING'
    """).fetchone()["count"]

    processed = connection.execute("""
        SELECT COUNT(*) AS count
        FROM windows_event_queue
        WHERE status = 'PROCESSED'
    """).fetchone()["count"]

    print("Total queued:", total)
    print("Pending:", pending)
    print("Processed:", processed)

finally:
    connection.close()
