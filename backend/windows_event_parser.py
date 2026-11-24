
import csv
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = PROJECT_ROOT / "data" / "windows_security_events.csv"


def parse_windows_events():
    """Parse exported Windows Security events into normalized records."""
    parsed_events = []

    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Windows events CSV not found: {CSV_PATH}")

    with CSV_PATH.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required_columns = {"TimeCreated", "EventID", "TargetUser", "SourceIP", "LogonType", "Status"}
        missing = required_columns - set(reader.fieldnames or [])

        if missing:
            raise ValueError(f"CSV is missing columns: {', '.join(sorted(missing))}")

        for row in reader:
            event_id = int(row["EventID"])

            if event_id not in (4624, 4625):
                continue

            try:
                timestamp = datetime.strptime(
                    row["TimeCreated"], "%Y-%m-%d %H:%M:%S"
                ).isoformat(sep=" ")
            except ValueError:
                timestamp = row["TimeCreated"]

            parsed_events.append({
                "timestamp": timestamp,
                "event_id": event_id,
                "event_type": (
                    "Successful Logon" if event_id == 4624
                    else "Failed Logon"
                ),
                "username": (
                    "" if row["TargetUser"].strip() in ("", "-")
                    else row["TargetUser"].strip()
                ),
                "source_ip": (
                    "" if row["SourceIP"].strip() in ("", "-")
                    else row["SourceIP"].strip()
                ),
                "logon_type": row["LogonType"].strip(),
                "status": row["Status"].strip(),
                "process_name": row.get("ProcessName", "").strip(),
            })

    return parsed_events


if __name__ == "__main__":
    events = parse_windows_events()

    print(f"Total events parsed: {len(events)}")
    print(f"Failed logons (4625): {sum(e['event_id'] == 4625 for e in events)}")
    print(f"Successful logons (4624): {sum(e['event_id'] == 4624 for e in events)}")

    print("\nFirst 5 parsed events:")
    for event in events[:5]:
        print(event)
