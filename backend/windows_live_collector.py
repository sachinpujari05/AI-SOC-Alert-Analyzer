import json
import subprocess
from pathlib import Path

from database import create_tables, enqueue_windows_event


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
} -MaxEvents 100 -ErrorAction Stop

$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = [string]$item.'#text'
    }

    [PSCustomObject]@{
        event_id   = $event.Id
        record_id  = $event.RecordId
        timestamp  = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        event_type = if ($event.Id -eq 4624) {
            'Successful Logon'
        } else {
            'Failed Logon'
        }
        username   = $data['TargetUserName']
        source_ip  = $data['IpAddress']
        logon_type = $data['LogonType']
        status     = $data['Status']
        process    = $data['ProcessName']
        computer   = $event.MachineName
    }
}

ConvertTo-Json -InputObject @($results) -Depth 4 -Compress
"""


def collect_recent_logons():
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_SCRIPT,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if completed.returncode != 0:
        error = completed.stderr.strip()

        if "UnauthorizedAccessException" in error:
            raise PermissionError(
                "Access to the Windows Security event log was denied. "
                "Run the VS Code terminal or worker with Administrator privileges."
            )

        if "NoMatchingEventsFound" in error:
            return []

        raise RuntimeError(
            error
            or "PowerShell failed to read Windows Security events."
        )

    output = completed.stdout.strip()

    if not output:
        return []

    data = json.loads(output)

    if isinstance(data, dict):
        return [data]

    return data


def export_events(events):
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"

    data_dir.mkdir(parents=True, exist_ok=True)

    output_path = data_dir / "windows_live_events.json"
    temp_path = data_dir / "windows_live_events.tmp"

    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=2)

    temp_path.replace(output_path)

    print(f"Exported {len(events)} events to: {output_path}")


def normalize_for_detection(events):
    normalized = []

    for event in events:
        if event.get("event_id") not in (4624, 4625):
            continue

        normalized.append(
            {
                "event_id": int(event["event_id"]),
                "timestamp": event["timestamp"],
                "source_ip": (
                    ""
                    if event.get("source_ip") in ("", "-")
                    else event.get("source_ip", "")
                ),
                "username": (
                    ""
                    if event.get("username") in ("", "-")
                    else event.get("username", "")
                ),
                "logon_type": event.get("logon_type", ""),
                "status": event.get("status") or "",
            }
        )

    return normalized


if __name__ == "__main__":
    try:
        create_tables()

        events = collect_recent_logons()

        export_events(events)

        queued_count = 0
        duplicate_count = 0

        for event in events:
            if event.get("event_id") not in (4624, 4625):
                continue

            if event.get("record_id") is None:
                continue

            if not event.get("computer"):
                continue

            if enqueue_windows_event(event):
                queued_count += 1
            else:
                duplicate_count += 1

        failed = [
            event
            for event in events
            if event.get("event_id") == 4625
        ]

        successful = [
            event
            for event in events
            if event.get("event_id") == 4624
        ]

        print(f"Total events collected: {len(events)}")
        print(f"Successful logons (4624): {len(successful)}")
        print(f"Failed logons (4625): {len(failed)}")
        print(f"New events queued: {queued_count}")
        print(f"Duplicate events skipped: {duplicate_count}")

        print("\nRecent failed logons:")

        for event in failed[:10]:
            print(event)

    except PermissionError as exc:
        print(f"[PERMISSION ERROR] {exc}")

    except Exception as exc:
        print(f"[COLLECTOR ERROR] {exc}")