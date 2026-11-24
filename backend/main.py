from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
import random
from fastapi.middleware.cors import CORSMiddleware
from ai_analyzer import analyze_alert
from windows_detection_adapter import analyze_windows_events
from windows_event_parser import parse_windows_events
from windows_time_detection import detect_windows_threats
import os
from pydantic import BaseModel
from database import (
    create_tables,
    save_alert,
    update_alert_status,
    is_windows_event_processed,
    mark_windows_event_processed,
    get_pending_windows_events,
    mark_queued_windows_event_processed,
)
from starlette.middleware.sessions import SessionMiddleware
import csv
import io
import json
from pathlib import Path
import secrets
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from detection import detect_threats


app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    same_site="lax",
    https_only=False,  # Local development only
)

class LoginRequest(BaseModel):
    token: str


@app.post("/login")
def login(data: LoginRequest, request: Request):
    expected_token = os.getenv("SOC_API_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured."
        )

    if not secrets.compare_digest(data.token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials."
        )

    request.session["authenticated"] = True

    return {"message": "Login successful"}

@app.get("/auth/check")
def check_auth(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    return {"authenticated": True}

security = HTTPBearer(auto_error=False)


def verify_api_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    expected_token = os.getenv("SOC_API_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured.",
        )

    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not secrets.compare_digest(
            credentials.credentials,
            expected_token,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True


frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "http://localhost:5173",
)

def require_login(request: Request):
    if not request.session.get("authenticated"):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated. Please log in."
        )

    return True

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        frontend_origin,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


create_tables()


@app.get("/")
def home():
    return {
        "message": "AI-Powered SOC Alert Analyzer is running"
    }


@app.post("/upload-log", dependencies=[Depends(verify_api_token)])
async def upload_log(file: UploadFile = File(...)):

    # Read uploaded file
    contents = await file.read()

    # Convert bytes into text
    text = contents.decode("utf-8")

    # Read CSV data
    csv_file = io.StringIO(text)
    reader = csv.DictReader(csv_file)

    # Required security log fields
    required_fields = [
        "timestamp",
        "source_ip",
        "user",
        "event_type",
        "status",
        "message"
    ]

    # Check CSV headers
    if reader.fieldnames is None:
        return {
            "status": "error",
            "message": "CSV file has no header"
        }

    missing_fields = [
        field for field in required_fields
        if field not in reader.fieldnames
    ]

    if missing_fields:
        return {
            "status": "error",
            "message": "Required fields are missing",
            "missing_fields": missing_fields
        }

    # Process rows
    valid_logs = []
    invalid_logs = []

    for row_number, row in enumerate(reader, start=2):

        # Check for empty required fields
        missing_values = [
            field for field in required_fields
            if not row.get(field, "").strip()
        ]

        if missing_values:
            invalid_logs.append({
                "row": row_number,
                "missing_fields": missing_values
            })
        else:
            valid_logs.append(row)

    alerts = detect_threats(valid_logs)

    for alert in alerts:
        save_alert(alert)

    return {
        "status": "success",
        "filename": file.filename,
        "total_logs": len(valid_logs) + len(invalid_logs),
        "valid_logs": len(valid_logs),
        "invalid_logs": len(invalid_logs),
        "alerts_detected": len(alerts),
        "alerts": alerts
    }

@app.get("/alerts", dependencies=[Depends(check_auth)])
def get_alerts():

    from database import get_connection

    connection = get_connection()

    rows = connection.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return {
        "total_alerts": len(rows),
        "alerts": [dict(row) for row in rows]
    }

@app.put(
    "/alerts/{alert_id}/status",
    dependencies=[Depends(require_login)]
)
def change_alert_status(alert_id: int, status: str):

    allowed_statuses = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED"
    ]

    status = status.upper()

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    updated = update_alert_status(alert_id, status)

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Alert not found."
        )

    return {
        "status": "success",
        "alert_id": alert_id,
        "new_status": status
    }

@app.post("/alerts/generate-test")
def generate_test_alerts(
    count: int = 10,
    authenticated: bool = Depends(require_login)
):
    if count < 1 or count > 10:
        raise HTTPException(
            status_code=400,
            detail="Count must be between 1 and 10."
        )

    import random

    alert_types = [
        {
            "alert_type": "Possible Brute-Force Attack",
            "severity": "HIGH",
            "description": "Multiple failed login attempts detected from a single source IP."
        },
        {
            "alert_type": "Repeated Failed Login Attempts",
            "severity": "MEDIUM",
            "description": "Repeated authentication failures detected. Further investigation is recommended."
        },
        {
            "alert_type": "Suspicious PowerShell Activity",
            "severity": "HIGH",
            "description": "Synthetic test alert representing potentially suspicious PowerShell activity."
        },
        {
            "alert_type": "Unusual Login Activity",
            "severity": "MEDIUM",
            "description": "Synthetic test alert representing an unusual login pattern."
        },
        {
            "alert_type": "Potential Malware Activity",
            "severity": "CRITICAL",
            "description": "Synthetic test alert representing potentially malicious endpoint activity."
        },
        {
            "alert_type": "Multiple Successful Logins",
            "severity": "LOW",
            "description": "Synthetic test alert representing multiple successful logins."
        }
    ]

    generated_count = 0

    for _ in range(count):
        template = random.choice(alert_types)

        is_successful_login = (
            template["alert_type"] == "Multiple Successful Logins"
        )

        alert = {
            **template,
            "source_ip": f"192.0.2.{random.randint(1, 254)}",
            "failed_attempts": (
                0 if is_successful_login else random.randint(3, 10)
            ),
            "successful_logins": (
                random.randint(3, 8) if is_successful_login else 0
            )
        }

        if save_alert(alert):
            generated_count += 1

    return {
        "status": "success",
        "generated_count": generated_count,
        "message": "Synthetic test alerts processed."
    }


@app.post("/alerts/{alert_id}/analyze", dependencies=[Depends(check_auth)])
def analyze_alert_endpoint(alert_id: int):

    from database import get_connection

    connection = get_connection()

    row = connection.execute("""
        SELECT *
        FROM alerts
        WHERE id = ?
    """, (alert_id,)).fetchone()

    connection.close()

    if row is None:
        return {
            "status": "error",
            "message": "Alert not found"
        }

    alert = dict(row)

    return analyze_alert(alert)


@app.post("/analyze-windows-logs", dependencies=[Depends(verify_api_token)])
def analyze_windows_logs_endpoint():
    result = analyze_windows_events()

    saved_alerts = 0

    for alert in result["alerts"]:
        was_saved = save_alert(alert)

        if was_saved:
            saved_alerts += 1

    return {
        "status": "success",
        "source": "Windows Security Event Log CSV",
        "windows_events_read": result["total_windows_events"],
        "failed_logon_events": result["failed_logon_events"],
        "alerts_detected": len(result["alerts"]),
        "alerts_saved": saved_alerts,
        "alerts": result["alerts"],
    }

@app.post("/detect-windows-threats", dependencies=[Depends(verify_api_token)])
def detect_windows_threats_endpoint():
    events = parse_windows_events()
    alerts = detect_windows_threats(events)

    saved_alerts = 0

    for alert in alerts:
        if save_alert(alert):
            saved_alerts += 1

    return {
        "status": "success",
        "source": "Windows Security Event Log CSV",
        "windows_events_read": len(events),
        "alerts_detected": len(alerts),
        "alerts_saved": saved_alerts,
        "alerts": alerts,
    }



@app.post("/detect-live-windows-threats", dependencies=[Depends(verify_api_token)])
def detect_live_windows_threats_endpoint():
    project_root = Path(__file__).resolve().parent.parent
    events_path = project_root / "data" / "windows_live_events.json"

    if not events_path.exists():
        return {
            "status": "error",
            "message": "Live Windows events file not found. Run the collector first."
        }

    
    try:
        with events_path.open("r", encoding="utf-8") as file:
            raw_events = json.load(file)
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "status": "error",
            "message": f"Could not read live Windows events: {exc}"
        }

    if not isinstance(raw_events, list):
        return {
            "status": "error",
            "message": "Invalid live events format: expected a JSON list."
        }


    new_events = []

    for event in raw_events:
        if event.get("event_id") not in (4624, 4625):
            continue

        record_id = event.get("record_id")
        computer_name = event.get("computer", "")

        if record_id is None or not computer_name:
            continue

        if is_windows_event_processed(computer_name, record_id):
            continue

        new_events.append({
            "event_id": int(event["event_id"]),
            "record_id": int(record_id),
            "computer": computer_name,
            "timestamp": event.get("timestamp", ""),
            "source_ip": (
                "" if event.get("source_ip") in ("", "-")
                else event.get("source_ip", "")
            ),
            "username": (
                "" if event.get("username") in ("", "-")
                else event.get("username", "")
            ),
            "logon_type": event.get("logon_type", ""),
            "status": event.get("status") or "",
        })

    alerts = detect_windows_threats(new_events)

    saved_alerts = 0
    for alert in alerts:
        if save_alert(alert):
            saved_alerts += 1

    processed_count = 0
    for event in new_events:
        if mark_windows_event_processed(
            event["computer"],
            event["record_id"],
            event["event_id"],
        ):
            processed_count += 1

    return {
        "status": "success",
        "source": "Windows Security events JSON",
        "new_events_read": len(new_events),
        "events_marked_processed": processed_count,
        "alerts_detected": len(alerts),
        "alerts_saved": saved_alerts,
        "alerts": alerts,
    }


@app.post("/detect-queued-windows-threats", dependencies=[Depends(verify_api_token)])
def detect_queued_windows_threats_endpoint():
    try:
        # Fetch a batch from the durable SQLite queue.
        events = get_pending_windows_events(limit=500)

        if not events:
            return {
                "status": "success",
                "source": "SQLite Windows event queue",
                "pending_events_read": 0,
                "events_marked_processed": 0,
                "alerts_detected": 0,
                "alerts_saved": 0,
                "alerts": [],
            }

        # Run the existing detection rules.
        alerts = detect_windows_threats(events)

        # Save detected alerts before marking events processed.
        saved_alerts = 0
        for alert in alerts:
            if save_alert(alert):
                saved_alerts += 1

        # Mark queue events processed only after detection and
        # alert saving complete without raising an exception.
        processed_count = 0
        for event in events:
            if mark_queued_windows_event_processed(
                event["computer"],
                event["record_id"],
            ):
                processed_count += 1

        return {
            "status": "success",
            "source": "SQLite Windows event queue",
            "pending_events_read": len(events),
            "events_marked_processed": processed_count,
            "alerts_detected": len(alerts),
            "alerts_saved": saved_alerts,
            "alerts": alerts,
        }

    except Exception as exc:
        return {
            "status": "error",
            "message": f"Queued Windows detection failed: {exc}",
        }
