def get_severity(alert_type):
    severity_map = {
        "Possible Brute-Force Attack": "HIGH",
        "Suspicious Authentication Activity": "HIGH",
        "Repeated Failed Login Attempts": "MEDIUM",
    }

    return severity_map.get(alert_type, "LOW")