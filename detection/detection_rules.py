
import pandas as pd

# SecureX SOC Detection Engine

FAILED_LOGIN_THRESHOLD = 3


def detect_threats(df):

    alerts = []

    # Check required columns
    required_columns = [
        "timestamp",
        "source_ip",
        "event_type",
        "username",
        "status",
        "details"
    ]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(f"Missing column: {column}")

    # Rule 1: Brute Force Detection
    failed_logins = df[
        (df["event_type"].str.lower() == "login") &
        (df["status"].str.lower() == "failed")
    ]

    login_counts = failed_logins.groupby("source_ip").size()

    for ip, count in login_counts.items():

        if count >= FAILED_LOGIN_THRESHOLD:

            alerts.append({
                "source_ip": ip,
                "threat": "Brute Force Attempt",
                "severity": "High",
                "count": int(count),
                "mitre_id": "T1110",
                "description": f"{count} failed login attempts detected"
            })

    # Rule 2: Port Scanning Detection
    port_scans = df[
        df["event_type"].str.lower() == "port_scan"
    ]

    for _, row in port_scans.iterrows():

        alerts.append({
            "source_ip": row["source_ip"],
            "threat": "Port Scanning",
            "severity": "Medium",
            "count": 1,
            "mitre_id": "T1046",
            "description": row["details"]
        })

    # Rule 3: Malware Detection
    malware = df[
        df["event_type"].str.lower() == "malware_detected"
    ]

    for _, row in malware.iterrows():

        alerts.append({
            "source_ip": row["source_ip"],
            "threat": "Malware Activity",
            "severity": "Critical",
            "count": 1,
            "mitre_id": "T1204",
            "description": row["details"]
        })

    # Rule 4: Phishing Detection
    phishing = df[
        df["event_type"].str.lower() == "phishing_reported"
    ]

    for _, row in phishing.iterrows():

        alerts.append({
            "source_ip": row["source_ip"],
            "threat": "Phishing Report",
            "severity": "High",
            "count": 1,
            "mitre_id": "T1566",
            "description": row["details"]
        })

    return pd.DataFrame(alerts)
