
# --------------------------------
# LOAD SECURITY DATA
# --------------------------------
import streamlit as st
import pandas as pd
import json
from pathlib import Path
from detection.detection_rules import detect_threats

BASE_DIR = Path(__file__).resolve().parent
sample_file = BASE_DIR / "data" / "sample_logs.csv"
wazuh_file = BASE_DIR / "data" / "wazuh_alerts.json"

data_source = st.sidebar.radio(
    "Select Data Source",
    ["Sample Dataset", "Live Wazuh Alerts"]
)


def get_value(record, key, default=""):
    value = record.get(key, default)

    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass

    return value


def get_severity(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0

    if level >= 15:
        return "Critical"
    elif level >= 12:
        return "High"
    elif level >= 7:
        return "Medium"
    return "Low"


if data_source == "Live Wazuh Alerts":

    if not wazuh_file.exists():
        st.error("Wazuh alerts file not found.")
        st.stop()

    try:
        records = []

        with open(wazuh_file, "r") as file:
            for line in file:
                if line.strip():
                    records.append(json.loads(line))

        if not records:
            st.warning("No Wazuh alerts found.")
            st.stop()

        alert_rows = []

        for record in records:

            agent = record.get("agent", {}) or {}
            rule = record.get("rule", {}) or {}
            data = record.get("data", {}) or {}
            mitre = rule.get("mitre", {}) or {}

            # Extract MITRE ATT&CK technique IDs
            if isinstance(mitre, list):
                mitre_ids = [
                    item.get("id", "")
                    for item in mitre
                    if isinstance(item, dict)
                ]
                mitre_id = ", ".join(mitreat for mitreat in mitre_ids if mitreat)

            elif isinstance(mitre, dict):
                mitre_ids = mitre.get("id", [])

                if isinstance(mitre_ids, list):
                    mitre_id = ", ".join(mitre_ids)
                else:
                    mitre_id = str(mitre_ids)

            else:
                mitre_id = ""

            level = get_value(rule, "level", 0)
            description = get_value(
                rule, "description", "Security Event"
            )

            source_ip = get_value(
                data,
                "srcip",
                get_value(agent, "ip", get_value(agent, "name", "Unknown"))
            )

            alert_rows.append({
                "timestamp": get_value(record, "timestamp"),
                "source_ip": source_ip,
                "event_type": description,
                "username": get_value(data, "srcuser"),
                "status": "Alert",
                "details": get_value(record, "full_log"),
                "threat": description,
                "severity": get_severity(level),
                "mitre_id": mitre_id or "Not mapped",
                "description": description,
                "agent": get_value(agent, "name", "Unknown"),
                "rule_level": level
            })

        df = pd.DataFrame(alert_rows)

        alerts = df.copy()

        st.sidebar.success(
            f"{len(alerts)} Wazuh alerts loaded"
        )

    except Exception as error:
        st.error(f"Unable to load Wazuh alerts: {error}")
        st.stop()


else:

    try:
        df = pd.read_csv(sample_file)

        required_columns = [
            "timestamp",
            "source_ip",
            "event_type",
            "username",
            "status",
            "details"
        ]

        missing_columns = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing_columns:
            st.error(
                "Missing columns: " + ", ".join(missing_columns)
            )
            st.stop()

        for col in required_columns:
            df[col] = (
                df[col]
                .fillna("")
                .astype(str)
                .str.strip()
            )

        alerts = detect_threats(df)

    except Exception as error:
        st.error(f"Unable to load security data: {error}")
        st.stop()
# --------------------------------
# DASHBOARD NAVIGATION
# --------------------------------

st.title("SecureX SOC")
st.caption("Security Operations Center | Wazuh Alert Monitoring")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Security Logs",
        "Threat Alerts",
        "MITRE ATT&CK",
        "Incident Reports"
    ]
)

# DASHBOARD
if page == "Dashboard":

    st.header("Security Dashboard")

    total_events = len(df)
    total_alerts = len(alerts)

    if "severity" in alerts.columns:
        critical = (alerts["severity"] == "Critical").sum()
        high = (alerts["severity"] == "High").sum()
    else:
        critical = 0
        high = 0

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)
    col2.metric("Total Alerts", total_alerts)
    col3.metric("Critical Alerts", critical)
    col4.metric("High Alerts", high)

    st.subheader("Recent Security Alerts")
    st.dataframe(alerts, use_container_width=True)

# SECURITY LOGS
elif page == "Security Logs":

    st.header("Security Logs")
    st.dataframe(df, use_container_width=True)

# THREAT ALERTS
elif page == "Threat Alerts":

    st.header("Threat Alerts")

    if alerts.empty:
        st.info("No threats detected.")
    else:
        st.dataframe(alerts, use_container_width=True)

# MITRE ATT&CK
elif page == "MITRE ATT&CK":

    st.header("MITRE ATT&CK Mapping")

    if "mitre_id" in alerts.columns:
        st.dataframe(
            alerts[["description", "mitre_id", "severity"]],
            use_container_width=True
        )
    else:
        st.info("No MITRE ATT&CK mapping available.")

# INCIDENT REPORTS
elif page == "Incident Reports":

    st.header("Incident Reports")
    st.dataframe(alerts, use_container_width=True)