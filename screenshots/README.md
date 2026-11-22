# SecureX SOC – Cybersecurity Monitoring Dashboard

## Project Overview

SecureX SOC is a cybersecurity monitoring dashboard designed to display security events, identify potential threats, and organize security alerts in one place.

The project uses Python and Streamlit to provide an interactive dashboard. It supports a sample security dataset and imported alerts exported from Wazuh.

## Features

- Security monitoring dashboard
- Sample security event analysis
- Wazuh alert integration using exported JSON data
- Threat alert visualization
- MITRE ATT&CK technique mapping when available
- Incident report overview
- Security event and alert tables
- Severity classification

## Technologies Used

- Python
- Streamlit
- Pandas
- Wazuh SIEM
- JSON
- MITRE ATT&CK Framework
- VS Code
- Ubuntu Server (UTM)

## Project Structure

```text
SecureX-SOC/
│
├── app.py
├── requirements.txt
├── README.md
│
├── data/
│   ├── sample_logs.csv
│   └── wazuh_alerts.json
│
├── detection/
│   ├── __init__.py
│   └── detection_rules.py
│
├── logs/
│   └── security_logs.txt
│
├── reports/
│   └── incident_report_template.md
│
└── screenshots/
    ├── 01_dashboard.png
    ├── 02_security_logs.png
    ├── 03_threat_alerts.png
    ├── 04_mitre_attack.png
    └── 05_incident_reports.png
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd SecureX-SOC
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the environment

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal to access the dashboard.

## Wazuh Integration

Wazuh was installed on an Ubuntu Server virtual machine using UTM. A Wazuh agent was configured on macOS and connected to the Wazuh manager.

Exported Wazuh alerts were transferred into the project's `data` folder and loaded into the Streamlit dashboard using JSON processing.

**Note:** The current implementation displays an exported alert snapshot. It does not provide continuous real-time alert streaming.

## Limitations

- The Wazuh integration currently uses exported alert data.
- Threat detection in the sample dataset uses predefined rules.
- AI/ML-based threat prediction is not currently implemented.
- Alert severity depends on the available Wazuh rule levels.

## Future Improvements

- Continuous Wazuh alert integration
- Machine learning-based threat detection
- Automated incident report generation
- Email notifications for critical alerts
- Advanced threat visualization

## Project Screenshots

The `screenshots` folder contains images of the dashboard, security logs, threat alerts, MITRE ATT&CK mapping, and incident reports.

## Conclusion

SecureX SOC demonstrates how security event data and SIEM alerts can be organized into an interactive cybersecurity monitoring dashboard. It provides a foundation for further development in security monitoring and threat detection.
