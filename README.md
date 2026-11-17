# NetSentry

NetSentry is a local Python and Streamlit application for offline network traffic analysis and rule-based anomaly detection. It is designed as a cybersecurity portfolio project for SOC Analyst, Network Security Analyst, Cybersecurity Analyst, and Incident Response Analyst roles.

The application accepts PCAP and PCAPNG files, extracts packet metadata, analyzes traffic and DNS activity, identifies suspicious patterns using transparent configurable heuristics, and produces investigation reports. Version 1.0 does not perform live capture, packet replay, blocking, or network transmission.

## Features

- Bounded Scapy PCAP/PCAPNG parsing with payload-free packet records.
- Pandas traffic, protocol, DNS, conversation, timeline, and internal/external analysis.
- Eight transparent configurable detection rules with evidence and investigation steps.
- Dark Streamlit overview plus Traffic Explorer, Protocol Analysis, DNS Investigation, Anomaly Alerts, and Investigation Reports pages.
- CSV and structured JSON exports, deterministic tests, and harmless local synthetic captures.
- No live capture, transmission, replay, arbitrary shell execution, or payload storage.

## Technology stack

- Python 3.12 or 3.13
- Streamlit
- Scapy
- Pandas
- Plotly
- Pytest
- JSON, CSV, and JSON reporting

No Docker, database, cloud infrastructure, machine-learning service, or live network capture is required.

## Folder structure

```text
NetSentry/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── config/
│   └── detection_config.json
├── data/
│   ├── samples/
│   └── reports/
├── src/{capture,analysis,detection,reporting,utils}/
├── pages/  ├── tests/
└── scripts/
```

The modules are deliberately separated so parser, analysis, detection, reporting, and UI logic can be tested independently.

## Installation on Windows PowerShell

Open PowerShell in the project directory:

```powershell
cd C:\path\to\NetSentry

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use the current-user execution-policy command below, then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Alternatively, run the virtual-environment Python directly without activation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the application

```powershell
streamlit run app.py
```

Streamlit will print a local URL, normally `http://localhost:8501`. Open it in a browser, upload an authorized capture, and select **Analyze capture**.

## Detection configuration

Detection thresholds are stored in `config/detection_config.json` so they can be reviewed and adjusted without changing dashboard code. The planned rules are:

- **NET-001:** Possible port scan.
- **NET-002:** Unusually high TCP SYN activity.
- **NET-003:** ICMP burst.
- **NET-004:** DNS query spike.
- **NET-005:** Long DNS query name.
- **NET-006:** Unusual destination port.
- **NET-007:** High traffic volume.
- **NET-008:** High TCP reset ratio.

These are evidence-based heuristics, not proof of malicious activity. A finding requires analyst validation and context.

## Synthetic test captures

```powershell
python scripts\generate_test_pcaps.py
```

This writes clearly named harmless captures under `data/samples/` for normal traffic, DNS, ICMP, port scans, SYN activity, DNS spikes, and reset ratios. Scapy writes files locally; it never sends packets.

## Security and reliability principles

NetSentry will not execute packet payloads, replay packets, transmit traffic, automatically block IP addresses, execute arbitrary shell commands, or claim that a capture is safe merely because no alert was generated. Uploaded files will have size and packet-count limits, and the application will store metadata rather than unnecessary payloads.

## Testing

The full Pytest suite is introduced in later milestones. Once tests exist, run:

```powershell
pytest -q
```

## Testing

```powershell
pytest -q
```

Tests use controlled records and local synthetic data, not a live network. They cover parsing boundaries, aggregation, DNS, all detection-rule paths, threshold behavior, and CSV/JSON exports.

## Screenshots

Screenshots will be added after the interactive dashboard pages are implemented.

## Limitations

The initial release is an offline PCAP analyzer. It will not replace a SIEM, IDS, packet broker, malware sandbox, threat-intelligence platform, or incident-response case-management system. Rule-based detections may produce false positives and require analyst review. Encrypted traffic can generally be analyzed only through metadata unless decryption material is separately available and authorized.

## Future improvements

Potential future work includes richer conversation reconstruction, allowlists and baselines, optional threat-intelligence enrichment, case notes, configurable report templates, larger-capture streaming improvements, and integration with authorized SIEM workflows. Any future network-facing capability must be designed with explicit safety controls.
