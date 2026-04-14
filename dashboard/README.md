# Streamlit Dashboard

## Role
The dashboard visualizes the real behavior of the Trusted Gatekeeper System.
It does not simulate data and does not change backend security logic.

## Data Source
The dashboard reads:

```text
logs/fog_security.log
logs/cloud_audit.log
```

These files are created when the Fog Gateway and Cloud Server process normal
messages or attack simulations.

## Sections
- System Status: shows NORMAL or ALERT based on recent blocked or suspicious
  activity.
- Live Data Flow: shows the IoT -> Fog -> Cloud pipeline and message counts.
- Message Monitoring Panel: shows recent accepted, suspicious, and blocked
  messages.
- Attack Detection Panel: lists fake device, replay, flooding, and invalid
  encrypted-message events.
- Device Trust Score Panel: shows trust scores calculated from log behavior.
- Logs Viewer: provides a filterable table of parsed log events.
- Activity Summary: shows message count and device activity charts.

## How to Run
Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend in separate terminals:

```bash
python -m cloud_server.server
python -m fog_gateway.gateway
```

Generate real events:

```bash
python -m iot_device.device
python -m attacks.fake_device_attack
python -m attacks.replay_attack
python -m attacks.flooding_attack
```

Start the dashboard:

```bash
streamlit run dashboard/app.py
```

If `streamlit` is not recognized, use the Python module form after installing
dependencies:

```bash
python -m pip install -r requirements.txt
python -m streamlit run dashboard/app.py
```

You can also use the helper launcher:

```bash
python run_dashboard.py
```

## Important
If the dashboard is empty, it means the log files do not exist yet. Start the
backend and generate normal or attack traffic first.
