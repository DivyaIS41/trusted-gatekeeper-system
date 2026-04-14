"""
Trusted Gatekeeper System Dashboard
=====================================
Reads real backend log files and visualizes the Zero-Trust IoT-Fog-Cloud security pipeline.
No fake data. No backend modifications. Log files must be generated first by running
the backend scripts.

Log files read:
  - logs/fog_security.log
  - logs/cloud_audit.log

Run with:
  streamlit run dashboard/app.py
  python -m streamlit run dashboard/app.py
"""

import ast
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st

# ─── Path Configuration ──────────────────────────────────────────────────────

# Resolve log paths relative to project root (parent of dashboard/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FOG_LOG_PATH = PROJECT_ROOT / "logs" / "fog_security.log"
CLOUD_LOG_PATH = PROJECT_ROOT / "logs" / "cloud_audit.log"

# Attack event types recognised from logs
ATTACK_EVENTS = {
    "fake_device_attack",
    "replay_attack",
    "flooding_attack",
    "invalid_encrypted_message",
    "suspicious_timestamp",
    "malformed_message",
}

BLOCKED_EVENTS = {"blocked_message"} | ATTACK_EVENTS
SUSPICIOUS_EVENTS = {"suspicious_message", "suspicious_timestamp"}


# ─── Log Parsing ─────────────────────────────────────────────────────────────

def parse_log_line(raw_line: str, source: str) -> Optional[dict]:
    """
    Parse one log line of the form:
      TIMESTAMP | event=EVENT | reason=REASON | message={DICT}

    Returns a flat dict with extracted fields, or None on parse failure.
    """
    line = raw_line.strip()
    if not line:
        return None

    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 2:
        return None

    record = {
        "source": source,
        "raw": line,
        "timestamp": "",
        "event_type": "",
        "reason": "",
        "device_id": "unknown",
        "message": {},
        "action_taken": "",
    }

    # First segment is always the timestamp
    record["timestamp"] = parts[0]

    for segment in parts[1:]:
        if segment.startswith("event="):
            record["event_type"] = segment[len("event="):]
        elif segment.startswith("reason="):
            record["reason"] = segment[len("reason="):]
        elif segment.startswith("message="):
            raw_dict = segment[len("message="):]
            try:
                parsed = ast.literal_eval(raw_dict)
                if isinstance(parsed, dict):
                    record["message"] = parsed
            except Exception:
                record["message"] = {}

    # Extract device_id from multiple possible locations in the message dict
    msg = record["message"]
    record["device_id"] = (
        msg.get("device_id")
        or msg.get("original_message", {}).get("device_id")
        or msg.get("blocked_message", {}).get("device_id")
        or "unknown"
    )

    # Derive action_taken from event type for readability
    et = record["event_type"]
    if et == "accepted_message" or (
        source == "Cloud Server" and et != "blocked_message"
    ):
        record["action_taken"] = "Forwarded to Cloud"
    elif et in BLOCKED_EVENTS:
        record["action_taken"] = "Blocked"
    elif et in SUSPICIOUS_EVENTS:
        record["action_taken"] = "Flagged Suspicious"
    else:
        record["action_taken"] = "Logged"

    return record


def load_log_file(path: Path, source: str) -> List[dict]:
    """
    Read a log file and return a list of parsed record dicts.
    Returns an empty list if the file doesn't exist or is unreadable.
    """
    if not path.exists():
        return []
    records = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                rec = parse_log_line(line, source)
                if rec:
                    records.append(rec)
    except OSError:
        pass
    return records


def load_all_logs() -> pd.DataFrame:
    """
    Load and merge fog and cloud logs into a single sorted DataFrame.
    Returns an empty DataFrame with the expected columns if no logs exist.
    """
    fog_records = load_log_file(FOG_LOG_PATH, source="Fog Gateway")
    cloud_records = load_log_file(CLOUD_LOG_PATH, source="Cloud Server")

    all_records = fog_records + cloud_records

    columns = [
        "timestamp", "source", "device_id", "event_type",
        "action_taken", "reason", "message", "raw",
    ]

    if not all_records:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(all_records, columns=columns)
    # Sort by timestamp string (ISO format sorts correctly lexicographically)
    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    return df


# ─── Category Helpers ─────────────────────────────────────────────────────────

def categorise(event_type: str, source: str = "") -> str:
    """Return 'accepted', 'suspicious', 'blocked', or 'attack' for an event."""
    if event_type == "accepted_message":
        return "accepted"
    if source == "Cloud Server" and event_type != "blocked_message":
        return "accepted"
    if event_type in SUSPICIOUS_EVENTS:
        return "suspicious"
    if event_type in ATTACK_EVENTS:
        return "attack"
    if event_type in BLOCKED_EVENTS:
        return "blocked"
    return "info"


# ─── Trust Score Calculation ──────────────────────────────────────────────────

def calculate_trust_scores(df: pd.DataFrame) -> Dict[str, int]:
    """
    Derive a simple trust score per device from the log DataFrame.

    Scoring rules:
      Start:              80
      accepted_message:   +2  (capped at 100)
      suspicious:         -10
      blocked_message:    -20
      fake_device_attack:   0 (force to 0)
      flooding_attack:    -30
      replay_attack:      -15
    """
    if df.empty:
        return {}

    scores: Dict[str, int] = {}

    # Process in chronological order (df is newest-first, so reverse)
    for _, row in df[::-1].iterrows():
        device = row["device_id"]
        et = row["event_type"]

        if device == "unknown":
            continue

        if device not in scores:
            scores[device] = 80

        if et == "accepted_message" or (
            row["source"] == "Cloud Server" and et != "blocked_message"
        ):
            scores[device] = min(100, scores[device] + 2)
        elif et in SUSPICIOUS_EVENTS:
            scores[device] = max(0, scores[device] - 10)
        elif et == "blocked_message":
            scores[device] = max(0, scores[device] - 20)
        elif et == "fake_device_attack":
            scores[device] = 0
        elif et == "flooding_attack":
            scores[device] = max(0, scores[device] - 30)
        elif et == "replay_attack":
            scores[device] = max(0, scores[device] - 15)

    return scores


# ─── Dashboard Sections ───────────────────────────────────────────────────────

def render_sidebar(df: pd.DataFrame):
    """
    Sidebar: log source status, auto-refresh controls, and startup instructions.
    """
    st.sidebar.title("⚙️ Controls")

    # ── Log file status ──
    st.sidebar.subheader("📂 Log File Status")

    fog_exists = FOG_LOG_PATH.exists()
    cloud_exists = CLOUD_LOG_PATH.exists()

    if fog_exists:
        fog_size = FOG_LOG_PATH.stat().st_size
        st.sidebar.success(f"✅ fog_security.log ({fog_size:,} bytes)")
    else:
        st.sidebar.error("❌ fog_security.log — not found")

    if cloud_exists:
        cloud_size = CLOUD_LOG_PATH.stat().st_size
        st.sidebar.success(f"✅ cloud_audit.log ({cloud_size:,} bytes)")
    else:
        st.sidebar.error("❌ cloud_audit.log — not found")

    # ── Startup instructions when logs are missing ──
    if not fog_exists or not cloud_exists:
        st.sidebar.markdown("---")
        st.sidebar.subheader("🚀 How to generate logs")
        st.sidebar.code(
            "# Terminal 1 — Cloud Server\n"
            "python -m cloud_server.server\n\n"
            "# Terminal 2 — Fog Gateway\n"
            "python -m fog_gateway.gateway\n\n"
            "# Terminal 3 — IoT Device\n"
            "python -m iot_device.device\n\n"
            "# Optional — Attack Simulations\n"
            "python -m attacks.fake_device_attack\n"
            "python -m attacks.replay_attack\n"
            "python -m attacks.flooding_attack",
            language="bash",
        )

    # ── Auto-refresh controls ──
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔄 Refresh Controls")

    auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
    interval = st.sidebar.slider(
        "Refresh interval (seconds)", min_value=2, max_value=30, value=5,
        disabled=not auto_refresh,
    )
    refresh_now = st.sidebar.button("🔃 Refresh Now")

    if refresh_now:
        st.rerun()

    # ── Record count ──
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Total log records loaded: **{len(df)}**")
    st.sidebar.caption(f"Last refreshed: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")

    return auto_refresh, interval


def apply_auto_refresh(auto_refresh: bool, interval: int):
    """Refresh the dashboard after all sections have rendered."""

    if auto_refresh:
        time.sleep(interval)
        st.rerun()


def render_system_status(df: pd.DataFrame):
    """
    Section 1 — System Status banner.
    Shows NORMAL (green) when no recent attacks/blocks exist,
    ALERT (red) when attacks or blocked messages are detected.
    """
    st.header("🛡️ System Status")

    logs_missing = df.empty

    if logs_missing:
        st.warning(
            "⚠️ **No backend logs found yet.**  \n"
            "Start the Cloud Server, Fog Gateway, and IoT Device (or attack scripts) first.  \n"
            "See the sidebar for exact commands."
        )
        return

    recent_attacks = df[df["event_type"].isin(ATTACK_EVENTS | BLOCKED_EVENTS)]

    if recent_attacks.empty:
        st.success("🟢 **NORMAL** — No attack or block events detected.")
    else:
        attack_count = len(recent_attacks)
        st.error(
            f"🔴 **ALERT** — {attack_count} attack / block event(s) detected in logs. "
            "Review the Attack Detection panel below."
        )


def render_live_data_flow(df: pd.DataFrame):
    """
    Section 2 — Live Data Flow.
    Displays IoT → Fog → Cloud flow with accepted / suspicious / blocked counts.
    """
    st.header("📡 Live Data Flow")

    accepted = int(
        (
            (df["event_type"] == "accepted_message")
            | ((df["source"] == "Cloud Server") & (df["event_type"] != "blocked_message"))
        ).sum()
    )
    suspicious = int(df["event_type"].isin(SUSPICIOUS_EVENTS).sum())
    blocked = int(df["event_type"].isin(BLOCKED_EVENTS).sum())

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", len(df))
    col2.metric("✅ Accepted", accepted)
    col3.metric("⚠️ Suspicious", suspicious)
    col4.metric("🚫 Blocked / Attacks", blocked)

    # Visual pipeline arrow
    st.markdown(
        """
        <div style='text-align:center; font-size:1.1rem; padding:12px 0;
                    color:#aaa; letter-spacing:0.05em;'>
          <span style='color:#4caf50;'>IoT Device</span>
          &nbsp;→&nbsp;
          <span style='color:#2196f3;'>Fog Gateway</span>
          &nbsp;→&nbsp;
          <span style='color:#9c27b0;'>Cloud Server</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if df.empty:
        st.info("No messages recorded yet. Run the backend scripts to populate logs.")


def render_message_monitoring(df: pd.DataFrame):
    """
    Section 3 — Message Monitoring Panel.
    Colour-coded table of all events with expandable JSON per row.
    """
    st.header("📋 Message Monitoring")

    if df.empty:
        st.info("No messages yet. Logs are empty or missing.")
        return

    # Build a display copy with a category column
    display_df = df.copy()
    display_df["category"] = display_df.apply(
        lambda row: categorise(row["event_type"], row["source"]),
        axis=1,
    )

    # Filter selector
    category_filter = st.selectbox(
        "Filter by category",
        ["All", "Accepted", "Suspicious", "Blocked", "Attack"],
        key="msg_filter",
    )

    if category_filter != "All":
        display_df = display_df[
            display_df["category"] == category_filter.lower()
        ]

    if display_df.empty:
        st.info(f"No '{category_filter}' events found.")
        return

    # Colour coding legend
    st.markdown(
        "🟢 **Accepted** &nbsp;&nbsp; 🟡 **Suspicious** &nbsp;&nbsp; 🔴 **Blocked / Attack**",
        unsafe_allow_html=True,
    )
    st.markdown("")

    for _, row in display_df.head(100).iterrows():
        cat = row["category"]
        if cat == "accepted":
            colour = "#1e4620"
            icon = "✅"
        elif cat == "suspicious":
            colour = "#4a3a00"
            icon = "⚠️"
        else:
            colour = "#4a1010"
            icon = "🚫"

        with st.expander(
            f"{icon} [{row['timestamp']}] {row['event_type']} — {row['device_id']}"
        ):
            col_a, col_b = st.columns(2)
            col_a.markdown(f"**Source:** {row['source']}")
            col_a.markdown(f"**Device ID:** `{row['device_id']}`")
            col_a.markdown(f"**Event:** `{row['event_type']}`")
            col_b.markdown(f"**Action:** {row['action_taken']}")
            col_b.markdown(f"**Reason:** {row['reason']}")
            st.code(str(row["message"]), language="python")


def render_attack_detection(df: pd.DataFrame):
    """
    Section 4 — Attack Detection Panel.
    Lists detected attacks and shows a frequency bar chart.
    """
    st.header("⚔️ Attack Detection")

    attacks_df = df[df["event_type"].isin(ATTACK_EVENTS | BLOCKED_EVENTS)].copy()

    if attacks_df.empty:
        st.success("No attacks detected in current logs.")
        return

    st.error(f"**{len(attacks_df)} attack/block event(s) detected.**")

    # ── Attack frequency bar chart ──
    freq = (
        attacks_df["event_type"]
        .value_counts()
        .reset_index()
    )
    freq.columns = ["Attack Type", "Count"]
    st.bar_chart(freq.set_index("Attack Type"))

    # ── Attack detail table ──
    st.subheader("Attack Event Details")
    detail_cols = ["timestamp", "event_type", "device_id", "action_taken", "reason"]
    st.dataframe(
        attacks_df[detail_cols].rename(columns={
            "timestamp": "Time",
            "event_type": "Attack Type",
            "device_id": "Device ID",
            "action_taken": "Action Taken",
            "reason": "Reason",
        }),
        use_container_width=True,
        hide_index=True,
    )


def render_trust_scores(df: pd.DataFrame):
    """
    Section 5 — Device Trust Score Panel.
    Calculates and displays a trust score progress bar per device.

    Scoring:
      Start: 80 | Accepted: +2 | Suspicious: -10 | Blocked: -20
      Fake device: 0 | Flooding: -30 | Replay: -15
    """
    st.header("🔐 Device Trust Scores")

    if df.empty:
        st.info("No device data yet.")
        return

    scores = calculate_trust_scores(df)

    if not scores:
        st.info("No identifiable devices in logs.")
        return

    for device, score in sorted(scores.items()):
        if score >= 70:
            colour = "normal"
            badge = "🟢"
        elif score >= 40:
            colour = "normal"
            badge = "🟡"
        else:
            colour = "normal"
            badge = "🔴"

        label = f"{badge} `{device}` — Trust Score: **{score}/100**"
        st.markdown(label)
        st.progress(score / 100)


def render_logs_viewer(df: pd.DataFrame):
    """
    Section 6 — Logs Viewer.
    Filterable, scrollable table of all log entries.
    """
    st.header("📜 Logs Viewer")

    if df.empty:
        st.info("No log records to display.")
        return

    # Category filter buttons via selectbox
    filter_choice = st.selectbox(
        "Show events",
        ["All", "Accepted", "Suspicious", "Blocked", "Attacks"],
        key="log_filter",
    )

    filtered = df.copy()
    if filter_choice == "Accepted":
        filtered = filtered[
            (filtered["event_type"] == "accepted_message")
            | ((filtered["source"] == "Cloud Server") & (filtered["event_type"] != "blocked_message"))
        ]
    elif filter_choice == "Suspicious":
        filtered = filtered[filtered["event_type"].isin(SUSPICIOUS_EVENTS)]
    elif filter_choice == "Blocked":
        filtered = filtered[filtered["event_type"].isin(BLOCKED_EVENTS)]
    elif filter_choice == "Attacks":
        filtered = filtered[filtered["event_type"].isin(ATTACK_EVENTS)]

    display_cols = ["timestamp", "source", "device_id", "event_type", "action_taken", "reason"]
    st.dataframe(
        filtered[display_cols].rename(columns={
            "timestamp": "Timestamp",
            "source": "Source",
            "device_id": "Device ID",
            "event_type": "Event Type",
            "action_taken": "Action Taken",
            "reason": "Reason",
        }),
        use_container_width=True,
        hide_index=True,
        height=400,
    )
    st.caption(f"Showing {len(filtered)} of {len(df)} total records.")


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="Trusted Gatekeeper System",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title("🛡️ Trusted Gatekeeper System Dashboard")
    st.caption(
        "Zero-Trust IoT → Fog → Cloud security pipeline — real-time log visualisation.  "
        "All data is read directly from backend log files."
    )

    # ── Load logs once per render cycle ──
    df = load_all_logs()

    # ── Sidebar controls ──
    auto_refresh, interval = render_sidebar(df)

    # ── Main content sections ──
    render_system_status(df)
    st.divider()

    render_live_data_flow(df)
    st.divider()

    render_message_monitoring(df)
    st.divider()

    render_attack_detection(df)
    st.divider()

    render_trust_scores(df)
    st.divider()

    render_logs_viewer(df)

    apply_auto_refresh(auto_refresh, interval)


if __name__ == "__main__":
    main()
