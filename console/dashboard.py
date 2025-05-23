### dashboard.py
import streamlit as st
import json
import os

ALERTS_FILE = "db/alerts.json"

st.set_page_config(page_title="DIDS Alert Dashboard", layout="wide")
st.title("\U0001F6A8 Distributed Intrusion Detection System (DIDS) Dashboard")

# Display system status
def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE, "r") as f:
        return json.load(f)

alerts = load_alerts()
st.subheader("Active Alerts")

if alerts:
    for alert in reversed(alerts[-10:]):
        with st.expander(f"Alert from {alert['device']} - Trust Score: {alert['trust_score']}"):
            st.write("**Anomaly Detected:**", alert["anomaly"])
            st.write("**Trust Score:**", alert["trust_score"])
            st.write("**Action:**", "Reroute / Block" if alert['trust_score'] < 70 else "Monitor")
else:
    st.success("No current alerts. All devices are trusted.")

st.markdown("---")
st.caption("Live IDS status. Refresh periodically for updates.")