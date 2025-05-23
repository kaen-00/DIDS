from flask import Flask, request, jsonify
import joblib
import numpy as np
from datetime import datetime
import json
import os

app = Flask(__name__)

model = joblib.load("intrusion_model.pkl")
ALERT_LOG = "alerts.json"
TRUST_DB = {}

def log_alert(alert):
    if not os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "w") as f:
            json.dump([], f)

    with open(ALERT_LOG, "r") as f:
        alerts = json.load(f)

    alerts.append(alert)

    with open(ALERT_LOG, "w") as f:
        json.dump(alerts, f, indent=2)

def update_trust(device_id, is_anomaly):
    if device_id not in TRUST_DB:
        TRUST_DB[device_id] = 1.0  # full trust

    if is_anomaly:
        TRUST_DB[device_id] -= 0.1
    else:
        TRUST_DB[device_id] = min(TRUST_DB[device_id] + 0.01, 1.0)  # regain trust slowly

    TRUST_DB[device_id] = round(max(0.0, min(TRUST_DB[device_id], 1.0)), 2)
    return TRUST_DB[device_id]

@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.json
    device_id = data.get("device_id")
    timestamp = data.get("timestamp")
    features = data.get("features")

    try:
        # Convert features to model input
        X = np.array([[
            features["cpu_percent"],
            features["ram_percent"],
            features["disk_percent"],
            features["net_io_sent"],
            features["net_io_recv"],
            features["suspicious_file_count"],
            features["num_remote_ips"],
            features["num_open_ports"]
        ]])

        prediction = model.predict(X)[0]  # -1 = anomaly, 1 = normal
        is_anomaly = prediction == -1

        trust = update_trust(device_id, is_anomaly)

        if is_anomaly:
            alert = {
                "device_id": device_id,
                "timestamp": timestamp,
                "type": "Anomaly Detected",
                "trust": trust,
                "details": features
            }
            log_alert(alert)
            print(f"🚨 Anomaly detected from {device_id} | Trust: {trust}")
        else:
            print(f"[{timestamp}] {device_id} normal | Trust: {trust}")

        return jsonify({"anomaly": is_anomaly, "trust": trust}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
