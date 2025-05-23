### analysis_engine.py
from flask import Flask, request, jsonify
from trust_utils import update_trust_score, get_device_status
import json
import os

app = Flask(__name__)

ALERTS_FILE = "db/alerts.json"
TRUST_THRESHOLD = 70

# Ensure alerts file exists
os.makedirs("db", exist_ok=True)
if not os.path.exists(ALERTS_FILE):
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)

@app.route("/report", methods=["POST"])
def receive_report():
    data = request.get_json()
    device = data.get("device")
    trust_score = data.get("trust_score")
    anomaly = data.get("anomaly")

    # Update trust and get status
    updated_score, status = update_trust_score(device, trust_score, anomaly)

    response = {
        "device": device,
        "trust_score": updated_score,
        "status": status
    }

    if status == "intrusion":
        alert = {
            "device": device,
            "alert": "Intrusion detected",
            "trust_score": updated_score,
            "anomaly": anomaly
        }
        with open(ALERTS_FILE, "r+") as f:
            alerts = json.load(f)
            alerts.append(alert)
            f.seek(0)
            json.dump(alerts, f, indent=2)

        print(f"[ALERT] Intrusion detected from {device}, rerouting...")

    return jsonify(response)

@app.route("/health")
def health_check():
    return "Engine is running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
