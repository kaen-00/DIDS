### agent.py
import time
import random
import requests
import joblib
import psutil
from trust_utils import calculate_trust_score

# Change this to your central server IP
CENTRAL_ENGINE_URL = "http://192.168.1.20:5000/report"
DEVICE_NAME = "pi"  # or "laptop_b" if running on Laptop B
MODEL_PATH = "intrusion_model.pkl"

# Load the trained unsupervised anomaly detection model
model = joblib.load(MODEL_PATH)

def get_features():
    # Simulated or real system metrics
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory().percent
    net_io = psutil.net_io_counters()
    packets = net_io.packets_sent + net_io.packets_recv
    return [cpu, memory, packets]

def detect_anomaly(features):
    # Returns True if anomaly is detected by the model
    prediction = model.predict([features])
    return prediction[0] == -1

def run_agent():
    while True:
        features = get_features()
        is_anomaly = detect_anomaly(features)
        trust_score = calculate_trust_score(is_anomaly)

        report = {
            "device": DEVICE_NAME,
            "trust_score": trust_score,
            "anomaly": is_anomaly
        }

        try:
            res = requests.post(CENTRAL_ENGINE_URL, json=report, timeout=5)
            print(f"Sent report: {report}, Response: {res.status_code}")
        except Exception as e:
            print(f"Failed to send report: {e}")

        time.sleep(10)  # Interval between reports

if __name__ == "__main__":
    run_agent()
