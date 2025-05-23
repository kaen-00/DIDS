import os
import time
import socket
import psutil
import requests
import json
from datetime import datetime
from glob import glob

SERVER_URL = "http://<LAPTOP_A_IP>:5000/evaluate"  # Replace with actual IP

# Configuration
FILE_WATCH_PATHS = ["/home/pi/", "/etc/"]  # Adjust as needed
SUSPICIOUS_EXTENSIONS = [".sh", ".py", ".exe"]
DEVICE_ID = socket.gethostname()

def get_system_metrics():
    return {
        "cpu_percent": psutil.cpu_percent(),
        "ram_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "net_io_sent": psutil.net_io_counters().bytes_sent,
        "net_io_recv": psutil.net_io_counters().bytes_recv,
    }

def get_file_metrics():
    suspicious_files = 0
    for path in FILE_WATCH_PATHS:
        for ext in SUSPICIOUS_EXTENSIONS:
            suspicious_files += len(glob(f"{path}**/*{ext}", recursive=True))
    return {
        "suspicious_file_count": suspicious_files
    }

def get_network_metrics():
    connections = psutil.net_connections()
    remote_ips = set()
    open_ports = set()

    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED:
            if conn.raddr:
                remote_ips.add(conn.raddr.ip)
        if conn.status == psutil.CONN_LISTEN:
            open_ports.add(conn.laddr.port)

    return {
        "num_remote_ips": len(remote_ips),
        "num_open_ports": len(open_ports)
    }

def collect_features():
    features = {}
    features.update(get_system_metrics())
    features.update(get_file_metrics())
    features.update(get_network_metrics())
    return features

def send_data(features):
    payload = {
        "device_id": DEVICE_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "features": features
    }
    try:
        res = requests.post(SERVER_URL, json=payload, timeout=5)
        print(f"[{datetime.now()}] Sent data: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[{datetime.now()}] Failed to send data: {e}")

if __name__ == "__main__":
    while True:
        features = collect_features()
        send_data(features)
        time.sleep(15)  # Every 15 seconds
