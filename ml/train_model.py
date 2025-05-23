import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# Simulate or load training data
# For demonstration, we generate random "normal" data
def generate_data(n=500):
    np.random.seed(42)
    data = {
        "cpu_percent": np.random.uniform(0, 50, n),
        "ram_percent": np.random.uniform(10, 70, n),
        "disk_percent": np.random.uniform(10, 80, n),
        "net_io_sent": np.random.uniform(10000, 500000, n),
        "net_io_recv": np.random.uniform(10000, 500000, n),
        "suspicious_file_count": np.random.poisson(1, n),
        "num_remote_ips": np.random.poisson(3, n),
        "num_open_ports": np.random.poisson(5, n)
    }
    return pd.DataFrame(data)

# Prepare training data
df = generate_data()
X = df.values

# Train unsupervised model
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X)

# Save model
joblib.dump(model, "intrusion_model.pkl")
print("✅ Model trained and saved as intrusion_model.pkl")
