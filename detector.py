import pandas as pd
from sklearn.ensemble import IsolationForest

# Load the logs
df = pd.read_csv("logs.csv")

# Encode categorical data
df["location_code"] = df["location"].astype('category').cat.codes
df["agent_code"] = df["user_agent"].astype('category').cat.codes

# Feature matrix
X = df[["login_attempts", "location_code", "agent_code"]]

# Train the Isolation Forest
model = IsolationForest(contamination=0.3)
model.fit(X)

# Predict anomalies
df["anomaly"] = model.predict(X)

# Print results
print(df[["ip", "login_attempts", "location", "anomaly"]])

# Simulate blocking
for index, row in df.iterrows():
    if row["anomaly"] == -1:
        print(f"[ALERT] Blocking suspicious IP: {row['ip']} from {row['location']}")
        # To actually block on Linux, uncomment:
        # import subprocess
        # subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", row['ip'], "-j", "DROP"])
