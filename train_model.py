import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# === Dummy training data ===
data = pd.DataFrame({
    "file_size": [1234, 2222, 1024, 50000, 23456],
    "entropy": [5.2, 7.8, 6.3, 1.0, 8.5],
    "unique_bytes": [128, 255, 100, 20, 240],
    "ascii_ratio": [0.6, 0.1, 0.3, 0.8, 0.2],
    "label": [0, 1, 0, 1, 1]  # 1 = malware
})

# === Train the model ===
X = data.drop("label", axis=1)
y = data["label"]

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# === Save the model to scanner/models/ ===
os.makedirs("scanner/models", exist_ok=True)
joblib.dump(model, "scanner/models/rf_model.pkl")
print("✅ Model saved to scanner/models/rf_model.pkl")
