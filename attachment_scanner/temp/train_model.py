import pandas as pd
import lightgbm as lgb
import joblib
import os

DATASET = "training_dataset.csv"

if not os.path.exists(DATASET):
    raise FileNotFoundError("training_dataset.csv not found")

df = pd.read_csv(DATASET)

X = df.drop("label", axis=1)
y = df["label"]

model = lgb.LGBMClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=6
)

model.fit(X, y)

os.makedirs("attachment_scanner/models", exist_ok=True)

joblib.dump(model, "attachment_scanner/models/malware_model.pkl")

print("Model trained successfully")