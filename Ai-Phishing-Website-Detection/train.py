import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier

from extractor import extract_features

DATASET_PATH = "data/dataset.csv"

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError("data/dataset.csv not found! Run 'python fetch_data.py' first.")

print("[*] Reading dataset...")
raw_df = pd.read_csv(DATASET_PATH)

print("[*] Extracting feature vectors from URLs (takes ~10-20 seconds)...")
feature_rows = [extract_features(url) for url in raw_df["url"]]
X = pd.DataFrame(feature_rows)
y = raw_df["label"]

# 80% train, 20% test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"[*] Training XGBoost on {len(X_train)} samples...")
model = XGBClassifier(
    n_estimators=150,
    max_depth=5,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42
)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\n" + "="*45)
print("             EVALUATION REPORT")
print("="*45)
print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("="*45)

# Serialize the trained model and feature schema
joblib.dump(model, "phishing_model.pkl")
joblib.dump(list(X.columns), "feature_names.pkl")
print("\n[+] Exported: phishing_model.pkl & feature_names.pkl")