# Traffic Classification with Machine Learning

Build ML models to classify encrypted network traffic using JoyfulJay features.

---

## Overview

This tutorial shows how to:
1. Extract ML-ready features from labeled PCAPs
2. Train a classifier with scikit-learn
3. Evaluate and deploy the model

---

## Prerequisites

```bash
pip install joyfuljay scikit-learn pandas
```

---

## Step 1: Prepare Labeled Data

You need PCAP files with labels. Common approaches:

**Option A: Separate files per class**
```
data/
  web_browsing/
    capture1.pcap
    capture2.pcap
  video_streaming/
    youtube1.pcap
    netflix1.pcap
  voip/
    zoom1.pcap
```

**Option B: Label CSV**
```csv
flow_id,src_ip,dst_ip,label
abc123,192.168.1.10,93.184.216.34,web
def456,192.168.1.10,142.250.185.78,video
```

---

## Step 2: Extract Features

### From Separate Directories

```python
import joyfuljay as jj
import pandas as pd
from pathlib import Path

# Feature groups effective for classification
config = jj.Config(
    features=["timing", "size", "tls", "fingerprint", "entropy"],
    bidirectional_split=True,
)
pipeline = jj.Pipeline(config)

all_data = []

# Process each labeled directory
for label_dir in Path("data").iterdir():
    if not label_dir.is_dir():
        continue

    label = label_dir.name

    for pcap_file in label_dir.glob("*.pcap"):
        df = pipeline.process_pcap(str(pcap_file))
        df["label"] = label
        df["source_file"] = pcap_file.name
        all_data.append(df)

# Combine all data
dataset = pd.concat(all_data, ignore_index=True)
print(f"Total flows: {len(dataset)}")
print(f"Labels: {dataset['label'].value_counts()}")

# Save for later use
dataset.to_csv("extracted_features.csv", index=False)
```

### Using Label CSV

```python
import joyfuljay as jj
from joyfuljay.utils import LabelLoader

# Extract features
df = jj.extract("combined_capture.pcap", features=["timing", "size", "tls"])

# Load and merge labels
loader = LabelLoader()
loader.load_csv("labels.csv", flow_id_column="flow_id", label_column="label")
labeled_df = loader.merge_with_features(df)
```

---

## Step 3: Prepare for Training

```python
import pandas as pd
from sklearn.model_selection import train_test_split

# Load extracted features
df = pd.read_csv("extracted_features.csv")

# Select numeric features only (exclude IPs, hashes, etc.)
numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()

# Remove identifiers if present
exclude = ["flow_id", "src_port", "dst_port"]
feature_cols = [c for c in numeric_cols if c not in exclude]

# Prepare X and y
X = df[feature_cols].fillna(0)
y = df["label"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")
print(f"Features: {len(feature_cols)}")
```

---

## Step 4: Train Classifier

### Random Forest (Recommended Start)

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Train
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
```

### Feature Importance

```python
import pandas as pd

# Get importance scores
importance = pd.DataFrame({
    "feature": feature_cols,
    "importance": clf.feature_importances_
}).sort_values("importance", ascending=False)

print("Top 20 Features:")
print(importance.head(20))
```

### XGBoost (Better Performance)

```python
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

# Encode labels for XGBoost
le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc = le.transform(y_test)

# Train
clf_xgb = XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf_xgb.fit(X_train, y_train_enc)

# Evaluate
y_pred_enc = clf_xgb.predict(X_test)
y_pred = le.inverse_transform(y_pred_enc)
print(classification_report(y_test, y_pred))
```

---

## Step 5: Cross-Validation

```python
from sklearn.model_selection import cross_val_score

scores = cross_val_score(clf, X, y, cv=5, scoring="f1_weighted")
print(f"Cross-validation F1: {scores.mean():.3f} (+/- {scores.std()*2:.3f})")
```

---

## Step 6: Save Model

```python
import joblib

# Save model and feature list
joblib.dump(clf, "traffic_classifier.pkl")
joblib.dump(feature_cols, "feature_columns.pkl")

# Load later
clf_loaded = joblib.load("traffic_classifier.pkl")
feature_cols_loaded = joblib.load("feature_columns.pkl")
```

---

## Step 7: Classify New Traffic

```python
import joyfuljay as jj
import joblib

# Load model
clf = joblib.load("traffic_classifier.pkl")
feature_cols = joblib.load("feature_columns.pkl")

# Extract features from new capture
config = jj.Config(
    features=["timing", "size", "tls", "fingerprint", "entropy"],
    bidirectional_split=True,
)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("new_capture.pcap")

# Prepare features (same columns as training)
X_new = df[feature_cols].fillna(0)

# Predict
predictions = clf.predict(X_new)
probabilities = clf.predict_proba(X_new)

# Add predictions to dataframe
df["predicted_label"] = predictions
df["confidence"] = probabilities.max(axis=1)

# Show results
print(df[["src_ip", "dst_ip", "predicted_label", "confidence"]].head(20))
```

---

## Best Practices

### Feature Selection

Start with these feature groups for classification:

| Group | Why |
|-------|-----|
| `timing` | IAT patterns distinguish applications |
| `size` | Packet sizes vary by protocol |
| `tls` | TLS metadata reveals application |
| `fingerprint` | Protocol-specific patterns |
| `entropy` | Encrypted vs plaintext |

### Handling Imbalanced Data

```python
from sklearn.utils.class_weight import compute_class_weight
import numpy as np

# Compute weights
classes = np.unique(y_train)
weights = compute_class_weight("balanced", classes=classes, y=y_train)
class_weights = dict(zip(classes, weights))

# Use in classifier
clf = RandomForestClassifier(class_weight=class_weights)
```

### Avoiding Overfitting

```python
# Use flow_id to prevent data leakage
# Don't let packets from same flow appear in train and test

from sklearn.model_selection import GroupShuffleSplit

groups = df["flow_id"]
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
```

---

## Example: Web vs Video vs VoIP

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Features that distinguish these traffic types
config = jj.Config(
    features=["timing", "size", "tcp"],
    bidirectional_split=True,
)
pipeline = jj.Pipeline(config)

# Key distinguishing features:
# - VoIP: Regular IAT, small packets, UDP or RTP
# - Video: Bursty, large packets, variable rate
# - Web: Request-response pattern, varied sizes

# After training, check feature importance:
# - iat_std: High for video, low for VoIP
# - pkt_len_mean: High for video, medium for web
# - burst_count: High for video
# - tcp_psh_ratio: High for web
```

---

## See Also

- [Encrypted Traffic Analysis](encrypted-traffic.md) - Tor/VPN detection
- [API Reference](../api.md) - Full API documentation
- [Feature Reference](../features.md) - All available features
