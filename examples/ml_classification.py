#!/usr/bin/env python3
"""Machine learning classification with JoyfulJay features.

This example demonstrates using extracted features with scikit-learn
for traffic classification.

Usage:
    python ml_classification.py train.pcap test.pcap

Requirements:
    pip install scikit-learn
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

import joyfuljay as jj

# Check for scikit-learn
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("This example requires scikit-learn:")
    print("  pip install scikit-learn")
    sys.exit(1)


def extract_features(pcap_path: str) -> pd.DataFrame:
    """Extract ML-ready features from a PCAP file."""
    config = jj.Config(
        features=["timing", "size", "tcp", "entropy", "fingerprint"],
        bidirectional_split=True,  # Separate forward/backward features
    )
    pipeline = jj.Pipeline(config)
    return pipeline.process_pcap(pcap_path)


def prepare_dataset(df: pd.DataFrame, label_column: str = "label") -> tuple:
    """Prepare features for ML training.

    Args:
        df: DataFrame with features and labels.
        label_column: Name of the label column.

    Returns:
        Tuple of (X, y, feature_names).
    """
    # Drop non-numeric columns and the label
    feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Remove label if present
    if label_column in feature_cols:
        feature_cols.remove(label_column)

    # Remove any columns with all NaN
    feature_cols = [col for col in feature_cols if not df[col].isna().all()]

    X = df[feature_cols].fillna(0).values
    y = df[label_column].values if label_column in df.columns else None

    return X, y, feature_cols


def train_classifier(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """Train a Random Forest classifier."""
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    return clf


def main() -> None:
    """Demonstrate ML classification with JoyfulJay features."""
    print("JoyfulJay ML Classification Example")
    print("=" * 50)

    # For demonstration, we'll create synthetic labeled data
    # In practice, you would have labeled PCAP files

    if len(sys.argv) >= 2:
        pcap_path = sys.argv[1]
        print(f"\nExtracting features from: {pcap_path}")
        df = extract_features(pcap_path)
    else:
        # Generate synthetic demo data
        print("\nNo PCAP provided, generating synthetic demo data...")
        np.random.seed(42)
        n_samples = 500

        df = pd.DataFrame(
            {
                "iat_mean_fwd": np.random.exponential(0.05, n_samples),
                "iat_mean_bwd": np.random.exponential(0.05, n_samples),
                "pkt_len_mean_fwd": np.random.normal(500, 200, n_samples),
                "pkt_len_mean_bwd": np.random.normal(800, 300, n_samples),
                "entropy_mean": np.random.uniform(0, 8, n_samples),
                "tcp_syn_count": np.random.poisson(2, n_samples),
                "total_packets": np.random.poisson(50, n_samples),
            }
        )

        # Create synthetic labels (3 classes)
        df["label"] = np.random.choice(["web", "streaming", "other"], n_samples)

    print(f"Dataset shape: {df.shape}")
    print(f"Features: {len(df.columns) - 1}")

    # Prepare data
    if "label" not in df.columns:
        # Assign random labels for demo
        df["label"] = np.random.choice(["class_a", "class_b", "class_c"], len(df))

    X, y, feature_names = prepare_dataset(df)
    print(f"Numeric features: {len(feature_names)}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train classifier
    print("\nTraining Random Forest classifier...")
    clf = train_classifier(X_train_scaled, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_scaled)

    print("\nClassification Report:")
    print("-" * 50)
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    print("-" * 50)
    print(confusion_matrix(y_test, y_pred))

    # Feature importance
    print("\nTop 10 Most Important Features:")
    print("-" * 50)
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for i, idx in enumerate(indices, 1):
        print(f"  {i}. {feature_names[idx]}: {importances[idx]:.4f}")


if __name__ == "__main__":
    main()
