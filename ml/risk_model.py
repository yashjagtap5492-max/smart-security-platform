import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "security_risk_model.joblib")

FEATURE_NAMES = [
    "failed_attempts",
    "unique_ips",
    "new_devices",
    "high_risk_events",
    "unusual_activity",
    "login_frequency",
    "failure_ratio",
    "account_age_days"
]


def build_training_data():
    X = np.array([
        [0, 1, 0, 0, 0, 1, 0.00, 365],
        [1, 1, 0, 0, 0, 2, 0.10, 300],
        [2, 1, 0, 0, 0, 3, 0.20, 250],
        [3, 2, 1, 0, 0, 5, 0.30, 200],
        [4, 2, 1, 1, 0, 7, 0.40, 180],
        [5, 3, 1, 1, 1, 9, 0.50, 150],
        [7, 3, 2, 2, 1, 12, 0.58, 120],
        [8, 4, 2, 2, 1, 15, 0.65, 100],
        [10, 5, 3, 3, 1, 18, 0.72, 80],
        [12, 5, 3, 4, 1, 20, 0.80, 60],
        [15, 6, 4, 5, 1, 25, 0.88, 30],
        [20, 8, 5, 6, 1, 30, 0.95, 10]
    ])

    y = np.array([
        "LOW",
        "LOW",
        "LOW",
        "MEDIUM",
        "MEDIUM",
        "MEDIUM",
        "HIGH",
        "HIGH",
        "HIGH",
        "CRITICAL",
        "CRITICAL",
        "CRITICAL"
    ])

    return X, y


def train_model():
    X, y = build_training_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=200,
                max_depth=8,
                min_samples_split=2,
                min_samples_leaf=1,
                class_weight="balanced",
                random_state=42
            )
        )
    ])

    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)

    return model


def load_model():
    if not os.path.exists(MODEL_PATH):
        return train_model()

    return joblib.load(MODEL_PATH)


def prepare_features(
    failed_attempts=0,
    unique_ips=1,
    new_devices=0,
    high_risk_events=0,
    unusual_activity=0,
    login_frequency=1,
    failure_ratio=0.0,
    account_age_days=365
):
    return np.array([[
        max(0, failed_attempts),
        max(1, unique_ips),
        max(0, new_devices),
        max(0, high_risk_events),
        1 if unusual_activity else 0,
        max(0, login_frequency),
        max(0.0, min(float(failure_ratio), 1.0)),
        max(0, account_age_days)
    ]])


def predict_risk(
    failed_attempts=0,
    unique_ips=1,
    new_devices=0,
    high_risk_events=0,
    unusual_activity=0,
    login_frequency=1,
    failure_ratio=0.0,
    account_age_days=365
):
    model = load_model()

    features = prepare_features(
        failed_attempts,
        unique_ips,
        new_devices,
        high_risk_events,
        unusual_activity,
        login_frequency,
        failure_ratio,
        account_age_days
    )

    prediction = model.predict(features)[0]

    probabilities = model.predict_proba(features)[0]

    classes = model.named_steps[
        "classifier"
    ].classes_

    probability_map = {
        str(label): round(
            float(probability) * 100,
            2
        )
        for label, probability
        in zip(classes, probabilities)
    }

    confidence = round(
        float(max(probabilities)) * 100,
        2
    )

    return {
        "risk_level": str(prediction),
        "confidence": confidence,
        "probabilities": probability_map,
        "features": {
            name: float(value)
            for name, value
            in zip(FEATURE_NAMES, features[0])
        }
    }


if __name__ == "__main__":
    result = predict_risk(
        failed_attempts=7,
        unique_ips=3,
        new_devices=2,
        high_risk_events=2,
        unusual_activity=1,
        login_frequency=12,
        failure_ratio=0.58,
        account_age_days=120
    )

    print(result)