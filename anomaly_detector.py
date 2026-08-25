import pandas as pd

import numpy as np

from sklearn.ensemble import IsolationForest

from sklearn.preprocessing import StandardScaler

import json

def detect_anomalies(summary_df):

    features = ['total_events','avg_severity',

                'high_severity_count','after_hours_count',

                'unique_rules']

    X = summary_df[features].fillna(0)

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.1, random_state=42)

    model.fit(X_scaled)

    scores = model.score_samples(X_scaled)

    summary_df['anomaly_score'] = -scores

    summary_df['is_anomaly'] = model.predict(X_scaled)

    summary_df['is_anomaly'] = summary_df['is_anomaly'].map({1:0, -1:1})

    return summary_df

def compute_risk_score(row):

    score = 0

    score += min(row['anomaly_score'] * 30, 40)

    score += min(row['high_severity_count'] * 0.5, 20)

    score += min(row['after_hours_count'] * 0.05, 20)

    score += min(row['unique_rules'] * 0.5, 20)

    return min(round(score, 2), 100)

if __name__ == "__main__":

    from feature_engineering import get_alerts, build_features, get_user_summary

    alerts = get_alerts()

    df = build_features(alerts)

    summary = get_user_summary(df)

    result = detect_anomalies(summary)

    result['risk_score'] = result.apply(compute_risk_score, axis=1)

    result = result.sort_values('risk_score', ascending=False)

    print("\n=== UEBA RISK REPORT ===")

    print(result[['agent','total_events','high_severity_count',

                  'after_hours_count','anomaly_score',

                  'is_anomaly','risk_score']].to_string())


