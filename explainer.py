import shap

import numpy as np

import pandas as pd

from sklearn.ensemble import IsolationForest

from sklearn.preprocessing import StandardScaler

def explain_risk(summary_df):

    features = ['total_events','avg_severity',

                'high_severity_count','after_hours_count',

                'unique_rules']

    X = summary_df[features].fillna(0)

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.1, random_state=42)

    model.fit(X_scaled)

    explainer = shap.Explainer(model.score_samples, X_scaled)

    shap_values = explainer(X_scaled)

    return shap_values, features, summary_df

def generate_explanation(agent, shap_vals, features, row):

    contributions = dict(zip(features, shap_vals))

    top = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:3]

    lines = [f"\n=== RISK EXPLANATION: {agent} ==="]

    for feat, val in top:

        direction = "HIGH" if val > 0 else "LOW"

        lines.append(f"  - {feat}: {direction} contribution ({val:.3f})")

    lines.append(f"  after_hours_count actual value: {int(row['after_hours_count'])}")

    lines.append(f"  high_severity_count actual value: {int(row['high_severity_count'])}")

    return "\n".join(lines)

if __name__ == "__main__":

    from feature_engineering import get_alerts, build_features, get_user_summary

    from anomaly_detector import detect_anomalies, compute_risk_score

    alerts = get_alerts()

    df = build_features(alerts)

    summary = get_user_summary(df)

    result = detect_anomalies(summary)

    result['risk_score'] = result.apply(compute_risk_score, axis=1)

    shap_values, features, result = explain_risk(result)

    for i, row in result.iterrows():

        print(generate_explanation(row['agent'], shap_values.values[i], features, row))
