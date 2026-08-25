from feature_engineering import get_alerts, build_features, get_user_summary

from anomaly_detector import detect_anomalies, compute_risk_score

from datetime import datetime

import json

def run_ueba():

    print(f"\n{'='*50}")

    print(f"  UEBA ENGINE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"{'='*50}")

    print("Fetching alerts from Wazuh...")

    alerts = get_alerts()

    print(f"Fetched {len(alerts)} alerts")

    df = build_features(alerts)

    summary = get_user_summary(df)

    result = detect_anomalies(summary)

    result['risk_score'] = result.apply(compute_risk_score, axis=1)

    result = result.sort_values('risk_score', ascending=False)

    return result



def print_report(result):

    print("INSIDER THREAT RISK REPORT")

    for _, row in result.iterrows():

        risk = row['risk_score']

        if risk >= 60:

            level = "HIGH RISK"

        elif risk >= 30:

            level = "MEDIUM RISK"

        else:

            level = "LOW RISK"

        print(f"\nAgent    : {row['agent']}")

        print(f"Risk     : {level} ({risk}/100)")

        print(f"Events   : {int(row['total_events'])}")

        print(f"After hrs: {int(row['after_hours_count'])}")

        print(f"High sev : {int(row['high_severity_count'])}")

        print(f"Rules    : {int(row['unique_rules'])}")

        print("-"*40)



if __name__ == "__main__":

    result = run_ueba()

    print_report(result)

