from flask import Flask, render_template_string

from feature_engineering import get_alerts, build_features, get_user_summary

from anomaly_detector import detect_anomalies, compute_risk_score

app = Flask(__name__)



def get_report():

    alerts = get_alerts()

    df = build_features(alerts)

    summary = get_user_summary(df)

    result = detect_anomalies(summary)

    result['risk_score'] = result.apply(compute_risk_score, axis=1)

    result = result.sort_values('risk_score', ascending=False)

    return result, len(alerts)



def get_recent_alerts():

    raw = get_alerts()

    alerts = []

    for a in raw[:20]:

        src = a['_source']

        alerts.append({

            'agent': src.get('agent',{}).get('name','unknown'),

            'rule_desc': src.get('rule',{}).get('description',''),

            'level': src.get('rule',{}).get('level', 0),

            'timestamp': src.get('@timestamp','')

        })

    return alerts



HTML = open('/home/socadmin/ueba-engine/template.html').read()

@app.route('/')
def index():
    data, total = get_report()
    high_count = len(data[data['risk_score'] >= 60])
    alerts = get_recent_alerts()
    return render_template_string(HTML, data=data, total=total,
        high_count=high_count, agent_count=len(data), alerts=alerts)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
