import pandas as pd

import numpy as np

import requests, json, urllib3

from datetime import datetime

urllib3.disable_warnings()

INDEXER_URL = "https://localhost:9200"

USER = "admin"

PASS = ".z781D.cb*pV1g*7p3aBR++515++PX5p"



def get_alerts():

    r = requests.post(f"{INDEXER_URL}/wazuh-alerts-*/_search",

        json={"size":1000,"query":{"match_all":{}}},

        auth=(USER,PASS), verify=False)

    return r.json().get('hits',{}).get('hits',[])

def build_features(alerts):

    rows = []

    for a in alerts:

        src = a['_source']

        ts = src.get('@timestamp','')

        try:

            hour = datetime.fromisoformat(ts.replace('Z','+00:00')).hour

        except:

            hour = 0

        rows.append({

            'timestamp': ts,

            'agent': src.get('agent',{}).get('name','unknown'),

            'rule_level': src.get('rule',{}).get('level', 0),

            'rule_id': src.get('rule',{}).get('id', 0),

            'hour': hour,

            'after_hours': 1 if hour < 6 or hour > 20 else 0,

            'high_severity': 1 if src.get('rule',{}).get('level', 0) >= 10 else 0,

            'description': src.get('rule',{}).get('description','')

        })

    df = pd.DataFrame(rows)

    return df

def get_user_summary(df):

    summary = df.groupby('agent').agg(

        total_events=('rule_id','count'),

        avg_severity=('rule_level','mean'),

        high_severity_count=('high_severity','sum'),

        after_hours_count=('after_hours','sum'),

        unique_rules=('rule_id','nunique')

    ).reset_index()

    return summary



if __name__ == "__main__":

    alerts = get_alerts()

    df = build_features(alerts)

    summary = get_user_summary(df)

    print("Feature matrix per agent:")

    print(summary.to_string())
