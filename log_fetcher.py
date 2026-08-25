import requests, json, urllib3

urllib3.disable_warnings()

INDEXER_URL = "https://localhost:9200"

USER = "admin"

from config import PASS

def get_alerts():

    r = requests.post(f"{INDEXER_URL}/wazuh-alerts-*/_search",

        json={"size":500,"query":{"match_all":{}}},

        auth=(USER,PASS), verify=False)

    return r.json().get('hits',{}).get('hits',[])

if __name__ == "__main__":

    alerts = get_alerts()

    print(f"Fetched {len(alerts)} alerts")

    for a in alerts[:3]:

        print(json.dumps(a['_source'].get('rule',{}), indent=2))
