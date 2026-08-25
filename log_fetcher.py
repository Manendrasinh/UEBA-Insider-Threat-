import requests, json, urllib3

urllib3.disable_warnings()

INDEXER_URL = "https://localhost:9200"

USER = "admin"

PASS = ".z781D.cb*pV1g*7p3aBR++515++PX5p"

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
