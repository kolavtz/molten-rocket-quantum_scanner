import requests
import urllib3
urllib3.disable_warnings()

url = 'https://127.0.0.1:5000/results/d093e76d'
try:
    r = requests.get(url, verify=False, timeout=10)
    print('Status:', r.status_code)
    print('Len:', len(r.text))
    print(r.text[:400])
except Exception as e:
    print('Request error:', e)
