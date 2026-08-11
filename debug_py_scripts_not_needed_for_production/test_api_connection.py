import urllib.request
import ssl

ctx = ssl._create_unverified_context()

url = "https://127.0.0.1:5000/api/scan?target=google.com"

try:
    print(f"Hitting: {url}")
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        print(f"Status Code: {resp.status}")
        print(f"Response: {resp.read().decode('utf-8')[:200]}...")
except urllib.error.HTTPError as e:
    print(f"HTTP Error: {e.code} {e.reason}")
    print(f"Response: {e.read().decode('utf-8')[:200]}...")
except Exception as e:
    print(f"Error: {e}")
