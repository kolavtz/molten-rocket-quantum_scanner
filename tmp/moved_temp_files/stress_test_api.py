import urllib.request
import ssl
import time
import concurrent.futures

# Configuration
API_KEY = "qss_15b9dc7601b37c130a7ddc2908f893f35f7fb01ee96bff4a691b57e976829a81dc4ee36f0ed35c505178f4706f4fc19d"
URL = "https://127.0.0.1:5000/api/scan"
TARGET_PREFIX = "example"  # Use different targets to avoid cache hitting identically if any
NUM_REQUESTS = 5            # Keep it small to respect rate limit (60/hr) but check concurrency
CONCURRENCY = 3              # Number of threads

ctx = ssl._create_unverified_context()

def make_request(request_num):
    target = f"{TARGET_PREFIX}{request_num}.com"
    full_url = f"{URL}?target={target}"
    
    print(f"[Thread] Starting request {request_num} for {target}")
    req = urllib.request.Request(full_url)
    req.add_header("X-API-Key", API_KEY)
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            elapsed = time.time() - start_time
            print(f"[+] Request {request_num} SUCCESS ({elapsed:.2f}s): Code {resp.status}")
            return True, elapsed, resp.status
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start_time
        print(f"[-] Request {request_num} FAILED ({elapsed:.2f}s): HTTP {e.code} {e.reason}")
        # Try to read error body
        try:
            body = e.read().decode('utf-8')
            print(f"    Error Body: {body[:200]}")
        except:
             pass
        return False, elapsed, e.code
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[-] Request {request_num} ERROR ({elapsed:.2f}s): {e}")
        return False, elapsed, str(e)

print(f"Starting Stress Test: {NUM_REQUESTS} requests, {CONCURRENCY} threads...")

results = []
start_all = time.time()

with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
    # Schedule requests
    futures = [executor.submit(make_request, i) for i in range(1, NUM_REQUESTS + 1)]
    # Wait for all to finish
    for future in concurrent.futures.as_completed(futures):
        results.append(future.result())

end_all = time.time()
total_time = end_all - start_all

# Statistics
successes = sum(1 for r in results if r[0])
failures = sum(1 for r in results if not r[0])
avg_time = sum(r[1] for r in results) / len(results) if results else 0

print("\n=== Stress Test Results ===")
print(f"Total Time: {total_time:.2f} seconds")
print(f"Successes:  {successes}")
print(f"Failures:   {failures}")
print(f"Avg Response Time: {avg_time:.2f} seconds")

if failures > 0:
    print("\nWARNING: Some requests failed. This could be due to rate limiting (60/hr) or server saturation.")
