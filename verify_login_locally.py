import urllib.request
import urllib.error
import ssl

def main():
    url = "https://127.0.0.1:5000/login"
    print(f"[*] GET {url}...")
    try:
        # Create unverified SSL context to bypass self-signed cert blocker
        context = ssl._create_unverified_context()
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=context, timeout=5) as r:
            print(f"[✅] Status: {r.status}")
            print(f"[*] Response Headers: {r.headers}")
            body = r.read().decode('utf-8')
            print(f"[*] Response Body (first 500 chars): {body[:500]}")
            
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.reason}")
        # Read error body if available
        try:
             print(f"[*] Error Body: {e.read().decode('utf-8')[:500]}")
        except:
             pass
    except Exception as e:
        print(f"[!] Request failed: {e}")

if __name__ == "__main__":
    main()

