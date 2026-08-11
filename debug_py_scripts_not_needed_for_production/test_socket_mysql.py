import socket
import time

def test_mysql_socket():
    host = "::1"
    port = 3306
    print(f"[*] Connecting to socket {host}:{port}...")
    
    try:
        # Create IPv6 socket
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2.0)
        
        start = time.time()
        s.connect((host, port))
        print(f"[✅] Socket connected in {time.time() - start:.3f}s")
        
        print("[*] Waiting for MySQL greeting packet...")
        s.settimeout(3.0)
        data = s.recv(1024)
        print(f"[✅] Received {len(data)} bytes: {repr(data[:60])}")
        s.close()
        
    except Exception as e:
        print(f"[!] Socket test failed: {e}")

if __name__ == "__main__":
    test_mysql_socket()
