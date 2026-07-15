import http.server
import socketserver
import threading
import time
from core.active_scanner import ActiveScanner

# Define a mock web handler that simulates a leaked .env file and a leaked git HEAD
class LeakMockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecretpassword123\nDB_USER=admin")
        elif self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File Not Found")

    def log_message(self, format, *args):
        pass # Suppress logging to keep output clean

def run_mock_server(port):
    with socketserver.TCPServer(("127.0.0.1", port), LeakMockHandler) as httpd:
        httpd.serve_forever()

def main():
    port = 8888
    print(f"[+] Starting mock web server on 127.0.0.1:{port}...")
    
    # Run server in background thread
    t = threading.Thread(target=run_mock_server, args=(port,), daemon=True)
    t.start()
    time.sleep(1) # Allow server to bind

    scanner = ActiveScanner()
    
    print("\n[+] Step 1: Verifying active port status...")
    is_open = scanner.is_port_open("127.0.0.1", port)
    print(f"    Result: Port open? {is_open}")

    print("\n[+] Step 2: Running sensitive file leak audit...")
    leaks = scanner.audit_sensitive_files("127.0.0.1", port)
    print(f"    Result: Discovered Leaks: {leaks}")

    if leaks:
        print("\n[-] TEST SUCCESSFUL: Sensitive files correctly discovered!")
    else:
        print("\n[!] TEST FAILED: Leaked files were not detected.")

if __name__ == "__main__":
    main()
