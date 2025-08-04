import socket
import datetime
import os

LISTEN_PORT = 8080
LOG_FILE = "honeypot.log"

if not os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w').close()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', LISTEN_PORT))
server_socket.listen(5)

print(f"🛡️  Honeypot listening on port {LISTEN_PORT}...")

try:
    while True:
        conn, addr = server_socket.accept()
        ip, port = addr
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        try:
            data = conn.recv(1024).decode('utf-8', errors='ignore')
        except:
            data = "[no readable data]"

        log_entry = f"[{timestamp}] Connection from {ip}:{port}\nData: {data.strip()}\n\n"
        print(log_entry)

        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)

        conn.close()

except KeyboardInterrupt:
    print("\n🚪 Honeypot stopped.")
    server_socket.close()
