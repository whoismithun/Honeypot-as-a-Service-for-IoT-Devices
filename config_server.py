import socket
import threading
import os

# ------------ CONFIGURATION ------------
HOST = "0.0.0.0"   # Listen on all network interfaces
PORT = 8443
SHARED_SECRET = "mysharedsecret123"     # <-- change this
CONFIG_FILE = "./customer_config_settings.txt"
# ---------------------------------------

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    try:
        # Receive the shared secret (limit to 1024 bytes)
        received = conn.recv(1024).decode().strip()
        print(f"[*] Received secret: {received}")

        if received != SHARED_SECRET:
            conn.sendall(b"ERROR: Invalid shared secret\n")
            print("[-] Invalid secret, closing connection.")
            return

        # If secret is correct, read the file
        if not os.path.exists(CONFIG_FILE):
            conn.sendall(b"ERROR: Config file not found\n")
            print("[-] Config file missing.")
            return

        with open(CONFIG_FILE, "r") as f:
            data = f.read()

        # Send file contents
        conn.sendall(data.encode())
        print("[+] Sent configuration successfully.")

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        conn.close()
        print(f"[+] Connection with {addr} closed.")


def start_server():
    print(f"[+] Starting TCP server on port {PORT}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print("[+] Server is running and waiting for connections...")

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.start()


if __name__ == "__main__":
    start_server()
