import socket
import threading
import json
import sys

BUFFER_SIZE = 65535


def log(msg: str):
    print(msg, flush=True)


# ---------- TCP FORWARDER CORE ----------

def pipe(src: socket.socket, dst: socket.socket):
    """Bidirectional pipe between src and dst sockets."""
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        # Normal when one side closes abruptly
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


def handle_client(client_sock: socket.socket, remote_host: str, remote_port: int, local_desc: str):
    """Handle a single incoming connection and forward to remote."""
    try:
        client_addr = client_sock.getpeername()
    except OSError:
        client_addr = ("?", 0)

    log(
        f"[+] {local_desc} new connection from "
        f"{client_addr[0]}:{client_addr[1]} -> {remote_host}:{remote_port}"
    )

    try:
        remote_sock = socket.create_connection((remote_host, remote_port), timeout=10)
    except Exception as e:
        log(f"[!] Failed to connect to remote {remote_host}:{remote_port}: {e}")
        try:
            client_sock.close()
        except:
            pass
        return

    t1 = threading.Thread(target=pipe, args=(client_sock, remote_sock), daemon=True)
    t2 = threading.Thread(target=pipe, args=(remote_sock, client_sock), daemon=True)
    t1.start()
    t2.start()


def start_listener(local_host: str, local_port: int, remote_host: str, remote_port: int):
    """Start a TCP listener on local_host:local_port that forwards to remote_host:remote_port."""
    local_desc = f"{local_host}:{local_port}"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((local_host, local_port))
    s.listen(100)
    log(f"[+] Listening on {local_desc} -> forwarding to {remote_host}:{remote_port}")

    while True:
        client_sock, _ = s.accept()
        t = threading.Thread(
            target=handle_client,
            args=(client_sock, remote_host, remote_port, local_desc),
            daemon=True,
        )
        t.start()


# ---------- CONFIG FETCH FROM SERVER ----------

def fetch_service_config(server_host: str, server_port: int, secret: str) -> dict:
    """
    Connect to your existing config server, send the shared secret,
    and receive the config file contents.

    Expects config to be JSON like:
        {"telnet": 2323, "ssh": 2222}
    """
    log(f"[+] Connecting to config server at {server_host}:{server_port}...")
    with socket.create_connection((server_host, server_port), timeout=10) as sock:
        # Your server expects just the secret (one line)
        payload = (secret.strip() + "\n").encode("utf-8")
        sock.sendall(payload)

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    if not chunks:
        raise RuntimeError("No data received from config server")

    text = b"".join(chunks).decode("utf-8", errors="ignore").strip()
    log(f"[+] Raw config from server:\n{text}")

    if text.startswith("ERROR"):
        raise RuntimeError(f"Server returned an error: {text}")

    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse config as JSON: {e}")

    if not isinstance(cfg, dict):
        raise RuntimeError("Config JSON must be an object like {'telnet': 2323, ...}")

    return cfg


# ---------- MAIN INTERACTIVE CLIENT ----------

def main():
    print("=== Honeypot Client Agent ===")
    print("This will expose local IPs/ports on THIS machine and forward traffic to")
    print("honeypot services on the SERVER based on the config it sends.\n")

    server_host = input("Config server IP/hostname: ").strip()
    if not server_host:
        print("Config server is required.")
        sys.exit(1)

    server_port_str = input("Config server port [8443]: ").strip() or "8443"
    try:
        server_port = int(server_port_str)
    except ValueError:
        print("Invalid port number.")
        sys.exit(1)

    secret = input("Shared secret: ").strip()
    if not secret:
        print("Shared secret is required.")
        sys.exit(1)

    # 1) Fetch service -> port config from the server
    try:
        services = fetch_service_config(server_host, server_port, secret)
    except Exception as e:
        print(f"[!] Could not fetch config: {e}")
        sys.exit(1)

    if not services:
        print("[!] Config has no services. Nothing to map.")
        sys.exit(1)

    # Example: services = {"telnet": 2323, "ssh": 2222}
    print("\nAvailable honeypot services from server:")
    service_items = list(services.items())
    for idx, (svc_name, svc_port) in enumerate(service_items, start=1):
        print(f"  {idx}. {svc_name}  (remote port: {svc_port})")

    print(
        "\nYou can now map ANY local IP and ANY local port on this client\n"
        "to one of the services on the server.\n"
        "Example: local 0.0.0.0:80 -> ssh(2222) on server\n"
    )

    mappings = []

    while True:
        choice = input(
            "Select service by number (or press Enter to finish adding mappings): "
        ).strip()

        if choice == "":
            break

        try:
            idx = int(choice)
            if idx < 1 or idx > len(service_items):
                print("Invalid choice.")
                continue
        except ValueError:
            print("Please enter a valid number.")
            continue

        svc_name, svc_remote_port = service_items[idx - 1]
        print(f"[*] Selected service: {svc_name} (remote port: {svc_remote_port})")

        local_ip = input(
            "Local IP to listen on [0.0.0.0 => all IPs on client]: "
        ).strip() or "0.0.0.0"

        local_port_str = input("Local port to expose (e.g. 22, 80, 8080): ").strip()
        if not local_port_str:
            print("Local port is required.")
            continue
        try:
            local_port = int(local_port_str)
        except ValueError:
            print("Invalid local port. Must be an integer.")
            continue

        # Remote IP: usually the same host as the config server.
        # If your honeypot lives elsewhere, you can:
        #   - put that IP into the config file instead, or
        #   - add a separate "server_ip" field.
        remote_ip = server_host

        # Remote port is fixed by the service chosen
        remote_port = int(svc_remote_port)

        mappings.append(
            {
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "service": svc_name,
            }
        )

        print(
            f"[+] Added mapping: local {local_ip}:{local_port} -> "
            f"{svc_name}@{remote_ip}:{remote_port}\n"
        )

    if not mappings:
        print("No mappings defined. Exiting.")
        sys.exit(0)

    print("\n[+] Starting listeners for all mappings...\n")

    # 2) Start listeners for each mapping
    for m in mappings:
        t = threading.Thread(
            target=start_listener,
            args=(
                m["local_ip"],
                int(m["local_port"]),
                m["remote_ip"],
                int(m["remote_port"]),
            ),
            daemon=True,
        )
        t.start()
        log(
            f"[+] Mapping active: local {m['local_ip']}:{m['local_port']} "
            f"-> {m['service']}@{m['remote_ip']}:{m['remote_port']}"
        )

    print("\n[+] All listeners started.")
    print("[+] Any traffic hitting those local IP:port pairs on THIS client")
    print("    will be forwarded to the honeypot services on the SERVER.")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        print("\n[+] Shutting down agent.")


if __name__ == "__main__":
    main()

