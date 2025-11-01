# paste this whole file as src/honeypot.py (replace existing)
#!/usr/bin/env python3
# src/honeypot.py

import socket, threading, json, sqlite3, argparse, os, traceback, requests
from datetime import datetime

# -----------------------------
# Config
# -----------------------------
LOG_JSONL = "logs/attacks.jsonl"
DB_FILE = "logs/honeypot.db"
MAX_READ = 1024  # safe max bytes read
GEO_API = "http://ip-api.com/json/{}"  # free geolocation API

BANNERS = {
    2222: b"SSH-2.0-OpenSSH_7.9p1 FakeHoneypot\r\n",
    2121: b"220 FTP Server Ready (FakeHoneypot)\r\n",
    2323: b"Welcome to Telnet (FakeHoneypot)\r\n"
}

# -----------------------------
# DB init + migration
# -----------------------------
def init_honeypot_tables(db_file=DB_FILE):
    """Ensure tables exist and add 'location' columns if missing"""
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    # Main detailed events table (ensure location column exists)
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            banner TEXT,
            payload TEXT,
            bytes INTEGER,
            duration REAL
        )
    ''')

    # Summary table for quick lookups (honeypot_events)
    c.execute('''
        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            operation TEXT,
            src_ip TEXT,
            dst_port INTEGER,
            payload TEXT
        )
    ''')
    conn.commit()

    # Migrate: add 'location' column to both tables if it doesn't exist (SQLite ignores if exists is not supported)
    try:
        c.execute("ALTER TABLE events ADD COLUMN location TEXT")
    except sqlite3.OperationalError:
        # column already exists or other situation; ignore
        pass
    try:
        c.execute("ALTER TABLE honeypot_events ADD COLUMN location TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

# -----------------------------
# Geolocation helper
# -----------------------------
def get_geo(ip):
    """Return a short 'City, Region, Country' or 'Unknown' on failure.
       Cache or rate-limit if you make many requests in production."""
    if ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        # local/private addresses — don't geolocate
        return "Local"
    try:
        url = GEO_API.format(ip)
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            j = resp.json()
            if j.get("status") == "success":
                city = j.get("city") or ""
                region = j.get("regionName") or ""
                country = j.get("country") or ""
                parts = [p for p in (city, region, country) if p]
                if parts:
                    return ", ".join(parts)
                return country or "Unknown"
        return "Unknown"
    except Exception:
        return "Unknown"

# -----------------------------
# Logging functions
# -----------------------------
def log_event_json(event):
    os.makedirs(os.path.dirname(LOG_JSONL), exist_ok=True)
    with open(LOG_JSONL, "a") as f:
        f.write(json.dumps(event) + "\n")

def log_event_db(event, db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    # ensure columns exist; location column may be present
    c.execute('''
        INSERT INTO events (ts, src_ip, src_port, dst_port, banner, payload, bytes, duration, location)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (event['ts'], event['src_ip'], event['src_port'], event['dst_port'],
          event['banner'], event['payload'], event['bytes'], event['duration'], event.get('location')))
    conn.commit()
    conn.close()

def log_to_sql(operation, src_ip, dst_port, payload, db_file=DB_FILE):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO honeypot_events (timestamp, operation, src_ip, dst_port, payload, location)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, operation, src_ip, dst_port, payload, get_geo(src_ip)))
    conn.commit()
    conn.close()

# -----------------------------
# handle_client
# -----------------------------
def handle_client(conn, addr, dst_port):
    start = datetime.utcnow()
    src_ip, src_port = addr[0], addr[1]
    banner = BANNERS.get(dst_port, b"Hello from FakeHoneypot\r\n")
    try:
        conn.sendall(banner)
        conn.settimeout(3.0)
        try:
            data = conn.recv(MAX_READ)
        except socket.timeout:
            data = b""
        duration = (datetime.utcnow() - start).total_seconds()
        payload = data.decode(errors='replace')[:300]

        # get geolocation once (avoid calling multiple times)
        location = get_geo(src_ip)

        event = {
            'ts': start.isoformat() + "Z",
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'banner': banner.decode(errors='ignore').strip(),
            'payload': payload,
            'bytes': len(data),
            'duration': duration,
            'location': location
        }

        # Log to JSON
        try:
            log_event_json(event)
        except Exception as e:
            print("JSON logging error:", e)

        # Log summary to honeypot_events table
        try:
            log_to_sql(
                operation="Connection Attempt",
                src_ip=src_ip,
                dst_port=dst_port,
                payload=payload
            )
        except Exception as e:
            print("SQL logging (honeypot_events) error:", e)

        # Log detailed event
        try:
            log_event_db(event)
        except Exception as e:
            print("SQL logging (events) error:", e)

        conn.close()
        print(f"[+] Logged {src_ip}:{src_port} -> {dst_port} (loc: {location})")

    except Exception as e:
        print("Error in handle_client:", e)
        traceback.print_exc()
        try:
            conn.close()
        except:
            pass

# -----------------------------
# server listener + main
# -----------------------------
def start_listener(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"[+] Listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, port), daemon=True)
        t.start()

def main(args):
    init_honeypot_tables()  # ensure all tables & columns exist
    host = args.host
    ports = args.ports
    for p in ports:
        t = threading.Thread(target=start_listener, args=(host, p), daemon=True)
        t.start()
    print("[*] Honeypot running. Press Ctrl+C to stop.")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping honeypot.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0", help="host to bind (0.0.0.0 for all)")
    parser.add_argument("--ports", nargs="+", type=int, default=[2222,2121,2323], help="ports to listen on")
    args = parser.parse_args()
    main(args)
