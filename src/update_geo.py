import sqlite3
import requests
import time
import os

DB_FILE = os.path.join(os.path.dirname(__file__), "../logs/honeypot.db")

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data["status"] == "success":
            return f"{data['city']}, {data['country']}"
    except Exception as e:
        print(f"Error fetching {ip}: {e}")
    return "Unknown"

def update_locations():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT DISTINCT src_ip FROM events WHERE location IS NULL OR location = ''")
    ips = [row[0] for row in c.fetchall()]

    print(f"Updating {len(ips)} IPs with location data...")

    for ip in ips:
        location = get_location(ip)
        print(f"{ip} → {location}")
        c.execute("UPDATE events SET location=? WHERE src_ip=?", (location, ip))
        conn.commit()
        time.sleep(1)  # wait 1s between requests to avoid rate limits

    conn.close()
    print("✅ Done updating locations.")

if __name__ == "__main__":
    update_locations()
