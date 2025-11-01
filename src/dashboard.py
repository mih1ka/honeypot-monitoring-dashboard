#!/usr/bin/env python3
# src/dashboard.py

from flask import Flask, render_template, send_file
import sqlite3
import matplotlib.pyplot as plt
import io, os, base64, requests
from datetime import datetime

app = Flask(__name__)
DB_FILE = os.path.join(os.path.dirname(__file__), "../logs/honeypot.db")

# -------------------------------
# Helper: Get GeoIP (Country)
# -------------------------------
def get_country(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("country", "Unknown")
    except:
        return "Unknown"

# -------------------------------
# Dashboard Route
# -------------------------------
@app.route("/")
def dashboard():
    health = {"db_connected": False, "recent_attacks": False, "last_updated": "N/A"}

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Check DB connection
        health["db_connected"] = True

        # Fetch last 10 events
        c.execute("SELECT id, ts, src_ip, dst_port, payload, location FROM events ORDER BY ts DESC LIMIT 10")
        events = c.fetchall()

        if events:
            health["recent_attacks"] = True
            health["last_updated"] = events[0]["ts"]

        # --- Attack Trend Over Time ---
        c.execute("SELECT substr(ts, 1, 10) as date, COUNT(*) as count FROM events GROUP BY date ORDER BY date")
        trend_data = c.fetchall()
        dates = [row["date"] for row in trend_data]
        attack_counts = [row["count"] for row in trend_data]

        plt.figure(figsize=(6, 4))
        plt.plot(dates, attack_counts, marker='o', color='blue')
        plt.title("Attack Trend Over Time")
        plt.xlabel("Date")
        plt.ylabel("Number of Attacks")
        plt.tight_layout()
        img_trend = io.BytesIO()
        plt.savefig(img_trend, format="png")
        img_trend.seek(0)
        plot_trend = base64.b64encode(img_trend.getvalue()).decode()
        plt.close()

        # --- Top 5 Attacker IPs ---
        c.execute("SELECT src_ip, COUNT(*) as hits FROM events GROUP BY src_ip ORDER BY hits DESC LIMIT 5")
        top_ips = c.fetchall()
        ip_labels = [row["src_ip"] for row in top_ips]
        ip_hits = [row["hits"] for row in top_ips]

        plt.figure(figsize=(6, 4))
        plt.bar(ip_labels, ip_hits, color='orange')
        plt.title("Top 5 Attacker IPs")
        plt.xlabel("Source IP")
        plt.ylabel("Number of Attacks")
        plt.tight_layout()
        img_ips = io.BytesIO()
        plt.savefig(img_ips, format="png")
        img_ips.seek(0)
        plot_ips = base64.b64encode(img_ips.getvalue()).decode()
        plt.close()

        # --- GeoIP Pie Chart (Countries) ---
        c.execute("SELECT location, COUNT(*) as count FROM events WHERE location IS NOT NULL GROUP BY location")
        country_data = c.fetchall()
        if country_data:
            countries = [row["location"] for row in country_data]
            counts_loc = [row["count"] for row in country_data]
            plt.figure(figsize=(5, 5))
            plt.pie(counts_loc, labels=countries, autopct="%1.1f%%", startangle=140)
            plt.title("Attacks by Country")
            img_geo = io.BytesIO()
            plt.savefig(img_geo, format="png")
            img_geo.seek(0)
            plot_geo = base64.b64encode(img_geo.getvalue()).decode()
            plt.close()
        else:
            plot_geo = None

        conn.close()

    except Exception as e:
        print(f"[ERROR] Dashboard loading failed: {e}")
        events, plot_trend, plot_ips, plot_geo = [], None, None, None

    return render_template(
        "dashboard.html",
        events=events,
        plot_trend=plot_trend,
        plot_ips=plot_ips,
        plot_geo=plot_geo,
        health=health
    )

# -------------------------------
# Run Flask Server
# -------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
