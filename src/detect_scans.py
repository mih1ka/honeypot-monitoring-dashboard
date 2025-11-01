#!/usr/bin/env python3
# src/detect_scans.py
import json
from datetime import datetime, timedelta
from collections import defaultdict

def detect(path="logs/attacks.jsonl", window_minutes=5, port_threshold=5):
    rows=[]
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r['src_ip']].append((datetime.fromisoformat(r['ts'].replace("Z","")), r['dst_port']))
    alerts=[]
    for ip, evs in by_ip.items():
        evs.sort()
        for i in range(len(evs)):
            start = evs[i][0]
            end = start + timedelta(minutes=window_minutes)
            unique_ports = set(p for t,p in evs if start<=t<=end)
            if len(unique_ports) >= port_threshold:
                alerts.append({'ip': ip, 'start': start.isoformat(), 'ports': len(unique_ports)})
                break
    return alerts

if __name__ == "__main__":
    alerts = detect()
    if alerts:
        print("Potential scanners:")
        for a in alerts:
            print(a)
    else:
        print("No scans detected.")
