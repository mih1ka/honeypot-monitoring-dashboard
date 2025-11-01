#!/usr/bin/env python3
# src/analyze_simple.py
import json, collections, os

def read_logs(path="logs/attacks.jsonl"):
    if not os.path.exists(path):
        print("No logs found.")
        return []
    rows=[]
    with open(path) as f:
        for line in f:
            rows.append(json.loads(line))
    return rows

def summary(rows):
    ips = collections.Counter(r['src_ip'] for r in rows)
    ports = collections.Counter(r['dst_port'] for r in rows)
    print("Total events:", len(rows))
    print("Top IPs:")
    for ip, c in ips.most_common(5):
        print(ip, c)
    print("Ports:")
    for p, c in ports.most_common():
        print(p, c)

if __name__ == "__main__":
    rows = read_logs()
    summary(rows)
