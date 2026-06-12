#!/usr/bin/env python3
"""
Suricata Log Parser — Eve.json to SQLite Pipeline
================================================
Tails Suricata's eve.json output file, filters for alert events,
and writes normalized data to SQLite table: alerts.

Uses seek-to-end polling (memory-efficient) rather than loading full file.
Filters only event_type='alert' events; skips flow/dns/http logs.

Integration: Run as background process alongside Suricata container.
"""

import json
import sqlite3
import time
import os
from datetime import datetime, timezone
import argparse


EVE_JSON_PATH = '/var/log/suricata/eve.json'
DB_PATH = '/app/db/soc_station.db'  # Flask app database location
POLL_INTERVAL = 2  # seconds between checks

# Severity mapping: Suricata uses integer codes, but we'll store them directly
SURICATA_SEVERITY_MAP = {
    '1': 1,      # critical
    '2': 2,      # high
    '3': 3,      # medium
    '4': 4,      # low
}


def get_latest_alert_id(db_path):
    """Get the highest alert ID in database (for deduplication)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COALESCE(MAX(id), 0) as last_id FROM alerts')
        row = cursor.fetchone()
        return row['last_id']
    except sqlite3.OperationalError:
        # Table doesn't exist yet — will be created on first alert
        return -1
    finally:
        conn.close()


def write_alert_to_db(alert_data, db_path):
    """Write a single alert event to SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Insert with deduplication on signature
    cursor.execute('''
        INSERT OR IGNORE INTO alerts 
        (id, timestamp, src_ip, dest_ip, src_port, dest_port, proto, 
         signature, severity, category, notified, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_data.get('alert', {}).get('_id'),  # Suricata generates unique ID
        alert_data.get('alert', {}).get('timestamp', ''),
        alert_data.get('alert', {}).get('srcip', ''),
        alert_data.get('alert', {}).get('dest', ''),
        alert_data.get('alert', {}).get('srcport', None),
        alert_data.get('alert', {}).get('destport', None),
        alert_data.get('alert', {}).get('proto', 'unknown'),
        alert_data.get('alert', {}).get('sig', ''),
        str(alert_data.get('alert', {}).get('severity', 0)),
        alert_data.get('alert', {}).get('categories', []),
        0,  # Not notified yet
        json.dumps(alert_data.get('alert', {})),
    ))
    
    conn.commit()
    return cursor.rowcount


def tail_eve_json(eve_path, db_path):
    """Tail eve.json file using seek-to-end polling (memory-efficient)."""
    if not os.path.exists(eve_path):
        print(f'[*] Eve.json not found at {eve_path}')
        print(f'[i] Waiting for Suricata to generate logs...')
        time.sleep(30)
        return tail_eve_json(eve_path, db_path)  # Recursive retry
    
    # Open file handle once and reuse
    with open(eve_path, 'r') as f:
        last_position = 0
        last_id = get_latest_alert_id(db_path)
        
        print(f'[*] Tailing {eve_path} -> {db_path}')
        print(f'[i] Poll interval: {POLL_INTERVAL}s')
        print(f'[i] Existing alerts in DB: {last_id}')
        
        while True:
            # Seek to end of file (only read new lines)
            f.seek(0, 2)  # SEEK_END
            remaining = f.read()
            
            if not remaining:
                time.sleep(POLL_INTERVAL)
                continue
            
            # Parse JSON array from new entries
            try:
                alerts = json.loads(remaining)
                
                for alert_data in alerts:
                    event_type = alert_data.get('event_type', '')
                    
                    # Only process alert events (skip flow, dns, http, etc.)
                    if event_type == 'alert':
                        new_rows = write_alert_to_db(alert_data, db_path)
                        
                        if new_rows:
                            print(f'    [+]{alert_data.get("alert", {}).get("_id")[:12]}... {alert_data.get("alert", {}).get("sig")}')
                        else:
                            # Duplicate — may already exist in DB (signature match)
                            pass
                
                f.seek(last_position)  # Return position for next iteration
                last_position = f.tell()
                
            except json.JSONDecodeError:
                # Partial write or binary data — skip this chunk
                pass
            
            time.sleep(POLL_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description='Suricata Log Parser to SQLite')
    parser.add_argument('--eve-json', default=EVE_JSON_PATH, help='Path to Suricata eve.json')
    parser.add_argument('--db', default=DB_PATH, help='Output SQLite database path')
    parser.add_argument('--interval', type=int, default=POLL_INTERVAL, help='Poll interval in seconds')
    
    args = parser.parse_args()
    
    tail_eve_json(args.eve_json, args.db)


if __name__ == '__main__':
    main()
