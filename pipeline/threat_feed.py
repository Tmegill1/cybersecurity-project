#!/usr/bin/env python3
"""
Threat Feed Enrichment — AbuseIPDB Integration
=============================================
Queries AbuseIPDB API for IP reputation data on alerts' source IPs,
cross-references connection logs, and writes results to SQLite table: threat_intel.

Usage:
    python threat_feed.py --db /var/run/soc_station.db
    
Enriches existing alerts by JOINing with threat_intel table on src_ip.
"""

import sqlite3
import argparse
import time
from datetime import datetime, timezone


ABUSEIPDB_API_BASE = 'https://api.abuseipdb.com/api/v2/check'
MAX_AGE_DAYS = 90
DB_PATH = '/app/db/soc_station.db'


def get_abuseipdb_api_key():
    """Read AbuseIPDB API key from environment."""
    import os
    return os.environ.get('ABUSEIPDB_API_KEY', '')


def query_abuseipdb(ip_address):
    """Query AbuseIPDB for IP reputation data."""
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': MAX_AGE_DAYS,
    }
    
    try:
        import requests
        response = requests.get(ABUSEIPDB_API_BASE, params=params, timeout=10)
        
        if response.status_code == 429:
            print(f'[-] AbuseIPDB rate limit reached. Sleeping 60s...')
            time.sleep(60)
            return None
        
        data = response.json()
        
        # Handle API error responses
        if 'error' in data and data['error'].get('code') == 'too_many_requests':
            print(f'[-] AbuseIPDB rate limit: {data["error"].get("message", "Too many requests")}')
            time.sleep(60)
            return None
        
        if response.status_code == 200 and data.get('success'):
            result = data['data']
            
            # Map categories to array format expected by schema
            raw_categories = result.get('categories', {}) or {}
            categories = list(raw_categories.keys()) if isinstance(raw_categories, dict) else []
            
            return {
                'ip_address': ip_address,
                'source': 'abuseipdb',
                'confidence_score': float(result.get('reputation', 0)) if result.get('reputation') else None,
                'categories': categories,
                'country': raw_categories.get('countryCode') or '',
                'last_checked': datetime.now(timezone.utc).isoformat(),
            }
        
        return None
        
    except Exception as e:
        print(f'[-] AbuseIPDB query failed for {ip_address}: {e}')
        return None


def write_threat_intel(threat_data, db_path):
    """Write threat intel data to SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Upsert — avoid duplicate entries
    cursor.execute('''
        INSERT OR REPLACE INTO threat_intel 
        (ip_address, source, confidence_score, categories, country, last_checked)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        threat_data['ip_address'],
        threat_data['source'],
        threat_data.get('confidence_score'),
        json.dumps(threat_data.get('categories', [])),  # Store as JSON string for compatibility
        threat_data.get('country', ''),
        threat_data.get('last_checked', datetime.now(timezone.utc).isoformat()),
    ))
    
    conn.commit()
    return cursor.rowcount


def enrich_alerts_with_threat_intel(db_path):
    """Enrich existing alerts with threat intel data from AbuseIPDB."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get distinct source IPs from alerts
    cursor.execute('''
        SELECT DISTINCT src_ip FROM alerts
        WHERE notified = 0 OR notified = 1
        ORDER BY src_ip
    ''')
    
    unique_ips = {row[0] for row in cursor.fetchall()}
    conn.close()
    
    print(f'[*] Found {len(unique_ips)} unique source IP(s) to enrich with threat intel...')
    
    # Query AbuseIPDB for each unique IP (with caching via existing threat_intel table)
    enriched_count = 0
    
    for ip in unique_ips:
        # Check if we already have recent data for this IP
        try:
            cursor.execute('''
                SELECT ip_address, last_checked 
                FROM threat_intel 
                WHERE ip_address = ? 
            ''', (ip,))
            
            existing_row = cursor.fetchone()
            
            if existing_row and existing_row[1]:
                last_checked = datetime.fromisoformat(existing_row[1].replace('Z', '+00:00'))
                days_since_check = (datetime.now(timezone.utc) - last_checked).days
                
                if days_since_check < MAX_AGE_DAYS:
                    print(f'    [~] {ip}: cached data available ({MAX_AGE_DAYS}d max age)')
                    continue
            
            print(f'[*] Querying AbuseIPDB for {ip}')
            
            threat_data = query_abuseipdb(ip)
            
            if threat_data:
                rowcount = write_threat_intel(threat_data, db_path)
                
                if rowcount > 0:
                    enriched_count += 1
                    print(f'    [✓] Threat intel written for {ip}')
        except Exception as e:
            print(f'    [-] Error processing IP {ip}: {e}')
    
    return enriched_count


def main():
    parser = argparse.ArgumentParser(description='AbuseIPDB Threat Feed Enricher')
    parser.add_argument('--db', default=DB_PATH, help='SQLite database path')
    parser.add_argument('--abuseipdb-key', envvar='ABUSEIPDB_API_KEY', 
                        help='AbuseIPDB API key (env or arg)')
    
    args = parser.parse_args()
    
    print(f'[*] Threat Feed Enricher — AbuseIPDB Integration')
    print(f'[*] Database: {args.db}')
    
    # Load settings.yaml for optional configuration overrides
    import yaml
    try:
        with open('/app/config/settings.yaml', 'r') as f:
            settings = yaml.safe_load(f)[1]
            max_age_override = settings.get('abuseipdb_api', {}).get('max_age_days', MAX_AGE_DAYS)
            print(f'[*] Max cache age: {max_age_override} days')
    except Exception as e:
        print(f'[!] Could not load settings.yaml: {e}')
    
    enriched = enrich_alerts_with_threat_intel(args.db)
    print(f'\n[+] Enriched {enriched} alert(s) with threat intel data')


if __name__ == '__main__':
    main()
