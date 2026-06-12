#!/usr/bin/env python3
"""
CVE Lookup Script — NVD API Integration
======================================
Reads discovered assets from SQLite, matches services against CPE strings,
queries NVD API for known vulnerabilities, and stores results in SQLite table: cves.

Usage:
    python cve_lookup.py --db /var/run/soc_station.db --nvd-key YOUR_API_KEY
    
This cross-references Nmap service version output with NVD CPE format:
  Example: Apache 2.4.51 → cpe:/a:apache:http_server:2.4.51

Note: Requires free-tier API key from https://nvd.nist.gov/developers/request-an-api-key
"""

import sqlite3
import requests
import argparse
from datetime import datetime, timezone
import time


# NVD API endpoint (v2.0 format)
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def get_nvd_api_key():
    """Read NVD API key from environment or config."""
    import os
    return os.environ.get('NVD_API_KEY', '')


def build_cpe_string(service_info):
    """
    Convert service/product/version info to NVD CPE format.
    
    Example inputs:
      - {'product': 'Apache httpd', 'version': '2.4.51'}
      - {'product': 'nginx', 'version': '1.20.2'}
    """
    product = service_info.get('name', '').lower() if isinstance(service_info.get('name'), str) else ''
    version = service_info.get('version', '') or service_info.get('extrame', '') or ''
    
    # Clean up version string (strip brackets, quotes, etc.)
    clean_version = ''.join(c for c in version if c.isalnum() or c == '.')[:15]  # Max 15 chars
    
    return f"cpe:/a:{product}:{clean_version}"


def query_nvd_api(cpe_string):
    """Query NVD API for vulnerabilities matching a CPE string."""
    params = {
        'cpeName': cpe_string,
        'resultsPerPage': 25,
        'startIndex': 0,
    }
    
    try:
        response = requests.get(NVD_API_BASE, params=params, timeout=10)
        
        if response.status_code == 403 or 'Unauthorized' in response.text:
            print(f'[!] NVD API rate limit exceeded (free tier: 2000 req/day). Sleeping...')
            time.sleep(30)  # Respect 30s cooldown between requests without key
            
        if response.status_code == 429:
            print(f'[!] Rate limited by NVD. Waiting 60 seconds...')
            time.sleep(60)
        
        data = response.json()
        return {
            'success': response.status_code == 200,
            'vulnerabilities': data.get('vulnerabilities', []),
        }
    except requests.exceptions.RequestException as e:
        print(f'[!] API request failed for {cpe_string}: {e}')
        return {'success': False, 'vulnerabilities': []}


def fetch_cve_details(cve_id):
    """Fetch detailed CVE data from NVD."""
    cve_url = f'{NVD_API_BASE}/{cve_id}'
    
    try:
        response = requests.get(cve_url, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f'[!] Failed to fetch details for {cve_id}: HTTP {response.status_code}')
            return None
    except Exception as e:
        print(f'[!] Error fetching CVE {cve_id}: {e}')
        return None


def get_severity_from_cvss(cvss_score):
    """Map CVSS score to severity string."""
    if cvss_score is None or cvss_score == '':
        return 'unknown'
    
    try:
        score = float(cvss_score)
    except (ValueError, TypeError):
        return 'unknown'
    
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    else:
        return 'low'


def write_to_db(cves, db_path):
    """Write CVE results to SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get asset IDs that need CVE insertion (avoid duplicates with last_fetched check)
    cursor.execute('SELECT id FROM assets')
    existing_assets = {row[0] for row in cursor.fetchall()}
    
    for cve_data in cves:
        # Skip if we already fetched this recently (last_fetched logic handled in main)
        if cve_data.get('skip', False):
            continue
        
        asset_id = cve_data['asset_id']
        cve_id = cve_data['cve_id']
        
        cursor.execute('''
            INSERT OR REPLACE INTO cves 
            (asset_id, cve_id, description, cvss_score, severity, published_date, remediation_url, last_fetched)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset_id,
            cve_id,
            cve_data.get('description', '')[:500],  # Truncate long descriptions
            cve_data.get('cvss_score'),
            cve_data.get('severity', 'unknown'),
            cve_data.get('published_date') or '',
            cve_data.get('remediation_url') or 'https://nvd.nist.gov/vuln/detail/' + cve_id,
            datetime.now(timezone.utc).isoformat(),
        ))
    
    conn.commit()
    conn.close()
    
    return len(cves)


def main():
    parser = argparse.ArgumentParser(description='CVE Lookup from NVD API')
    parser.add_argument('--db', required=True, help='SQLite database path')
    parser.add_argument('--nvd-key', envvar='NVD_API_KEY', help='NVD API key (optional but recommended)')
    
    args = parser.parse_args()
    
    db_path = args.db
    
    # Connect to database and query discovered assets with service info
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT ip_address, open_ports FROM assets 
        WHERE open_ports IS NOT NULL AND open_ports != ''
    ''')
    
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    cves_to_fetch = []
    
    for ip, ports_json in rows:
        try:
            import json
            ports = json.loads(ports_json) if ports_json else []
            
            for port in ports:
                service_info = port.get('service', {}) or {}
                
                # Skip services without recognizable product/version
                if not service_info:
                    continue
                
                cpe_string = build_cpe_string(service_info)
                
                cves_to_fetch.append({
                    'asset_ip': ip,
                    'cpe_string': cpe_string,
                    'service_info': service_info,
                    'skip': False,  # Will be set to True if already fetched recently
                })
        except json.JSONDecodeError:
            continue
    
    print(f'[*] Found {len(cves_to_fetch)} service(s) to check against NVD API')
    
    # Query NVD API for each CPE string (with rate-limit respect)
    nvd_api_key = get_nvd_api_key()
    cves_found = []
    
    for i, item in enumerate(cves_to_fetch):
        print(f'[{i+1}/{len(cves_to_fetch)}] Checking {item["cpe_string"]}')
        
        result = query_nvd_api(item['cpe_string'])
        
        if not result.get('success'):
            continue
        
        vulns = result.get('vulnerabilities', [])
        
        for vuln in vulns:
            cve_id = vuln.get('cve', {}).get('id') or vuln.get('id') or ''
            
            # Fetch detailed data
            cve_details = fetch_cve_details(cve_id)
            
            if not cve_details:
                continue
            
            # Build CVE record for database
            cves_found.append({
                'asset_id': item['cpe_string'],  # Will be replaced with actual asset_id before write
                'cve_id': cve_id,
                'description': cve_details.get('vuln', {}).get('description', {}).get('short'),
                'cvss_score': cve_details.get('vuln', {}).get('cvssV31') or cve_details.get('vuln', {}).get('cvssScore'),
                'severity': get_severity_from_cvss(cve_details.get('vuln', {}).get('cvssV31')),
                'published_date': vuln.get('published', {}),
                'remediation_url': '',  # Would need vendor-specific lookup
            })
            
            cves_found[-1]['skip'] = True if nvd_api_key else False
            
            print(f'    [+]{cve_id[:8]}... ({get_severity_from_cvss(cve_details.get("vuln", {}).get("cvssV31"))})')
    
    # Replace asset IDs with actual values from database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    for cve in cves_found:
        cursor.execute('''
            UPDATE cves 
            SET cve_id=?, description=?, cvss_score=?, severity=?, last_fetched=?
            WHERE asset_id=? AND (cve_id IS NULL OR cve_id != ?)
        ''', (
            cve['cve_id'],
            cve.get('description', ''),
            cve.get('cvss_score'),
            cve.get('severity', 'unknown'),
            datetime.now(timezone.utc).isoformat(),
            cve['asset_ip'],  # Using CPE string as placeholder asset_id
            '',  # Empty cve_id to allow UPDATE
        ))
    
    conn.commit()
    update_count = cursor.rowcount
    
    print(f'[+] Updated {update_count} CVE record(s) in database')


if __name__ == '__main__':
    main()
