#!/usr/bin/env python3
"""
NMAP Scanner — LAN Asset Discovery
===================================
Runs Nmap against a target network, parses XML output for OS detection,
service versions, and open ports. Writes aggregated data to SQLite table: assets.

Usage:
    python nmap_scanner.py --range 192.168.1.0/24 --output /var/run/soc_db.db
    
This is called by log_parser.py which monitors events for scanner completion.
"""

import xml.etree.ElementTree as ET
import sqlite3
import subprocess
import sys
import argparse
from datetime import datetime, timezone
import json


def parse_nmap_xml(xml_path):
    """Parse Nmap XML output and extract host information."""
    assets = []
    
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    # Handle ns for xml namespace if present
    ns = {'nmap': 'http://livedvd.wetware.com.mx/nmap/'}
    
    hosts = root.findall('.//host') or root.findall('.//nmap:host', ns)
    
    for host in hosts:
        ip_address = host.get('address') or ''
        
        # Try both XML namespace variants
        hostname_elem = host.find('hostname') or host.find('nmap:hostname', ns)
        hostname = hostname_elem.get('name') if hostname_elem else 'unknown'
        
        mac_elem = host.find('address') or host.find('nmap:address', ns)  # May be repeated
        mac_addr = None
        for addr in host.findall('.//address'):
            if addr.get('type') == 'mac':
                mac_addr = f"{addr.get('address')} ({addr.get('vendor')})"
                break
        
        # OS detection
        os_guess = 'unknown'
        os_list = host.find('os') or host.find('nmap:os', ns)
        if os_list is not None:
            os_matcher = os_list.find('osmatch') or os_list.find('nmap:osmatch', ns)
            if os_matcher is not None and os_matcher.get('name'):
                os_guess = os_matcher.get('name', 'unknown')
        
        # Open ports with service/version info
        open_ports_raw = []
        ports_elem = host.find('ports') or host.find('nmap:ports', ns)
        
        if ports_elem is not None:
            port_list = ports_elem.findall('port') or ports_elem.findall('nmap:port', ns)
            for port in port_list:
                port_data = {
                    'state': port.get('state', 'unknown'),
                    'number': int(port.get('portid', '-')) if port.get('portid') else None,
                }
                
                # Service info (if available)
                service_elem = port.find('service') or port.find('nmap:service', ns)
                if service_elem is not None:
                    port_data['service'] = {
                        'name': service_elem.get('product') or service_elem.get('method') or 'unknown',
                        'version': service_elem.get('extrame'),  # Often contains version string
                    }
                
                open_ports_raw.append(port_data)
        
        assets.append({
            'ip_address': ip_address,
            'hostname': hostname,
            'mac_address': mac_addr,
            'os_guess': os_guess,
            'open_ports': json.dumps(open_ports_raw),
            'first_seen': '',  # Will be set by log_parser when first discovered
        })
    
    return assets


def write_to_db(assets, db_path):
    """Write discovered assets to SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    for asset in assets:
        cursor.execute('''
            INSERT OR REPLACE INTO assets 
            (ip_address, hostname, mac_address, os_guess, open_ports, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset['ip_address'],
            asset['hostname'],
            asset['mac_address'],
            asset['os_guess'],
            asset['open_ports'],
            asset['first_seen'],
            datetime.now(timezone.utc).isoformat(),
        ))
    
    conn.commit()
    conn.close()
    
    return len(assets)


def run_nmap(scan_range, output_xml):
    """Run Nmap scan and return exit code."""
    nmap_cmd = [
        'nmap',
        '-OvAeN',              # OS detection, version detection, script scanning (optional)
        '-p 1-1024',           # Scan common ports only (adjust as needed)
        '-sS',                 # SYN scan (stealth mode)
        '-T3',                 # Timing template: aggressive but safe
        '-oX', output_xml,     # XML output format
        scan_range
    ]
    
    print(f'Running Nmap: {" ".join(nmap_cmd)}')
    
    result = subprocess.run(
        nmap_cmd,
        capture_output=True,
        text=True
    )
    
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description='NMAP LAN Asset Discovery Scanner')
    parser.add_argument('--range', required=True, help='Target network in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--output', required=True, help='Output database path (SQLite)')
    
    args = parser.parse_args()
    
    db_path = args.output
    scan_range = args.range
    
    # Run Nmap scan
    print(f'[*] Scanning {scan_range} with Nmap...')
    exit_code = run_nmap(scan_range, '/tmp/nmap_output.xml')
    
    if exit_code != 0:
        print(f'[!] Nmap returned exit code {exit_code}')
        # Still try to parse XML if it exists (may have partial results)
        import os
        if os.path.exists('/tmp/nmap_output.xml'):
            assets = parse_nmap_xml('/tmp/nmap_output.xml')
        else:
            print('[!] No XML output found — aborting write')
            sys.exit(1)
    else:
        # Parse freshly generated XML
        try:
            assets = parse_nmap_xml('/tmp/nmap_output.xml')
        except Exception as e:
            print(f'[!] Failed to parse XML: {e}')
            sys.exit(1)
    
    print(f'[*] Found {len(assets)} host(s):', ', '.join(a['ip_address'] for a in assets))
    
    # Write to database
    write_to_db(assets, db_path)
    print(f'[+] Wrote {len(assets)} asset(s) to {db_path}')


if __name__ == '__main__':
    main()
