"""
SOC Station — Flask Dashboard Application
===========================================
A lightweight HTMX-powered dashboard for monitoring IDS alerts,
displaying discovered assets, and showing CVE lookups.

Database: SQLite (aggregated events only — raw logs stay in Suricata eve.json)
Routes:
  /alerts    — Suricata alert feed with HTMX polling
  /assets    — Discovered network devices from Nmap scans
  /cves      — CVE lookup results with severity color-coding
"""

import sqlite3
import os
from datetime import datetime
from flask import Flask, render_template, jsonify, g

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False  # Preserve field order for HTMX diffs

# Database configuration
DATABASE_PATH = os.environ.get(
    'DATABASE_URL',
    'sqlite:///db/soc_station.db'
)
DATABASE_DIR = os.path.dirname(DATABASE_PATH.rstrip('/.db'))
if not os.path.exists(DATABASE_DIR):
    os.makedirs(DATABASE_DIR)


def get_db():
    """Get database connection for current request context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row  # Enable dict-like access
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at end of request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database from schema.sql file."""
    schema_path = os.path.join(os.path.dirname(__file__), 'db/schema.sql')
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    with open(schema_path, 'r') as f:
        schema_sql = f.read()

    db = get_db()
    db.executescript(schema_sql)
    db.commit()


# === API ROUTES ===

@app.route('/alerts')
def alerts_route():
    """Serve alerts page with HTMX polling support."""
    db = get_db()
    
    # Query for recent alerts (last 100, ordered by timestamp desc)
    cursor = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100'
    )
    rows = cursor.fetchall()
    
    alerts_list = []
    for row in rows:
        alerts_list.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'src_ip': row['src_ip'],
            'dest_ip': row['dest_ip'],
            'src_port': row['src_port'],
            'dest_port': row['dest_port'],
            'proto': row['proto'],
            'signature': row['signature'][:100] + '...' if len(row['signature']) > 100 else row['signature'],
            'severity': row['severity'],
            'category': row['category'] or 'unknown',
            'notified': row['notified'],
            'raw_json': row['raw_json'][:200] + '...' if len(row['raw_json']) > 200 else row['raw_json']
        })
    
    return render_template('alerts.html', alerts=alerts_list)


@app.route('/assets')
def assets_route():
    """Serve discovered assets page."""
    db = get_db()
    
    cursor = db.execute('SELECT * FROM assets ORDER BY last_seen DESC')
    rows = cursor.fetchall()
    
    assets_list = []
    for row in rows:
        open_ports_data = row['open_ports']
        if open_ports_data:
            try:
                import json
                ports = json.loads(open_ports_data)
                # Extract service info from port data
                services_info = [p.get('service', {}).get('name', 'unknown') 
                               for p in ports if isinstance(p.get('service'), dict)]
            except (json.JSONDecodeError, TypeError):
                services_info = []
        else:
            services_info = []
        
        assets_list.append({
            'id': row['id'],
            'ip_address': row['ip_address'],
            'hostname': row['hostname'] or 'unknown',
            'mac_address': row['mac_address'] or 'unknown',
            'os_guess': row['os_guess'] or 'unknown',
            'open_ports': open_ports_data,
            'last_seen': row['last_seen'],
            'first_seen': row['first_seen']
        })
    
    return render_template('assets.html', assets=assets_list)


@app.route('/cves')
def cves_route():
    """Serve CVE lookup results with severity color-coding."""
    db = get_db()
    
    cursor = db.execute('SELECT * FROM cves ORDER BY published_date DESC')
    rows = cursor.fetchall()
    
    cves_list = []
    for row in rows:
        cves_list.append({
            'id': row['id'],
            'asset_id': row['asset_id'],
            'cve_id': row['cve_id'],
            'description': row['description'][:200] + '...' if len(row['description']) > 200 else row['description'],
            'cvss_score': row['cvss_score'],
            'severity': row['severity'],
            'published_date': row['published_date'],
            'remediation_url': row['remediation_url'] or '#'
        })
    
    return render_template('cves.html', cves=cves_list)


# === HTMX POLLING ENDPOINT FOR ALERTS ===

@app.route('/api/alerts')
def api_alerts():
    """JSON endpoint for HTMX polling. Returns diff of new alerts."""
    db = get_db()
    
    # Get last alert ID we've seen (or 0 if none)
    cursor = db.execute('SELECT COALESCE(MAX(id), 0) as last_id FROM alerts')
    last_id = cursor.fetchone()['last_id']
    
    if last_id == 0:
        return jsonify({'alerts': [], 'last_id': 1})
    
    # Get new alerts since last_id (limit to 50 for performance)
    cursor = db.execute(
        'SELECT * FROM alerts WHERE id > ? ORDER BY timestamp DESC LIMIT 50',
        (last_id,)
    )
    rows = cursor.fetchall()
    
    new_alerts = []
    new_last_id = last_id
    for row in rows:
        new_alerts.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'src_ip': row['src_ip'],
            'dest_ip': row['dest_ip'],
            'src_port': row['src_port'],
            'dest_port': row['dest_port'],
            'proto': row['proto'],
            'signature': row['signature'][:100] + '...' if len(row['signature']) > 100 else row['signature'],
            'severity': row['severity'],
            'category': row['category'] or 'unknown',
            'notified': row['notified'],
        })
    
    # Find the highest ID to update last_id in future requests
    if new_alerts:
        new_last_id = max(a['id'] for a in new_alerts) + 1
    
    return jsonify({'alerts': new_alerts, 'last_id': new_last_id})


# === DASHBOARD HOME ===

@app.route('/')
def index():
    """Dashboard home page with overview stats."""
    db = get_db()
    
    # Get summary stats
    cursor = db.execute('SELECT COUNT(*) as total FROM alerts')
    total_alerts = cursor.fetchone()['total']
    
    cursor = db.execute(
        'SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY CAST(severity AS INTEGER) DESC'
    )
    severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    cursor = db.execute('SELECT COUNT(*) as total FROM assets')
    total_assets = cursor.fetchone()['total']
    
    cursor = db.execute('SELECT COUNT(*) as total FROM cves')
    total_cves = cursor.fetchone()['total']
    
    return render_template('base.html', 
                          alerts_count=total_alerts,
                          severity_counts=severity_counts,
                          assets_count=total_assets,
                          cves_count=total_cves)


# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
