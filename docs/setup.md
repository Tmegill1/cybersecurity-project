# Setup Guide — Step-by-Step Installation

This guide walks you through deploying SOC Station on your Linux host (Raspberry Pi, NAS, WSL2, or standard server).

---

## Prerequisites

- **Linux** 7.0+ with bash shell
- **Docker** installed and running
- **Docker Compose** available
- Basic familiarity with networking concepts (CIDR notation, ports)

---

## Step 1: Clone Repository

```bash
git clone https://github.com/Tmegill1/cybersecurity-project.git
cd cybersecurity-project
```

---

## Step 2: Install Python Dependencies (Optional — for CLI tools)

```bash
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install flask requests python-yaml

# Verify installation
pip list | grep -E 'flask|requests|yaml'
```

---

## Step 3: Configure Docker Compose

Edit `docker/docker-compose.yml`:

```yaml
services:
  suricata:
    # ... existing config ...
    privileged: true                    # REQUIRED for first run (interface access)
    
  dashboard:
    # ... existing config ...
```

**Note:** `privileged: true` is required only on first startup. Can be removed in production after verifying Suricata runs as non-root.

---

## Step 4: Create `.env` File with Secrets

```bash
cp .env.example .env
nano .env    # Edit with your actual values
```

**Required:**
- `NVD_API_KEY=your_nvd_api_key_here`  
  → Get free key at https://nvd.nist.gov/developers/request-an-api-key

**Optional (but recommended):**
- `ABUSEIPDB_API_KEY=your_abuseipdb_key_here`
- `DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...`

---

## Step 5: Initialize SQLite Schema

```bash
python3 -c "import sqlite3; conn = sqlite3.connect('db/soc_station.db'); conn.executescript(open('db/schema.sql').read()); conn.commit(); conn.close()"
```

**Verify database created:**
```bash
ls -la db/
sqlite3 db/soc_station.db ".tables"  # Should show: alerts cves assets threat_intel
```

---

## Step 6: Start Suricata (IDS)

```bash
docker-compose up -d suricata

# Wait for logs to indicate startup
docker-compose logs --tail=20 suricata

# Verify eve.json created
ls -lh /var/log/suricata/eve.json
```

**Expected output:**
```
suricata  | [info] Suricata v7.0.0 is ready to rock...
suricata  | Listening on interface: any (tap0)
suricata  | eve-json started, will write to /var/log/suricata/eve.json
```

---

## Step 7: Generate Test Data (Optional — For Demo Purposes)

### Option A: Nmap LAN Discovery

If your network is reachable via Docker bridge:

```bash
docker exec suricata nmap -OvAeN -p 1-1024 -sS -T3 -oX /tmp/nmap_output.xml 192.168.1.0/24
python scanners/nmap_scanner.py --range 192.168.1.0/24 --output db/soc_station.db

# Verify assets written
sqlite3 db/soc_station.db "SELECT ip_address, hostname FROM assets LIMIT 5;"
```

### Option B: Manual Test Alerts (For Demo)

Insert fake alert into database to test dashboard rendering:

```bash
python3 << 'EOF'
import sqlite3
from datetime import datetime, timezone

conn = sqlite3.connect('db/soc_station.db')
cursor = conn.cursor()

# Create sample alert if table exists
cursor.execute('''
    INSERT OR IGNORE INTO alerts 
    (id, timestamp, src_ip, dest_ip, src_port, dest_port, proto, signature, severity, category, notified, raw_json)
    VALUES 
    (NULL, datetime("now", "utc"), "10.0.0.50", "192.168.1.100", 54321, 443, "tcp", 
     "ET POLICY HTTP Malformed HTTP Request Detected", 2, "attempt", 0, '{}')
''')

conn.commit()
print('Test alert inserted.')
conn.close()
EOF
```

---

## Step 8: Launch Flask Dashboard

```bash
export FLASK_ENV=development
python dashboard/app.py
# Or use Docker Compose for persistent container
docker-compose up -d dashboard
```

**Access at:** `http://localhost:5000` (or host IP if not on same subnet)

---

## Step 9: Verify All Components

### Check Suricata Logs
```bash
docker-compose logs suricata --tail=10 | grep "Ready"
```

### Check Database Tables
```bash
sqlite3 db/soc_station.db ".schema"
# Should show CREATE TABLE for alerts, assets, cves, threat_intel
```

### Check Dashboard Renders
Open browser at `http://localhost:5000` — verify navigation bar works and one of the views shows.

---

## Step 10 (Optional): Run Alert Pipeline in Background

**Discord webhook sender:**

```bash
python pipeline/alerter.py --db db/soc_station.db --webhook-url https://discord.com/api/webhooks/YOUR_WEBHOOK
# Or use env var: export DISCORD_WEBHOOK_URL=https://... and omit --webhook-url
```

**Threat feed enricher:**

```bash
python pipeline/threat_feed.py --db db/soc_station.db
```

---

## Common Issues & Solutions

### "No such file or directory" for network interface

**Cause:** Suricata can't bind to host network.

**Solution:** Add `privileged: true` to docker-compose.yml and restart container.

---

### Database schema missing tables

**Fix:**
```bash
python3 -c "import sqlite3; conn = sqlite3.connect('db/soc_station.db'); conn.executescript(open('db/schema.sql').read()); conn.commit(); conn.close()"
```

---

### Nmap XML parsing fails

**Verify output exists:**
```bash
ls -la /tmp/nmap_output.xml
cat /tmp/nmap_output.xml | head -30
```

---

### "NVD API rate limit exceeded"

**Solution:** Wait 30-60 seconds between requests, or use cached data in `cves` table.

---

## Next Steps After Setup

1. **Remove `privileged: true`** from docker-compose.yml (if Suricata runs correctly without it)
2. **Set up automated cron jobs** for regular Nmap scans and CVE lookups
3. **Configure email alerts** via `config/settings.yaml` if Discord not available
4. **Generate portfolio screenshots** of dashboard with real data
5. **Document your specific setup** in README.md with actual network topology

---

## Support & Resources

- [NVD API Documentation](https://nvd.nist.gov/developers/v2-start)
- [AbuseIPDB API Docs](https://abuseipdb.com/api/#overview)
- [Suricata Documentation](https://suricata.io/docs/)
- [HTMX Cheatsheet](https://htmx.org/cheatsheet/)
