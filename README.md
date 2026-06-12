# SOC Station — Home Network Security Operations Center

A self-hosted Security Operations Center (SOC) for monitoring your home network traffic, detecting threats via Suricata IDS, scanning for vulnerabilities, and automatically looking up CVE data from public security databases.

![SOC Station Architecture](docs/architecture_diagram.png)

---

## 🎯 What We're Building

A lightweight, zero-config-depends dashboard that:

1. **Monitors Network Traffic** — Suricata IDS running in Docker detects alerts on your LAN
2. **Discovers Assets** — Nmap scans enumerate devices, open ports, OS guesses, and service versions
3. **Looks Up Vulnerabilities** — Cross-references discovered services against NVD API for CVE data
4. **Enriches with Threat Intel** — AbuseIPDB reputation checks on alert source IPs
5. **Alerts in Real-Time** — Suricata alert → Python daemon → Discord webhook (or email)
6. **Visualizes Everything** — Flask + HTMX dashboard backed by SQLite

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Home SOC Dashboard                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│         [Dashboard UI] ← Flask/HTMX → SQLite                      │
│             (zero build step, local deployment)                   │
│                           ↓                                        │
│    ┌─────────────────────┬─────────────────────┬────────────────┐ │
│    │   Network Monitor   │   Vulnerability     │  Threat Intel   │ │
│    │                     │   Scanner           │  Enricher       │ │
│    ├─────────────────────┼─────────────────────┼────────────────┤ │
│    │   Suricata (IDS)   │ Nmap + custom       │ AbuseIPDB API  │ │
│    │   eve.json logs     │ CVE lookup script   │ Reputation data │ │
│    └─────────────────────┴─────────────────────┴────────────────┘ │
│                           ↓                                        │
│                     SQLite Database (aggregated events)            │
│         (NOT raw log storage — stays in Suricata's eve.json)     │
│                                                                    │
│              ┌───────────────────────────┐                        │
│              │   Alert Pipeline          │                        │
│              │   eve.json → SQLite       │                        │
│              │   SQLite → Discord/Email  │                        │
│              └───────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 💻 Technology Stack

| Component          | Technology         | Purpose                     |
|--------------------|--------------------|-----------------------------|
| IDS / Traffic      | Suricata           | Network threat detection    |
| Dashboard          | Flask + HTMX       | Zero-build frontend         |
| Database           | SQLite             | Aggregated events & CVEs    |
| Asset Discovery    | Nmap               | Host enumeration            |
| CVE Lookup         | Python requests    | NVD API integration         |
| Threat Intel       | AbuseIPDB API      | IP reputation data          |
| Alerting           | Discord/Email      | Real-time notifications     |
| Containerization   | Docker Compose     | Simple deployment           |

---

## 🚀 Quick Start (Local Deployment)

### Prerequisites

- Linux host (Raspberry Pi, NAS, or WSL2)
- Docker & Docker Compose installed
- Python 3.10+ for CLI tools (optional — can run Nmap natively)
- Basic network knowledge

### Step-by-Step Setup

#### 1. Clone Repository

```bash
git clone https://github.com/Tmegill1/cybersecurity-project.git
cd cybersecurity-project
```

#### 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install flask requests lxml python-yaml
```

#### 3. Generate Docker Compose (Optional but Recommended)

```bash
docker-compose up -d suricata
sleep 10
docker-compose logs suricata | head -20
# Verify Suricata started and eve.json created
ls /var/log/suricata/
```

**Note:** First-time run may require `privileged: true` in docker-compose.yml for network interface access.

#### 4. Configure Secrets

Create `.env` file from template:

```bash
cp .env.example .env
nano .env  # Edit with your actual keys
```

Required values:
- `NVD_API_KEY=your_nvd_api_key_here`
- (Optional) `ABUSEIPDB_API_KEY=your_abuseipdb_key_here`
- (Optional) `DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...`

#### 5. Initialize SQLite Schema

```bash
python pipeline/init_schema.py --db /app/db/soc_station.db
```

If init script doesn't exist yet, manually apply schema:

```bash
sqlite3 /app/db/soc_station.db < db/schema.sql
```

#### 6. Launch Flask Dashboard

```bash
export FLASK_ENV=development
python dashboard/app.py
# Access at http://localhost:5000
```

---

## 📁 Project Structure

```
cybersecurity-project/
├── README.md                       # This file — project overview & setup guide
├── TASKS.md                        # Living task list with phase completion status
├── .gitignore                      # Python, Docker volumes, logs ignored
├── .env.example                    # Secrets template (populate with real values)
├── docker/
│   ├── docker-compose.yml          # Suricata + Flask services
│   └── suricata/
│       └── suricata.yaml           # Suricata config (interface, rules, eve.json)
├── dashboard/
│   ├── app.py                      # Flask application entry point
│   ├── requirements.txt            # Python dependencies for dashboard container
│   ├── routes/                     # Route modules
│   │   ├── alerts.py               # /alerts endpoint — reads SQLite
│   │   ├── assets.py               # /assets endpoint — Nmap results
│   │   └── cves.py                 # /cves endpoint — CVE lookup data
│   └── templates/
│       ├── base.html               # Base layout with navigation
│       ├── alerts.html             # Alert feed (HTMX polling every 5s)
│       ├── assets.html             # Discovered devices table
│       └── cves.html               # CVE results with severity badges
├── scanners/
│   ├── nmap_scanner.py             # Runs Nmap, parses XML, writes to SQLite
│   └── cve_lookup.py               # Reads Nmap results, queries NVD API
├── pipeline/
│   ├── log_parser.py               # Tails eve.json, normalizes events to SQLite
│   ├── alerter.py                  # Reads new alerts, sends Discord/email webhook
│   └── threat_feed.py              # Queries AbuseIPDB, cross-references logs
├── db/
│   └── schema.sql                  # SQLite schema (alerts, assets, cves, threat_intel)
├── config/
│   └── settings.yaml               # API keys, webhook URL, Nmap targets
└── docs/
    ├── architecture.md             # Architecture diagram + design decisions
    └── setup.md                    # Step-by-step install guide
```

---

## 🛠️ Development Workflow

### Phase-Based Approach

Each phase is independently commitable — track progress in `TASKS.md`.

#### Phase 1: IDS Foundation (Current)

Deliverables:
- [ ] Suricata running in Docker Compose with eve.json output
- [ ] SQLite schema created (`db/schema.sql`)
- [ ] `log_parser.py` writing alerts to DB within 5s of firing
- [ ] `.gitignore` and `.env.example` added

#### Phase 2: Asset & CVE Scanning

Deliverables:
- [ ] `nmap_scanner.py` discovering LAN devices
- [ ] `cve_lookup.py` querying NVD API with caching (24h)
- [ ] `config/settings.yaml` externalizing all config

#### Phase 3: Alerting Pipeline

Deliverables:
- [ ] `alerter.py` sending Discord webhooks for severity ≤2 alerts
- [ ] `threat_feed.py` enriching alerts with AbuseIPDB reputation

#### Phase 4: Flask Dashboard

Deliverables:
- [ ] Three live routes: `/alerts`, `/assets`, `/cves`
- [ ] HTMX polling on `/alerts` (updates every 5s)
- [ ] Severity color-coding on CVE table

#### Phase 5: Portfolio Polish

Deliverables:
- [ ] README with architecture diagram + setup screenshots
- [ ] `docs/setup.md` install guide
- [ ] Security hardening (non-root user, API rate limits, Suricata not root)

---

## 🔐 Security Considerations

1. **Secrets Management** — All API keys in `.env`, never hardcoded. Committed `.env.example` only.
2. **Rate Limiting** — NVD API uses 24h cache to avoid hitting free-tier limits (50 req/30s).
3. **Non-Root Suricata** — Run as unprivileged user after initial start (see Phase 5 docs/setup.md).
4. **Database Isolation** — SQLite stores only aggregated events; raw logs stay in Suricata's eve.json.

---

## 📊 Database Schema

```sql
-- alerts: Suricata event feed
alerts(id, timestamp, src_ip, dest_ip, src_port, dest_port, proto, signature, severity, category, notified, raw_json)

-- assets: Nmap discovery results
assets(id, ip_address, hostname, mac_address, os_guess, open_ports (JSON), last_seen, first_seen)

-- cves: CVE lookups against discovered services
cves(id, asset_id (FK), cve_id, description, cvss_score, severity, published_date, remediation_url, last_fetched)

-- threat_intel: AbuseIPDB reputation data
threat_intel(id, ip_address, source, confidence_score, categories (JSON array), country, last_checked)
```

---

## 🖥️ Dashboard Preview

| View          | Description                                  |
|---------------|----------------------------------------------|
| `/`           | Home dashboard with summary stats            |
| `/alerts`     | Live alert feed (HTMX polls every 5s)        |
| `/assets`     | Table of discovered devices                  |
| `/cves`       | CVE lookup results with severity badges      |

---

## 🧪 Testing & Demo Data

For portfolio demonstrations without a live network:

```bash
# Test Nmap against localhost (if Docker networking permits)
python scanners/nmap_scanner.py --range 192.168.1.0/24 --output /app/db/soc_station.db

# Generate test alerts (manual — for demo purposes only)
sqlite3 /app/db/soc_station.db "INSERT INTO alerts VALUES (NULL, '2024-01-01T00:00:00Z', '10.0.0.1', '192.168.1.100', 12345, 443, 'tcp', 'ET POLICY SYN Flood Attack Detected', 1, 'policy-violation', 0, '{...}');"
```

---

## 📝 License

This project is provided as-is for educational purposes. Use at your own discretion.

---

## 🔧 Troubleshooting

### "No module named 'yaml'"
```bash
pip install python-yaml
```

### Suricata fails to start
- Check Docker logs: `docker-compose logs suricata`
- Verify network interface permissions
- May need `privileged: true` temporarily on first run

### NVD API rate limited (429)
- Wait 60 seconds between requests
- Get free API key at https://nvd.nist.gov/developers/request-an-api-key
- Cache duration set in `config/settings.yaml` is 24 hours

### Alerts not showing up
- Verify Suricata is running: `docker-compose logs suricata | grep "eve.json"`
- Check if eve.json has entries: `tail -10 /var/log/suricata/eve.json`
- Ensure log_parser.py is running to consume eve.json → SQLite
