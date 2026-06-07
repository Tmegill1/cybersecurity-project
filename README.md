# Home SOC Station Project

**Description:** A personal Security Operations Center dashboard for monitoring your home network traffic, scanning for vulnerabilities, and automatically looking up vulnerability descriptions and fixes from security databases.

---

## What We're Building

A self-hosted interactive dashboard that:

1. **Monitors Network Traffic:** Uses Zeek (formerly Bro) to analyze network flows and detect anomalies
2. **Scans for Vulnerabilities:** Nmap-based asset discovery, Nuclei vulnerability scanning, OS-level checks
3. **Auto-looks up Vuln Details:** Pulls CVE data from NVD API, vendor advisories (Microsoft, Google, etc.), and cross-references known exploits
4. **Interactive Dashboard:** Live view of detected threats, historical scan results, and remediation tracking

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Home SOC Dashboard                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  [Dashboard] ← Flask/HTMX → SQLite                          │
│      (zero build step, local deployment)                     │
│                      ↓                                        │
│  ┌──────────────────┬──────────────────┬──────────────────┐ │
│  │  Network Monitor │ Vulnerability     │ Auto-lookup Vuln │ │
│  │                  │ Scanner          │ Engine            │ │
│  ├──────────────────┼──────────────────┼──────────────────┤ │
│  │ Zeek (network)   │ Nmap + custom    │ CVE JSON API,    │ │
│  │ Suricata (IDS)   │ vuln scanner     │ vendor advisories │ │
│  │ NetFlow collector│                  │ local rules       │ │
│  └──────────────────┴──────────────────┴──────────────────┘ │
│                         ↓                                     │
│                   SQLite + JSON logs                          │
│                      (local disk)                            │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Hosting Decision: Local Docker on NAS/Raspberry Pi

- **Zero egress costs**
- **Direct traffic capture via promiscuous mode**
- **Simple LAN accessibility** (no Cloudflare needed)
- **Optional external access via cloudflared tunnel if desired**

---

## Technology Stack

| Component       | Technology          | Purpose                  |
|-----------------|---------------------|--------------------------|
| Dashboard       | Flask/HTMX          | Zero build, local deployment |
| Database        | SQLite              | Event logs and metrics  |
| Network Monitor | Zeek + Suricata     | Traffic analysis & IDS  |
| Asset Discovery | Nmap                | Host enumeration         |
| Vuln Scanner    | Nuclei + custom scripts | CVE detection      |
| Lookup Engine   | Python requests     | CVE JSON, vendor feeds  |

---

## Development Roadmap

### Phase 1: Foundation (Week 1)
- [ ] Create local dev environment (Docker Compose on NAS/WSL2)
- [ ] Build network monitor baseline (Zeek + log collector)
- [ ] Basic HTML dashboard skeleton with Flask/HTMX

### Phase 2: Vulnerability Scanning (Week 2-3)
- [ ] Implement Nmap-based asset discovery
- [ ] Add vuln scanner integration (Nuclei or custom Python scripts)
- [ ] Auto-lookup engine for CVE/NVD API queries

### Phase 3: Dashboard Integration (Week 3-4)
- [ ] Live traffic visualization
- [ ] Vulnerability alerting and detail view
- [ ] Rule engine for severity scoring

### Phase 4: Security Hardening (Week 5)
- [ ] Rate limiting on API endpoints
- [ ] Database backup automation
- [ ] Audit logging

---

## Project Structure

```
cybersecurity-project/
├── README.md                 # This file
├── dashboard/                # Flask app & HTML templates
│   ├── app.py               # Main entry point
│   ├── requirements.txt     # Python dependencies
│   └── templates/           # HTMX views
├── docker/                  # Docker Compose stacks
│   ├── docker-compose.yaml  # Main compose file
│   └── network-monitor/     # Zeek/Suricata configs
├── scanners/                # Vulnerability scanning scripts
│   ├── nmap_assets.py       # Asset discovery
│   ├── nuclei_scanner.py    # Vuln scanning
│   └── vuln_lookup.py       # CVE API integration
├── db/                      # SQLite schema & migrations
│   ├── schema.sql           # Database structure
│   └── migrations/          # Versioned migrations
├── config/                  # Configuration files
│   └── settings.yaml        # App settings (secrets in .env)
├── docs/                    # Documentation
│   ├── architecture.md      # This doc, expanded
│   └── runbook.md           # Operational procedures
└── tracking.html            # Interactive progress dashboard
```

---

## Getting Started (Local Deployment)

1. **Clone this repo** to your NAS/Raspberry Pi or WSL2 host
2. **Install Docker** and dependencies:
   ```bash
   docker-compose up -d
   ```
3. **Access dashboard:** `http://<host-ip>:5000`

---

## Security Considerations

- **Local-only deployment** by default (no public internet exposure)
- Optional Cloudflare Tunnel for external access to dashboard only
- Secrets stored in `.env` file, never hardcoded
- Rate limiting on all API endpoints

---

## Current Status

Refer to `tracking.html` for live progress tracking and task checklist.
