# SOC Station — Task Tracker

## Phase 1 — IDS Foundation
- [ ] Suricata running in Docker Compose
- [ ] SQLite schema created
- [ ] log_parser.py writing alerts to DB
- [ ] .gitignore and .env.example added

## Phase 2 — Asset & CVE Scanning
- [ ] nmap_scanner.py discovering LAN devices
- [ ] cve_lookup.py querying NVD API with caching
- [ ] settings.yaml externalizing all config

## Phase 3 — Alerting Pipeline
- [ ] alerter.py sending Discord webhooks
- [ ] threat_feed.py enriching alerts with AbuseIPDB

## Phase 4 — Flask Dashboard
- [ ] Flask skeleton with base template
- [ ] /alerts route with HTMX live polling
- [ ] /assets route
- [ ] /cves route with severity badges

## Phase 5 — Portfolio Polish
- [ ] README with architecture diagram and screenshots
- [ ] docs/setup.md step-by-step guide
- [ ] Security hardening (secrets, rate limits, non-root)
