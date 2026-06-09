# Architecture Decision Document: Personal IDS + CVE Remediation Reports

**Project:** Home SOC Station  
**Author:** Tyler Megill  
**Date:** June 2026  
**Version:** 1.0

---

## Executive Summary

This document outlines the architectural decisions for two major extensions to the existing cybersecurity project:

1. **Scapy-based Personal IDS** — A lightweight, Python-native intrusion detection system that analyzes network traffic locally and correlates signatures with threat intelligence.
2. **CVE Remediation Reports** — Automated generation of actionable remediation reports from NVD API data, vendor advisories, and internal vulnerability scans.

Both components integrate into the existing Flask/HTMX dashboard architecture without requiring external services or cloud dependencies.

---

## 1. Scapy-Based Personal IDS

### 1.1 Why Scapy?

**Decision:** Use Scapy for network packet analysis instead of Zeek/Suricata alone.

**Reasoning:**

| Factor | Zeek/Suricata | Scapy | Decision Rationale |
|--------|---------------|-------|---------------------|
| Deployment model | Daemonized binary | Pure Python, inline with scripts | Existing stack uses Python; Scapy integrates directly without managing extra processes |
| Visibility depth | High-level flow analysis | Deep packet inspection (L7 payloads) | IDS needs payload inspection for signature matching; Zeek lacks this natively |
| Rule flexibility | External rule files (.rules/.suricata.yaml) | In-memory scripting, dynamic rule loading | Python-native allows adaptive rules via existing scripts; faster iteration during development |
| Dependencies | Binary + system services | `pip install` | Consistent with dashboard's zero-build goal; works on NAS/WSL2 without systemd complexity |
| Local-only enforcement | Possible but requires config | Built for scripting in local environments | Matches project's self-hosted philosophy |

**Tradeoffs acknowledged:**

- Scapy is less performant than Zeek on multi-Gigabit links → acceptable for home network (typically ≤1 Gbps)
- No built-in NIDS alert persistence → will integrate with existing SQLite logs via custom collector
- Requires Python 3.8+ compatibility verification before deployment

**Alternative considered:** `nfdump` + `suricata-logs-parser` pipeline

**Rejected because:** Adds binary dependencies; reduces portability; conflicts with Flask dashboard's zero-build principle.

---

### 1.2 IDS Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              Scapy Personal IDS (IDS Module)                  │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│   [Promiscuous Interface] ←→ [Packet Sniffer (scapy)]        │
│                          ↓                                     │
│              [Payload Inspector (L3/L4/L7)]                   │
│                          ↓                                     │
│   ┌─────────────────────┴──────────────────────────────┐     │
│   │  Signature Engine                                      │ │
│   │    • TCP/UDP Port Scanning Detection                │ │
│   │    • DNS Query Anomalies (subdomain enumeration)   │ │
│   │    • Suspicious Payload Patterns (SQLi/XSS-like)   │ │
│   │    • Brute-force attempts (repeated HTTP 401s)     │ │
│   └─────────────────────┬──────────────────────────────┘     │
│                          ↓                                     │
│   [Correlate with Threat Intel (local rules + CVE DB)]        │
│                          ↓                                     │
│   [Alert to SQLite Dashboard]                                  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

**Why this architecture?**

1. **Minimal external dependencies** — Signature engine uses only existing Python packages (`requests`, `yaml`, `sqlite3`)
2. **Extensible via scripts** — New signatures can be added as inline functions without recompiling binaries
3. **Correlates with CVE DB** — When a payload matches a known exploit pattern (e.g., SQL injection), cross-reference local CVE database

---

### 1.3 Signature Implementation Strategy

**Decision:** Use explicit Python dictionaries for rule definitions; no external YAML-only rules.

**Reasoning:**

- Rules can be version-controlled alongside code
- Can include test cases inline (unit tests against mock traffic)
- Easier to explain and audit than binary formats

**Example rule shape:**

```python
RULES = {
    "port_scan": {
        "signature": "Multiple SYN packets from same IP <target_port>",
        "pattern": lambda pkt: len(pkt['SYN']) > 3 and set(pkt['TARGET_PORT']) == {22,80,443},
        "severity": 7,
        "remediation_hint": "Configure firewall to rate-limit SYN packets per IP",
    },
}
```

**Tradeoff:** Less human-readable than YAML but easier to integrate with existing Python codebase.

---

## 2. CVE Remediation Reports

### 2.1 Why Generate Reports?

**Problem:** The existing auto-lookup engine fetches CVE data from NVD API and vendor advisories, but does not synthesize them into actionable guidance. Tyler needs:

1. **Single-source-of-truth** for vulnerability impact across assets
2. **Clear remediation paths** (patch versions, workarounds)
3. **Historical tracking** of which systems addressed which CVEs

**Decision:** Build a Python script that aggregates NVD + vendor data and outputs structured Markdown/HTML reports.

---

### 2.2 Report Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              CVE Remediation Report Generator                │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│   [NVD API] + [Vendor Advisories]                            │
│                        ↓                                     │
│         [Normalize CVE Schema (CVE ID, severity, CVSS)]     │
│                        ↓                                     │
│    [Join with Asset Scan Results (Nmap/Nuclei outputs)]      │
│                        ↓                                     │
│   [Filter: Affected Hosts Only]                              │
│                        ↓                                     │
│  ┌─────────────────┬─────────────────┐                       │
│  │ Remediation     │ Workaround/     │                       │
│  │ Notes (patch    │ Temporary       │                       │
│  │ version,         │ mitigation     │                       │
│  │ vendor          │ links           │                       │
│  │ knowledge base) │                 │                       │
│  └─────────────────┴─────────────────┘                       │
│                        ↓                                     │
│   [Generate Report (Markdown/HTML)]                          │
│        → Rendered in Flask Dashboard                         │
└─────────────────────────────────────────────────────────────┘
```

**Why Markdown?**

- Simple to read in terminal or web viewers
- Can be converted to HTML via existing HTMX templates
- Version-controlled alongside code (no binary dependencies)

---

### 2.3 Report Schema

Each CVE report entry must contain:

```yaml
cve_id: "CVE-2025-XXXXX"
title: "Vulnerability Description"
cvss_score: 8.5
severity: "HIGH"
affected_hosts:
  - ip: "192.168.1.X"
    asset_name: "Router"
    affected_component: "Firmware v3.2"
remediation:
  primary: "Patch to version Y.Z (vendor KB#12345)"
  secondary: "Disable vulnerable service (if applicable)"
workarounds:
  - action: "Add rate-limit rule for exploited endpoint"
    impact: "Reduces exploit probability by X%"
exploit_available: true
nvd_url: "https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"
vendor_advisory_url: "https://security.example.com/advisories/KB-12345"
```

**Why this schema?**

- Normalizes vendor-specific data into consistent fields
- Enables filtering by severity for dashboard display
- Supports both primary (patch) and secondary (workaround) remediation paths

---

### 2.4 Workflow Integration

**Existing components to extend:**

1. **`scanners/nmap_assets.py`** → Outputs host inventory with vulnerable software versions
2. **`scanners/vuln_lookup.py`** → Fetches CVE data from NVD API
3. **New component: `reports/cve_remediation_generator.py`** → Aggregates scan + lookup outputs and generates reports

**Integration point:** Flask dashboard endpoint `/api/reports/cves` that returns aggregated JSON; rendered as Markdown/HTML in dashboard views.

---

### 2.5 Why This Workflow?

**Tradeoffs considered:**

| Option | Pros | Cons | Decision |
|--------|------|------|----------|
| Email reports | Familiar to non-tech users | Hard to correlate with existing dashboard; prone to email spam filters | Rejected |
| External SaaS (e.g., Jira) | Feature-rich | Requires external API keys, account management, egress costs | Rejected |
| Local Markdown + Flask render | Zero dependencies, version-controlled, integrates with existing stack | Requires writing custom renderer (done via HTMX templates) | **Selected** |

---

## 3. File Structure Additions

```
cybersecurity-project/
├── IDS/                         # NEW: Scapy-based personal IDS
│   ├── __init__.py              # Package init + global rules
│   ├── sniffer.py               # Packet capture logic (interface binding, packet filters)
│   ├── signatures.py            # Rule definitions (port scan, DNS anomaly, etc.)
│   ├── threat_correlator.py     # Matches traffic against CVE/exploit DB
│   └── output/                  # Collected alerts → SQLite logs
│       └── alert_logger.py      # Writes to `db/alerts.db`
│
├── reports/                     # NEW: CVE report generator
│   ├── __init__.py
│   ├── generators/              # Report types (markdown, html)
│   │   ├── markdown.py          # Markdown output for terminal/console viewing
│   │   └── flask.html           # HTMX-rendered HTML for dashboard embedding
│   ├── aggregators/             # Data aggregation logic
│   │   ├── nvd_loader.py        # Fetches NVD API data (cached locally)
│   │   ├── vendor_advisories.py # Fetches Microsoft/Google advisories (optional)
│   │   └── vuln_matcher.py      # Correlates scan results with CVE data
│   └── cli.py                   # Command-line interface for report generation
│
├── db/                          # Existing database schema extended
│   ├── schema.sql               # Add tables: `alerts`, `remediation_status`
│   └── migrations/              # Migration scripts for new tables
│
├── api/                         # NEW: Flask API endpoints
│   ├── routes.py                # `/api/alerts`, `/api/reports/cves`
│   └── models.py                # SQLAlchemy-style ORM for SQLite schema mapping
│
├── config/                      # Extended configuration
│   ├── ids_config.yaml          # Scapy capture interface, packet filter rules
│   └── report_config.yaml       # Report frequency, output formats
│
└── docs/                        # Documentation updates
    ├── architecture.md          # Updated with new modules
    └── runbook.md               # IDS operational procedures, CVE reporting workflow
```

---

## 4. Why These Decisions? Summary

**Scapy over Zeek/Suricata-only:**

- Pure Python → no binary dependencies; matches existing stack
- Deep packet inspection → necessary for signature-based detection
- Extensible via inline rules → faster iteration during development

**Markdown/HTML reports over email/SaaS:**

- Zero egress costs
- Version-controlled and auditable
- Integrates with existing Flask dashboard architecture

**SQLite + ORM for alerts/remediation tracking:**

- Avoids adding new database dependencies
- Enables relational queries across assets, CVEs, remediation status

**Local-only design:**

- Matches project's core philosophy (self-hosted, no external services)
- Supports NAS/WSL2 deployments without Cloudflare/proxy configuration overhead

---

## 5. Next Steps for Implementation

1. **Create `IDS/` and `reports/` packages** — Package structure only (no implementation yet)
2. **Extend SQLite schema** — Add `alerts`, `remediation_status` tables
3. **Implement signature engine** — Start with port scan detection rule
4. **Build CVE report aggregator** — Fetch NVD data, match with scan results
5. **Add Flask API endpoints** — `/api/alerts`, `/api/reports/cves`
6. **Update dashboard views** — Render new endpoints in HTMX templates

---

## 6. Security Considerations

- **IDS:** Packet capture must be on promiscuous mode only for local interfaces (no external exposure)
- **CVE reports:** NVD API rate limiting; cache locally to avoid hitting API limits
- **Alert data:** Encrypt sensitive fields (source/dest IPs) in DB via column-level encryption if needed

---

*Document end.*
