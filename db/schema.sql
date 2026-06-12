-- SOC Station Database Schema
-- SQLite only — raw logs stay in Suricata's eve.json on disk

-- Table: alerts
-- Purpose: Store normalized alert events for dashboard viewing
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,           -- ISO 8601 timestamp when alert fired
    src_ip TEXT NOT NULL,              -- Source IP of the attack
    dest_ip TEXT NOT NULL,             -- Destination IP attacked
    src_port INTEGER,                  -- Source port (may be null)
    dest_port INTEGER,                 -- Destination port being targeted
    proto TEXT NOT NULL,               -- Protocol: tcp/udp/etc
    signature TEXT NOT NULL,           -- Rule/signature that matched
    severity INTEGER NOT NULL,         -- 1=critical, 2=high, 3=medium, 4=low
    category TEXT,                     -- e.g., 'policy-violation', 'exfiltration'
    notified INTEGER DEFAULT 0,        -- 1 if webhook/email sent, 0 otherwise
    raw_json TEXT                      -- Full eve.json alert event for debugging
);

-- Create index on signature for dashboard queries
CREATE INDEX IF NOT EXISTS idx_alerts_signature ON alerts(signature);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

-- Table: assets
-- Purpose: Track discovered hosts, their services, and scan history
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,   -- Discovered IP address
    hostname TEXT,                     -- DNS/hosts file resolution
    mac_address TEXT,                  -- From Nmap/mac lookup
    os_guess TEXT,                     -- Nmap OS detection guess
    open_ports TEXT,                   -- JSON array of ports with service/version
    last_seen TEXT NOT NULL,           -- ISO 8601 last scan timestamp
    first_seen TEXT                    -- ISO 8601 first time discovered
);

-- Create indexes for dashboard lookups
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);

-- Table: cves
-- Purpose: Store CVE lookups against discovered services
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,         -- FK to assets.id
    cve_id TEXT NOT NULL,              -- e.g., CVE-2024-1234
    description TEXT,                  -- Summary of vulnerability
    cvss_score REAL,                   -- CVSS score 0.0-10.0
    severity TEXT NOT NULL,            -- critical/high/medium/low
    published_date TEXT,               -- ISO 8601 NVD publish date
    remediation_url TEXT,              -- Vendor advisory or fix URL
    last_fetched TEXT                 -- When this CVE data was fetched
);

-- FK constraint: cves.asset_id references assets.id
-- SQLite doesn't support DELETE CASCADE on tables without ON UPDATE/DELETE
-- Use triggers for cascade behavior if needed
CREATE INDEX IF NOT EXISTS idx_cves_asset_id ON cves(asset_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);

-- Table: threat_intel
-- Purpose: Cache IP reputation data from AbuseIPDB/OTX
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,          -- IP address being checked
    source TEXT NOT NULL,              -- 'abuseipdb' or 'otx'
    confidence_score REAL,             -- AbuseIPDB score 0-100
    categories TEXT,                   -- JSON array of categories
    country TEXT,                      -- Two-letter ISO code if available
    last_checked TEXT                  -- When this data was fetched
);

-- FK: threat_intel.ip_address may match alerts.src_ip for dashboard join
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel(ip_address);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel(source);
