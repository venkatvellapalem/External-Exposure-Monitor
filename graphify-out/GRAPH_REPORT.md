# Graph Report - .  (2026-07-20)

## Corpus Check
- Corpus is ~23,152 words - fits in a single context window. You may not need a graph.

## Summary
- 275 nodes · 483 edges · 12 communities (10 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 12 edges (avg confidence: 0.69)
- Token cost: 1,500 input · 600 output

## Community Hubs (Navigation)
- Collector Pipeline & Data Ingestion
- Core Authentication & Rate Limiting
- Frontend UI Dashboard Client
- Public Web UI Client Mirror
- Vercel Serverless API Handlers
- Interactive Terminal Configuration
- Active Network Scanner & Port Audit
- Splunk Web SSO Authentication Engine
- HTML Templates & Dashboard Views
- Project Architecture & Documentation
- Vercel Routing & Deployment Configuration
- Public Brand Assets & Icons

## God Nodes (most connected - your core abstractions)
1. `AuthManager` - 28 edges
2. `showToast()` - 14 edges
3. `ExposureEvent` - 14 edges
4. `showToast()` - 14 edges
5. `ActiveScanner` - 13 edges
6. `main()` - 12 edges
7. `initAuthFlow()` - 11 edges
8. `RateLimiter` - 11 edges
9. `BaselineEngine` - 11 edges
10. `initAuthFlow()` - 11 edges

## Surprising Connections (you probably didn't know these)
- `EASM Single Page Web Dashboard UI` --references--> `EASM Radar Brand Icon`  [EXTRACTED]
  index.html → favicon.svg
- `main()` --calls--> `ActiveScanner`  [EXTRACTED]
  collector.py → core/active_scanner.py
- `main()` --calls--> `BaselineEngine`  [EXTRACTED]
  collector.py → core/baseline.py
- `LeakMockHandler` --uses--> `ActiveScanner`  [INFERRED]
  simulate_leak.py → core/active_scanner.py
- `test_phase1()` --calls--> `AuthManager`  [EXTRACTED]
  scratch/test_auth_phase1.py → core/auth.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **EASM Frontend UI Components** — index_html_web_dashboard, public_index_html_web_dashboard, favicon_svg_branding [EXTRACTED 1.00]

## Communities (12 total, 2 thin omitted)

### Community 0 - "Collector Pipeline & Data Ingestion"
Cohesion: 0.06
Nodes (32): get_target_ips(), main(), Helper to resolve domain strings to IP address if needed., Yields unique individual tuples of (ip, domain/hostname) from the configured ass, resolve_reverse_dns(), resolve_to_ip(), CensysClient, Queries Censys Platform API v3 (hosts lookup) using a Personal Access Token (PAT (+24 more)

### Community 1 - "Core Authentication & Rate Limiting"
Cohesion: 0.07
Nodes (20): AuthManager, _get_fernet_key(), RateLimiter, Auth and IAM Engine supporting RBAC, salted bcrypt hashing, TOTP MFA, and JWT se, Bootstraps default Root Admin user if database doesn't exist., Creates initial root_admin account: admin / Admin@2026Secure!, Hashes plaintext password using salted bcrypt., Verifies password against stored bcrypt hash. (+12 more)

### Community 2 - "Frontend UI Dashboard Client"
Cohesion: 0.11
Nodes (34): addAsset(), applyRbacUI(), checkAuthSession(), clearAuthErrors(), closeProfileDropdown(), createIamUser(), deleteAsset(), deleteIamUser() (+26 more)

### Community 3 - "Public Web UI Client Mirror"
Cohesion: 0.11
Nodes (34): addAsset(), applyRbacUI(), checkAuthSession(), clearAuthErrors(), closeProfileDropdown(), createIamUser(), deleteAsset(), deleteIamUser() (+26 more)

### Community 4 - "Vercel Serverless API Handlers"
Cohesion: 0.09
Nodes (21): auth_change_password(), auth_me(), auth_splunk_sso(), extract_splunk_host(), get_assets_path(), get_baseline_path(), get_current_user_from_request(), get_env_path() (+13 more)

### Community 5 - "Interactive Terminal Configuration"
Cohesion: 0.13
Nodes (12): main(), normalize_splunk_url(), test_splunk_hec(), test_splunk_hec_direct(), BaselineEngine, Loads baseline state as a dictionary of ip:port mapping to status., Saves current state to disk., Returns the last known status ('open' or 'closed') or None if never seen. (+4 more)

### Community 6 - "Active Network Scanner & Port Audit"
Cohesion: 0.13
Nodes (10): ActiveScanner, Performs active verification of open ports and audits for leaked configuration f, Returns True if rustscan binary is installed in the system PATH., Runs RustScan to scan all 65,535 ports in parallel.                  Parses outp, Verifies if a port is actually open using a direct TCP connection., Scans a list of ports in parallel using a ThreadPoolExecutor to eliminate latenc, Checks for highly sensitive leaked files on HTTP/HTTPS ports.                  U, LeakMockHandler (+2 more)

### Community 7 - "Splunk Web SSO Authentication Engine"
Cohesion: 0.33
Nodes (4): Manages Single Sign-On (SSO) ticket generation with Splunk REST API on Port 8089, Obtains a Splunk Web session key via REST API on Port 8089., Constructs direct Splunk Web Dashboard Studio SSO URL with session ticket., SplunkSSOManager

### Community 8 - "HTML Templates & Dashboard Views"
Cohesion: 0.50
Nodes (4): Configured Target Asset Inventory, EASM Radar Brand Icon, EASM Single Page Web Dashboard UI, Public EASM Web UI Mirror

### Community 9 - "Project Architecture & Documentation"
Cohesion: 0.67
Nodes (3): EASM Decoupled System Architecture, External Exposure Monitor (EASM), Python Dependencies (Flask, PyOTP, Bcrypt, Cryptography)

## Knowledge Gaps
- **15 isolated node(s):** `lastUserActivity`, `sessionStartTime`, `TAB_SLUG_MAP`, `SLUG_TAB_MAP`, `lastUserActivity` (+10 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AuthManager` connect `Core Authentication & Rate Limiting` to `Vercel Serverless API Handlers`?**
  _High betweenness centrality (0.137) - this node is a cross-community bridge._
- **Why does `get_logger()` connect `Collector Pipeline & Data Ingestion` to `Core Authentication & Rate Limiting`?**
  _High betweenness centrality (0.099) - this node is a cross-community bridge._
- **Why does `ActiveScanner` connect `Active Network Scanner & Port Audit` to `Collector Pipeline & Data Ingestion`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `ExposureEvent` (e.g. with `BaselineEngine` and `CensysClient`) actually correct?**
  _`ExposureEvent` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `lastUserActivity`, `sessionStartTime`, `TAB_SLUG_MAP` to the rest of the system?**
  _15 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Collector Pipeline & Data Ingestion` be split into smaller, more focused modules?**
  _Cohesion score 0.06397306397306397 - nodes in this community are weakly interconnected._
- **Should `Core Authentication & Rate Limiting` be split into smaller, more focused modules?**
  _Cohesion score 0.06887755102040816 - nodes in this community are weakly interconnected._