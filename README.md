     
   
**SSRF Cyart**  
**Autonomous SSRF Detection · Exploit · Verify Agent**  
     
     
   ![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAADUlEQVR4nGP4//8/AwAI/AL+p5qgoAAAAABJRU5ErkJggg==)  
     
   ![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAADUlEQVR4nGP4//8/AwAI/AL+p5qgoAAAAABJRU5ErkJggg==)  
   
   **10-Phase Pipeline  ·  Differential Probing  ·  OOB-Verified  ·  Chain-Pivoting  ·  Zero False Positives**  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKa/i8WMIR7ECt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85PAYartXEogAAAABJRU5ErkJggg==)  
**Overview**  
SSRF Cyart is an enterprise-grade autonomous SSRF (Server-Side Request Forgery) detection, exploitation, and verification agent built for modern web targets. It pairs a SPA-aware native crawler with a 10-phase detection pipeline that triage, baseline, classify, fingerprint, probe, and verify every SSRF-plausible parameter on the target — stopping only when a confirmed finding is produced or all vectors are exhausted.  
Every finding is verified via differential z-score analysis or out-of-band callback confirmation, timestamped, and delivered with a ready-to-run curl PoC and a SARIF 2.1.0 report.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd40A5GMORPYEt7WMGbCFuCLTNzVFcAAPzFvVZbdX49AQDgtf0BSrIDUgOg4eAAAAAASUVORK5CYII=)  
**Features**  
- **10-Phase Autonomous Pipeline** — Surface Triage → Baseline → Context Classify → WAF Fingerprint → Differential Probe → OOB Correlation → Evidence Engine → Chain/Pivot → Confidence Score → Adaptive Feedback  
- **Native BFS Crawler** — Read-only crawl with JS static analysis, form parsing, and OpenAPI/Swagger auto-discovery; no spider file required  
- **Differential Probing** — z-score anomaly detection on timing, content-length, redirect depth, and status code — capped at 10.0 with a 2-dimension noise floor to eliminate false positives  
- **OOB Blind SSRF Confirmation** — Per-candidate Interactsh tokens; async pattern detection for FIRM-tier findings without guessing  
- **Evidence Engine** — Cloud IMDS (AWS/GCP/Azure), Kubernetes API, ECS Metadata, Oracle Cloud, Redis/Memcached banner, file read — schema-matched artifact extraction for CERTAIN-tier confirmation  
- **WAF Fingerprinting & Evasion** — 11 vendor signatures (Cloudflare, Akamai, AWS WAF, Imperva, F5, etc.) with per-vendor adaptive mutation chains  
- **Chain / Pivot Detection** — Second-order SSRF, DNS rebinding detection, K8s/ECS lateral pivot, up to max_hops=3 depth  
- **Confidence Scoring System** — 4-tier confidence model (TENTATIVE → FIRM → CERTAIN → CRITICAL+) with known-exploit escalation and reduction caps  
- **Authenticated Scanning** — Cookie, Bearer token, API key injection; auto-detected from spider headers  
- **Adaptive Feedback Loop** — Pattern propagation across candidates, WAF chain caching, IMDSv2 token escalation between phases  
- **Structured Reporting** — JSON + SARIF 2.1.0 output; curl PoC per finding; CVSS scores per tier  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUZfE2IYmVDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/xcF7U7sx4wAAAAASUVORK5CYII=)  
**Installation**  
 cd ssrf-cyart  
 chmod +x install.sh  
 ./install.sh  
   
Requires Python 3.10+. Creates an isolated .venv and links ssrf-cyart globally via /usr/local/bin/ssrf-cyart.  
# Manual install (development editable mode)  
 python3 -m venv .venv  
 source .venv/bin/activate  
 pip install -e .  
   
 # Verify installation  
 ssrf-cyart --version  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAUBBAwSfIb+HdmNvAkgaxgjcRZhLMNjNHdQUAwF/ce7Wq8+sJAACvrQctewNKtdojwQAAAABJRU5ErkJggg==)  
**Usage**  
# Basic detect scan from Hellhound Spider JSON file  
 ssrf-cyart --input spider_output.json http://target.com  
   
 # No spider file — SSRF Cyart crawls the target itself  
 ssrf-cyart http://target.com  
   
 # Native crawl scoped to an extra API subdomain, deeper BFS  
 ssrf-cyart http://target.com --crawl-scope api.target.com --crawl-depth 8  
   
 # With OOB for blind SSRF confirmation (FIRM tier findings)  
 ssrf-cyart --input spider.json --oob https://oast.pro  
   
 # Authenticated scan — Bearer token (JWT)  
 ssrf-cyart --input spider.json --bearer eyJhbGciOiJIUzI1NiJ9...  
   
 # Authenticated scan — Cookie + API key  
 ssrf-cyart --input spider.json --cookie session=abc123 --api-key sk-prod --api-key-header X-Api-Key  
   
 # Full pentest: OOB + auth + Burp proxy intercept  
 ssrf-cyart --input spider.json \  
            --oob https://oast.pro \  
            --bearer eyJhbGciOiJIUzI1NiJ9... \  
            --proxy http://127.0.0.1:8080  
   
 # Exploit mode — unlocks Gopher/Dict protocol probing (requires YES acknowledgment)  
 ssrf-cyart --input spider.json --mode detect_exploit  
   
 # Quiet CI/CD pipeline mode  
 ssrf-cyart --input candidates.json --quiet --output /tmp/ssrf-cyart-results  
   
 # Verbose mode — show all candidate decisions  
 ssrf-cyart --input spider.json --verbose  
   
 # Rate limiting + custom timeout  
 ssrf-cyart --input spider.json --rate 10 --timeout 15  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsad4EEtY9QcxnUms4E2ELcGWmTmrKwAA/uLeqrU6vp4AAPDa/gDzXgM37EF77AAAAABJRU5ErkJggg==)  
**Input Formats**  
SSRF Cyart supports three input modes that all converge on the same triage and filter pipeline:  
| | | |  
|-|-|-|  
| **Mode** | **Flag** | **Description** |   
| **Spider JSON** (recommended) | --input spider.json | Output from [Hellhound Spider. Auto-detected by endpoints + meta keys. Provides full surface coverage.](https://github.com/project-hellhound-org/X5Sentry "https://github.com/project-hellhound-org/X5Sentry") |   
| **Flat Candidate Array** | --input candidates.json | JSON array of explicit candidate objects. Each entry requires url, method, parameter, location. |   
| **Native Crawl** | *(no * *--input* *)* | Provide a target URL only. SSRF Cyart crawls the target via BFS, form parsing, and static JS analysis — then feeds discovery through the same pipeline. |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd4NIGBzPXBmAawhhW8ibAl2DIze3UGAMBf3Gu1VcfXEwAAXrsehaQEN+8fLHEAAAAASUVORK5CYII=)  
**10-Phase Pipeline**  
| | | |  
|-|-|-|  
| **Phase** | **Name** | **What it does** |   
| 00 | **Surface Triage** | Pre-score all candidates HIGH/MEDIUM/LOW via prescore.py; drop zero-score entries before any I/O |   
| 01 | **Baseline Collection** | 5 clean samples per candidate; auth-redirect detection; infra-noise fingerprinting via InfraNoiseTracker |   
| 02 | **Context Classifier** | Classify each candidate as fetch_url / redirect / file_include / crlf_injection / host_header |   
| 03 | **WAF Fingerprint** | 11 vendor signatures; score-based matching; per-vendor adaptive mutation chains via waf_detector.py |   
| 04 | **Differential Probe** | z-score anomaly on timing, redirect depth, status code, content-length (cap 10.0, 2-dim floor) |   
| 05 | **OOB Correlation** | Per-candidate Interactsh token injection; async callback polling; DNS/HTTP pattern matching |   
| 06 | **Evidence Engine** | AWS IMDS, GCP metadata, Azure IMDS, K8s API, ECS, Oracle Cloud, Redis/Memcached, file-read probing |   
| 07 | **Chain / Pivot** | Second-order SSRF; DNS rebinding detection; K8s/ECS lateral pivot; max_hops=3 recursion |   
| 08 | **Confidence Scoring** | Known-exploit registry escalation; reduction caps; per-candidate final tier assignment |   
| 09 | **Reporter** | JSON report + SARIF 2.1.0; curl PoC per finding; CVSS per tier; timestamped artifacts |   
| 10 | **Adaptive Feedback** | Pattern propagation across candidates; WAF chain caching; IMDSv2 token escalation |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCUpfDq4wwIAABiywEZJWQZeZ2ao9AAD+4liruzq/ngAA8Nr1ABweBgdur/QFAAAAAElFTkSuQmCC)  
**Confidence Tiers**  
| | | | |  
|-|-|-|-|  
| **Tier** | **Signal** | **CVSS** | **Severity** |   
| TENTATIVE | Differential anomaly detected — no external confirmation | 4.3 | Medium |   
| FIRM | OOB callback confirmed — server made outbound request | 6.5 | High |   
| CERTAIN | Schema-matched evidence artifact (IMDS body, Redis banner, K8s version) | 8.6 | Critical |   
| CRITICAL+ | Chained SSRF, K8s API access, or known-exploitable internal service reached | 9.6 | Critical |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAUBBAwSf8GGLWDWFDY3ixgjcRZhLMNjNHdQYAwF9cq1rV/vUEAIDX7gcRXAQ2s/16gwAAAABJRU5ErkJggg==)  
**Scan Modes**  
| | | |  
|-|-|-|  
| **Mode** | **Flag** | **Description** |   
| detect | *(default)* | Read-only detection. Safe for production targets. All 10 phases active but evidence collection restricted to non-destructive operations only. |   
| detect_exploit | --mode detect_exploit | Unlocks Gopher/Dict protocol banner probing. Still read-only. Requires operator YES acknowledgment at runtime. **Pentest-only.** |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNhRAF6EPYDLhGADSywEZJWQZeZ2aszAAD+4l6rrTq+ngAA8Nr1AIWsBDYDm5cLAAAAAElFTkSuQmCC)  
**Components**  
| | |  
|-|-|  
| **Module** | **Role** |   
| main.py | CLI entry point — argument parsing, config loading, orchestration |   
| core/agent.py | Core orchestrator — 10-phase pipeline runner with per-phase console output |   
| core/crawler.py | Native BFS crawler — BFS, form parsing, JS static analysis, sitemap/robots.txt |   
| core/spider_adapter.py | Converts Hellhound Spider JSON or flat arrays into scored Candidate objects |   
| core/prescore.py | Phase 00 — relevance scoring and triage queue ordering |   
| core/baseline.py | Phase 01 — baseline profiling, infra-noise tracking, auth-redirect detection |   
| core/context_classifier.py | Phase 02 — parameter context classification into 5 SSRF context classes |   
| core/waf_detector.py | Phase 03 — 11 WAF vendor fingerprinting with adaptive evasion mutation chains |   
| core/differential.py | Phase 04 — z-score statistical anomaly probing engine |   
| core/oob_hub.py | Phase 05 — Interactsh OOB token lifecycle management and async polling |   
| core/evidence_engine.py | Phase 06 — cloud metadata, Kubernetes API, Redis/Memcached, file-read extraction |   
| core/chaining.py | Phase 07 — second-order SSRF pivot, DNS rebinding detection |   
| core/scoring.py | Phase 08 — confidence tier assignment and reduction cap enforcement |   
| core/reporter.py | Phase 09 — JSON + SARIF 2.1.0 report generation and curl PoC builder |   
| core/feedback.py | Phase 10 — cross-candidate pattern propagation and adaptive chain caching |   
| core/http_client.py | Async HTTP engine with rate limiting, proxy support, redirect handling |   
| core/models.py | Core data models — Candidate, ProbeResult, BaselineProfile, ScanReport, etc. |   
| core/payload_engine.py | SSRF payload construction — Gopher, Dict, cloud metadata URLs, mutation chains |   
| core/auth_manager.py | Authentication injection — Bearer, Cookie, API key; spider header auto-detection |   
| core/loader.py | Input file ingestion — Spider JSON and flat candidate array format parsing |   
| core/console.py | Terminal UI — Cyber Tactical HUD, phase headers, status board, colour system |   
| core/known_exploits.py | Known-exploit registry — escalation rules for internal services and cloud APIs |   
| core/openapi_adapter.py | OpenAPI/Swagger spec auto-discovery and candidate generation |   
| core/graphql_adapter.py | GraphQL introspection-based SSRF surface extraction |   
| core/dns_intel.py | DNS intelligence gathering for rebinding and pivot analysis |   
| core/js_intel.py | Static JS analysis — fetch/axios/XHR string literal extraction |   
| core/recon_quality.py | Crawler output quality scoring and coverage gap detection |   
| core/wayback_probe.py | Wayback Machine historical endpoint discovery |   
| core/subdomain_enum.py | Subdomain enumeration for crawl scope expansion |   
| core/spa_detector.py | SPA framework detection — React, Angular, Vue, Next.js |   
| core/vuln_classifier.py | Post-probe vulnerability classification and severity mapping |   
| install.sh | High-fidelity installer — creates .venv, installs deps, deploys global command |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd49m4tA8nPaQJjWMGbCFuCLTOzV2cAAPzFvVZbdXw9AQDgtesBorcEPwOKyvQAAAAASUVORK5CYII=)  
**CLI Reference**  
ssrf-cyart [OPTIONS] <target_url>  
 ssrf-cyart --input <spiderfile.json> [target_url] [OPTIONS]  
   
 Authentication:  
   --bearer TOKEN          Bearer/JWT token injected into every request  
   --api-key KEY           API key value  
   --api-key-header HDR    Header name for --api-key (default: X-Api-Key)  
   --cookie NAME=VALUE     Session cookie (repeatable)  
   
 OOB:  
   --oob URL               Interactsh server for blind SSRF confirmation  
   
 Crawl (when --input is omitted):  
   --crawl-depth N         BFS max depth (default: 5)  
   --crawl-max-pages N     Page budget (default: 40, ceiling: 400)  
   --crawl-scope HOST      Extra in-scope host (repeatable)  
   --no-crawl-js           Disable static JS analysis  
   
 Scan Control:  
   --mode MODE             detect (default) | detect_exploit  
   --rate N                Requests per second (default: 20)  
   --timeout N             Per-request timeout in seconds (default: 10)  
   --max-hops N            SSRF chain depth limit (default: 3)  
   --no-openapi            Disable OpenAPI/Swagger auto-discovery  
   --proxy URL             HTTP proxy (e.g. http://127.0.0.1:8080)  
   --config PATH           Path to config.yaml  
   
 Output:  
   --output DIR            Report directory (default: ./reports)  
   --verbose               Show all candidates including clean/skipped  
   --quiet                 Suppress banner and status board  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAQBBAwSdcjsu6HYxoDsEK/okwk2COmdnVGQAAf3GtalX76wkAAK/dDxFWBDkFf6+SAAAAAElFTkSuQmCC)  
**Requirements**  
httpx[http2]>=0.27.0  
 PyYAML>=6.0.1  
 rich>=13.7.1  
   
 # Optional — headless rendering for SPA targets  
 playwright>=1.44.0  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhZscVjnidKEAGFtgISaugy8zs1RkAAH9xr9VWHV9PAAB47XoAor8EPg1yCpUAAAAASUVORK5CYII=)  
**Legal**  
SSRF Cyart must only be used against systems you are **explicitly authorized to test**. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction.  
*This tool is intended solely for authorized security assessments, red-team engagements, and security research.*  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSeYxZw/lieLGMACBrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA6fGBdgoVMwYAAAAAElFTkSuQmCC)  
   Built by **Hellhound Security**  ·  Part of the [Project Hellhound toolkit  
 ](https://github.com/project-hellhound-org "https://github.com/project-hellhound-org")  
