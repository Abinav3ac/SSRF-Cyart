# SSRF Cyart

**Autonomous Server-Side Request Forgery (SSRF) Detection and Verification**

SSRF Cyart is a Python-based security assessment tool for discovering, probing, and verifying potential Server-Side Request Forgery (SSRF) vulnerabilities in web applications and APIs. It combines a native breadth-first-search (BFS) crawler with a staged analysis pipeline for candidate triage, baseline collection, context classification, WAF fingerprinting, differential probing, out-of-band (OOB) correlation, evidence collection, chain analysis, confidence scoring, and structured reporting.

Findings can include supporting evidence, timestamps, reproducible `curl` proof-of-concept commands, JSON output, and SARIF 2.1.0 reports. Detection results should always be reviewed in the context of the target application and the authorization scope.

> **Authorized use only:** Run SSRF Cyart only against systems you own or have explicit permission to assess. Even read-oriented scans send requests and may affect target logs, rate limits, or availability. Confirm scope and scan limits before testing.

## Contents

- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Input Formats](#input-formats)
- [Pipeline Overview](#pipeline-overview)
- [Confidence Tiers](#confidence-tiers)
- [Scan Modes](#scan-modes)
- [CLI Reference](#cli-reference)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Legal and Responsible Use](#legal-and-responsible-use)
- [Project](#project)

## Key Features

- **Staged detection pipeline** — Triage, baseline collection, context classification, WAF fingerprinting, differential probing, OOB correlation, evidence collection, chain/pivot analysis, confidence scoring, reporting, and adaptive feedback.
- **Native BFS crawler** — Discovers pages and candidate surfaces through form parsing, static JavaScript analysis, and sitemap/`robots.txt` handling; OpenAPI/Swagger discovery is also supported. A spider input file is optional.
- **Differential probing** — Uses z-score analysis across response timing, content length, redirect depth, and HTTP status behavior, with thresholds and noise controls intended to reduce false positives.
- **Blind SSRF confirmation** — Supports per-candidate Interactsh correlation and asynchronous DNS/HTTP callback polling when an OOB endpoint is configured.
- **Evidence collection** — Includes probes for cloud metadata endpoints (AWS, GCP, Azure, and Oracle Cloud), Kubernetes and ECS metadata surfaces, Redis/Memcached banners, and file-read indicators.
- **WAF fingerprinting** — Includes signatures for 11 WAF vendors and vendor-specific mutation chains.
- **Chain and pivot analysis** — Supports second-order SSRF analysis, DNS rebinding detection, and Kubernetes/ECS pivot checks with a configurable hop limit.
- **Confidence scoring** — Assigns findings to four tiers: `TENTATIVE`, `FIRM`, `CERTAIN`, and `CRITICAL+`.
- **Authenticated assessment** — Supports Bearer tokens, session cookies, and API keys, including header information imported from spider input where available.
- **Adaptive feedback** — Propagates patterns between candidates, caches WAF mutation chains, and supports IMDSv2 token escalation logic.
- **Structured output** — Produces JSON and SARIF 2.1.0 reports, timestamps artifacts, and can include a `curl` PoC for each reported finding.
- **Workflow integration** — Supports HTTP proxy configuration, rate limiting, quiet output, and configurable report directories.

## Installation

### Install using the project installer

From the repository directory:

```bash
cd ssrf-cyart
chmod +x install.sh
./install.sh
```

The installer is designed to create an isolated `.venv`, install the project dependencies, and expose the `ssrf-cyart` command through `/usr/local/bin/ssrf-cyart`. The global link may require elevated permissions, depending on your environment.

Verify the installation:

```bash
ssrf-cyart --version
```

### Manual installation (development mode)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
ssrf-cyart --version
```

**Requirement:** Python 3.10 or newer.

## Quick Start

### Scan a target with the native crawler

```bash
ssrf-cyart https://target.example
```

### Scan candidates from Hellhound Spider output

```bash
ssrf-cyart --input spider_output.json https://target.example
```

### Specify an output directory

```bash
ssrf-cyart --input candidates.json --quiet --output ./reports
```

Use only a target and input file that are within your authorized assessment scope.

## Usage Examples

### Native crawl with an additional in-scope API host

```bash
ssrf-cyart https://target.example \
  --crawl-scope api.target.example \
  --crawl-depth 8
```

### Out-of-band checks for blind SSRF

```bash
ssrf-cyart --input spider.json --oob https://oast.example
```

Replace the example hostname with an OOB endpoint you control or are authorized to use.

### Authenticated assessment with a Bearer token

```bash
export CYART_TOKEN='replace-with-an-authorized-test-token'
ssrf-cyart --input spider.json --bearer "$CYART_TOKEN"
unset CYART_TOKEN
```

### Authenticated assessment with a session cookie and API key

```bash
export CYART_COOKIE='session=replace-with-test-session'
export CYART_API_KEY='replace-with-test-api-key'

ssrf-cyart --input spider.json \
  --cookie "$CYART_COOKIE" \
  --api-key "$CYART_API_KEY" \
  --api-key-header X-Api-Key

unset CYART_COOKIE CYART_API_KEY
```

Avoid putting real credentials directly in shell commands, scripts, or shared logs. Environment variables reduce accidental exposure in command text, but they are not a secret-management system.

### Use a local HTTP proxy (for example, Burp Suite)

```bash
ssrf-cyart --input spider.json \
  --proxy http://127.0.0.1:8080
```

### Enable the additional protocol-probing mode

```bash
ssrf-cyart --input spider.json --mode detect_exploit
```

This mode is intended for authorized penetration tests. Review the tool's runtime acknowledgment and the scope rules for your engagement before proceeding.

### Adjust request rate and timeout

```bash
ssrf-cyart --input spider.json --rate 10 --timeout 15
```

### Inspect clean and skipped candidates

```bash
ssrf-cyart --input spider.json --verbose
```

## Input Formats

All input modes feed into the same candidate triage and filtering workflow.

| Mode | How to use it | Description |
|---|---|---|
| **Hellhound Spider JSON** (recommended) | `--input spider.json` | Uses output from [Hellhound Spider / X5Sentry](https://github.com/project-hellhound-org/X5Sentry). Candidate endpoints and metadata are detected from the input structure. |
| **Flat candidate array** | `--input candidates.json` | Accepts a JSON array of candidate objects. Each entry requires `url`, `method`, `parameter`, and `location`. |
| **Native crawl** | Provide a target URL without `--input` | Performs a BFS crawl with form parsing and static JavaScript analysis, then sends discovered candidates through the pipeline. |

## Pipeline Overview

The implementation labels its stages from `00` through `10`.

| Phase | Stage | Responsibility |
|---:|---|---|
| 00 | **Surface triage** | Scores candidates as HIGH, MEDIUM, or LOW and removes zero-score entries before network I/O. |
| 01 | **Baseline collection** | Collects five clean samples per candidate; detects authentication redirects and tracks infrastructure noise. |
| 02 | **Context classification** | Classifies candidates into `fetch_url`, `redirect`, `file_include`, `crlf_injection`, or `host_header` contexts. |
| 03 | **WAF fingerprinting** | Matches WAF vendor signatures and selects vendor-specific mutation chains. |
| 04 | **Differential probing** | Analyzes timing, redirect depth, status code, and content-length anomalies using z-score thresholds and a multi-dimension noise floor. |
| 05 | **OOB correlation** | Injects candidate-specific Interactsh tokens and correlates asynchronous DNS/HTTP callbacks. |
| 06 | **Evidence engine** | Checks configured cloud metadata, Kubernetes/ECS, Redis/Memcached, and file-read evidence paths. |
| 07 | **Chain / pivot analysis** | Examines second-order SSRF, DNS rebinding, and Kubernetes/ECS pivot opportunities within the configured hop limit. |
| 08 | **Confidence scoring** | Applies known-exploit escalation and reduction rules to assign a final confidence tier. |
| 09 | **Reporting** | Generates JSON and SARIF 2.1.0 output, timestamps artifacts, and builds `curl` PoCs where available. |
| 10 | **Adaptive feedback** | Propagates observed patterns across candidates, caches WAF chains, and supports IMDSv2 token escalation logic. |

## Confidence Tiers

The tiers express the strength of the evidence collected. They are not a substitute for analyst validation or environment-specific impact assessment.

| Tier | Evidence signal (as defined by the project) | Reference CVSS | CVSS v3.1 severity band |
|---|---|---:|---|
| `TENTATIVE` | Differential anomaly detected without external confirmation | 4.3 | Medium |
| `FIRM` | OOB callback confirms an outbound request | 6.5 | Medium |
| `CERTAIN` | Schema-matched evidence artifact, such as an IMDS response, Redis banner, or Kubernetes version | 8.6 | High |
| `CRITICAL+` | Chained SSRF, Kubernetes API access, or a known-exploitable internal service is reached | 9.6 | Critical |

**Scoring note:** The numbers above are the project's reference values from the supplied specification. CVSS is intended to rate the severity of a specific vulnerability using its characteristics and impact; a confidence tier alone is not enough to determine an appropriate CVSS score. Recalculate and document the score for each validated finding before using it for formal risk decisions. CVSS v3.1 rates 6.5 as **Medium** and 8.6 as **High**, according to FIRST's severity scale: [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification.document).

## Scan Modes

| Mode | Flag | Description |
|---|---|---|
| **Detection** (default) | `--mode detect` or omit `--mode` | Read-oriented detection workflow. Evidence collection is described by the project as restricted to non-destructive operations in this mode. Requests can still affect the target, so production use requires authorization and suitable rate limits. |
| **Detection / additional protocol probing** | `--mode detect_exploit` | Enables additional Gopher/Dict protocol banner probing. The project describes this mode as read-only and requires a runtime `YES` acknowledgment; use it only in an authorized penetration test. |

## CLI Reference

```text
ssrf-cyart [OPTIONS] <target_url>
ssrf-cyart --input <spiderfile.json> [target_url] [OPTIONS]
```

### Authentication

| Option | Description |
|---|---|
| `--bearer TOKEN` | Inject a Bearer/JWT token into requests. |
| `--api-key KEY` | API key value. |
| `--api-key-header HDR` | Header name for the API key; default: `X-Api-Key`. |
| `--cookie NAME=VALUE` | Session cookie; repeatable. |

### Out-of-band confirmation

| Option | Description |
|---|---|
| `--oob URL` | Interactsh-compatible server endpoint for blind SSRF correlation. |

### Crawling (when `--input` is omitted)

| Option | Default / description |
|---|---|
| `--crawl-depth N` | Maximum BFS depth; default: `5`. |
| `--crawl-max-pages N` | Page budget; default: `40`, documented ceiling: `400`. |
| `--crawl-scope HOST` | Add an in-scope host; repeatable. |
| `--no-crawl-js` | Disable static JavaScript analysis. |

### Scan control

| Option | Default / description |
|---|---|
| `--mode MODE` | `detect` (default) or `detect_exploit`. |
| `--rate N` | Request rate per second; default: `20`. |
| `--timeout N` | Per-request timeout in seconds; default: `10`. |
| `--max-hops N` | SSRF chain depth limit; default: `3`. |
| `--no-openapi` | Disable OpenAPI/Swagger auto-discovery. |
| `--proxy URL` | HTTP proxy, such as `http://127.0.0.1:8080`. |
| `--config PATH` | Path to `config.yaml`. |

### Output and diagnostics

| Option | Description |
|---|---|
| `--output DIR` | Report directory; default: `./reports`. |
| `--verbose` | Show all candidates, including clean or skipped entries. |
| `--quiet` | Suppress the banner and status board. |

Use `ssrf-cyart --help` to check the options supported by the installed version.

## Project Structure

| Module | Responsibility |
|---|---|
| `main.py` | CLI entry point, argument parsing, configuration loading, and orchestration. |
| `core/agent.py` | Runs the staged pipeline and emits phase-level console output. |
| `core/crawler.py` | Native BFS crawler, form parsing, JavaScript analysis, sitemap, and `robots.txt` handling. |
| `core/spider_adapter.py` | Converts Hellhound Spider JSON or flat arrays into scored candidate objects. |
| `core/prescore.py` | Candidate relevance scoring and triage ordering. |
| `core/baseline.py` | Baseline profiling, infrastructure-noise tracking, and authentication-redirect detection. |
| `core/context_classifier.py` | Classifies candidate parameters into five SSRF context classes. |
| `core/waf_detector.py` | WAF fingerprinting and adaptive mutation chains. |
| `core/differential.py` | Z-score-based statistical anomaly probing. |
| `core/oob_hub.py` | Interactsh token lifecycle management and asynchronous callback polling. |
| `core/evidence_engine.py` | Cloud metadata, Kubernetes API, Redis/Memcached, and file-read evidence checks. |
| `core/chaining.py` | Second-order SSRF, pivot analysis, and DNS rebinding detection. |
| `core/scoring.py` | Confidence-tier assignment and score-reduction rules. |
| `core/reporter.py` | JSON/SARIF 2.1.0 report generation and `curl` PoC construction. |
| `core/feedback.py` | Cross-candidate pattern propagation and adaptive chain caching. |
| `core/http_client.py` | Asynchronous HTTP engine with rate limiting, proxy support, and redirect handling. |
| `core/models.py` | Core data models, including `Candidate`, `ProbeResult`, `BaselineProfile`, and `ScanReport`. |
| `core/payload_engine.py` | SSRF payload construction and mutation chains. |
| `core/auth_manager.py` | Bearer, cookie, and API-key injection; spider-header detection. |
| `core/loader.py` | Spider JSON and flat candidate-array ingestion. |
| `core/console.py` | Terminal HUD, phase headers, status board, and colour system. |
| `core/known_exploits.py` | Known-exploit registry and escalation rules for internal services and cloud APIs. |
| `core/openapi_adapter.py` | OpenAPI/Swagger discovery and candidate generation. |
| `core/graphql_adapter.py` | GraphQL introspection-based SSRF surface extraction. |
| `core/dns_intel.py` | DNS intelligence for rebinding and pivot analysis. |
| `core/js_intel.py` | Static JavaScript analysis for `fetch`, Axios, and XHR string literals. |
| `core/recon_quality.py` | Crawler-output quality scoring and coverage-gap detection. |
| `core/wayback_probe.py` | Historical endpoint discovery through the Wayback Machine. |
| `core/subdomain_enum.py` | Subdomain enumeration for crawl-scope expansion. |
| `core/spa_detector.py` | Detection of SPA frameworks such as React, Angular, Vue, and Next.js. |
| `core/vuln_classifier.py` | Post-probe vulnerability classification and severity mapping. |
| `install.sh` | Creates the virtual environment, installs dependencies, and deploys the command. |

## Dependencies

Core dependencies listed by the project:

```text
httpx[http2]>=0.27.0
PyYAML>=6.0.1
rich>=13.7.1
```

Optional dependency for headless rendering of SPA targets:

```text
playwright>=1.44.0
```

The package installer and project metadata should remain the source of truth for the exact dependency set used by a given release.

## Legal and Responsible Use

SSRF Cyart is intended for authorized security assessments, red-team engagements, and security research. Only test assets for which you have explicit authorization, and follow the engagement's scope, request-rate limits, data-handling rules, and disclosure process. Unauthorized testing may violate applicable law, including computer-misuse and unauthorized-access laws in your jurisdiction.

The operator is responsible for validating findings, reviewing proof-of-concept output before use, protecting credentials and collected evidence, and ensuring that testing does not access or expose data outside the approved scope.
