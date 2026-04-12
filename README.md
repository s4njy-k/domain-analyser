# AI-Powered Malicious Domain Analyser

This repository implements a six-phase malicious-domain analysis pipeline that ingests domain lists, performs passive threat-intelligence enrichment, captures evidence with Playwright, classifies the observed activity with Gemini, generates per-domain forensic reports in HTML and PDF, and publishes a consolidated intelligence dashboard to GitHub Pages.

The current implementation includes APNIC network-attribution enrichment from a repo-tracked allocation snapshot, downloadable evidence ZIP packages, and a maintained project blueprint in both Markdown and PDF form.

## Repository Outputs

- Per-domain raw JSON in `output/data/`
- Per-domain HTML reports in `output/reports/`
- Per-domain PDF draft reports in `output/reports/`
- Per-domain evidence bundles in `output/reports/*_evidence.zip`
- GitHub Pages dashboard and per-domain pages in `docs/`
- Maintained blueprint source in `PROJECT_BLUEPRINT.md`
- Maintained blueprint PDF in `PROJECT_BLUEPRINT.pdf`
- APNIC enrichment dataset snapshot in `resources/APNIC_(IP&ASN)_Resources.csv`

## GitHub Secrets

GitHub Actions reads keys only from repository or organization secrets. Do not place live keys in tracked files.

| Secret | Required | Purpose | Free source |
| --- | --- | --- | --- |
| `VT_API_KEY` | Yes | VirusTotal domain intelligence | [virustotal.com](https://www.virustotal.com/) |
| `URLSCAN_API_KEY` | Yes | URLScan search and on-demand scan | [urlscan.io](https://urlscan.io/) |
| `ABUSEIPDB_API_KEY` | Yes | AbuseIPDB IP reputation | [abuseipdb.com](https://www.abuseipdb.com/) |
| `OTX_API_KEY` | Yes | AlienVault OTX pulses | [otx.alienvault.com](https://otx.alienvault.com/) |
| `GOOGLE_SAFE_BROWSING_KEY` | Yes | Google Safe Browsing lookup | [console.cloud.google.com](https://console.cloud.google.com/) |
| `GEMINI_API_KEY` | Yes | Gemini structured legal analysis | [aistudio.google.com](https://aistudio.google.com/) |
| `HACKERTARGET_API_KEY` | No | Reserved optional enrichment slot | [hackertarget.com](https://hackertarget.com/) |

## Zero-to-Live Setup

1. Create or fork a GitHub repository and push this project to the default branch.
2. In repository `Settings -> Pages`, set `Source` to `GitHub Actions`.
3. In repository `Settings -> Actions -> General`, allow Actions to create and approve pull requests if your org policy requires it, and keep workflow permissions sufficient for Pages deployment and artifact upload.
4. Add the secrets listed above in `Settings -> Secrets and variables -> Actions`.
5. Review [input/domains.txt](/Users/turnstyle/Projects/domain-analyser/input/domains.txt) and replace it with the domains for the next batch, or plan to paste them into the workflow dispatch form.
6. Run the workflow from `Actions -> Malicious Domain Analysis Pipeline -> Run workflow`.
7. Supply:
   - `domains_input` if you want to paste the batch inline
   - `batch_name` for the case identifier
   - `max_domains` to cap the run if required
8. Wait for the single GitHub Actions job to complete. It installs Chromium, executes the full pipeline, uploads evidence artifacts, and deploys `docs/` to Pages in the same run.
9. Open the deployed GitHub Pages URL to review the dashboard and individual per-domain report pages.
10. Download the evidence artifact bundle from the completed run when you need HTML, PDF, JSON, screenshots, and ZIP packages offline.

## Local Ubuntu or GCP VM Setup

The intended local target is Ubuntu, including a GCP VM such as `/home/snjy_whb_gmail_com/Projects/domain-analyser`.

```bash
cd ~/Projects/domain-analyser
./setup.sh
cp .env.example .env
# fill .env with your local API keys if you want to run outside GitHub Actions
python3 run_local.py --batch-name batch-001
```

`setup.sh` installs:

- Python dependencies from `requirements.txt`
- Chromium for Playwright
- WeasyPrint runtime libraries on Debian/Ubuntu systems

If you are not on Debian/Ubuntu, install the equivalent Cairo, Pango, Harfbuzz, GDK-Pixbuf, and MIME libraries for WeasyPrint yourself. The code uses WeasyPrint first and falls back to Playwright PDF rendering if WeasyPrint is unavailable.

## Workflow Behavior

The GitHub Actions workflow:

- triggers on `workflow_dispatch`
- accepts `domains_input`, `batch_name`, and `max_domains`
- runs on `ubuntu-22.04`
- installs Playwright Chromium and WeasyPrint system libraries
- uploads `output/screenshots/`, `output/reports/`, and `output/data/` as 90-day artifacts
- deploys `docs/` to GitHub Pages
- commits the generated `docs/` snapshot back to `main` so the repository tree reflects the latest published batch

Required permissions in `.github/workflows/analyse.yml`:

| Permission | Value |
| --- | --- |
| `contents` | `write` |
| `pages` | `write` |
| `id-token` | `write` |

## What Each Domain Produces

For every processed domain, the pipeline generates:

- passive threat-intelligence results from the configured free APIs
- DNS and RDAP registration context
- APNIC allocation enrichment for resolved IPv4 and IPv6 addresses
- holder-linked ASN allocation context derived from matched APNIC holder names
- desktop and mobile screenshot evidence
- a structured AI legal classification with the full India-law reference block
- a browser-view HTML report
- a formal downloadable PDF draft report
- a manifest with SHA-256 hashes
- a downloadable evidence ZIP containing the report set and screenshots

## APNIC Enrichment

The APNIC snapshot at `resources/APNIC_(IP&ASN)_Resources.csv` is versioned with the repository and used by both local runs and GitHub Actions. During passive-intel processing the pipeline:

- parses the CSV once per process
- builds cached IPv4, IPv6, and ASN indexes
- applies longest-prefix-match against resolved addresses
- supports CIDR rows and range-style IPv4 rows in the APNIC export
- derives holder-linked ASN allocations by normalized `holder_name` matching
- defaults to empty enrichment objects when no match exists

The dashboard surfaces APNIC holder and region fields, and the per-domain report includes a dedicated network-attribution section.

## Dashboard Contents

The GitHub Pages dashboard includes:

- summary cards
- severity doughnut chart
- threat-category bar chart
- top hosting countries chart
- top impersonated brands table
- top allocation holders table
- infrastructure clusters table
- sortable, filterable, searchable domain table with report, PDF, JSON, and ZIP actions

## Formal PDF Reports

Each per-domain page includes:

- `Download PDF Report`
- `Download Evidence ZIP`
- `View Raw JSON`

The PDF is styled as an NCTAU/I4C draft and carries the recurring disclaimer:

`Analyst-generated draft for internal cybercrime review; not an official government issuance or order.`

The downloadable PDF is included in:

- `output/reports/`
- the per-domain GitHub Pages directory under `docs/domains/<domain>/report.pdf`
- the corresponding evidence ZIP bundle

## Runtime Expectations

These are practical estimates for the free-tier stack with rate limiting and screenshot capture enabled:

| Batch size | Estimated runtime |
| --- | --- |
| 25 domains | 20 to 30 minutes |
| 50 domains | 40 to 60 minutes |
| 100 domains | 80 to 120 minutes |
| 200 domains | 2.5 to 4 hours |

VirusTotal is capped at 4 requests per minute. Large cases should be split into operational batches.

## Safe Sample Guidance

For smoke tests or demos, use benign sample domains such as:

- `example.com`
- `iana.org`
- `wikipedia.org`
- `github.com`
- `python.org`

Keep operational or suspicious target lists in `input/domains.txt` only when you are ready to run the case.

## Blueprint Maintenance

The maintained source of truth now lives in:

- [PROJECT_BLUEPRINT.md](/Users/turnstyle/Projects/domain-analyser/PROJECT_BLUEPRINT.md)
- `PROJECT_BLUEPRINT.pdf`

To regenerate the PDF locally:

```bash
python3 scripts/render_blueprint_pdf.py
```

## Legal and Evidence Handling

Review [LEGAL_USE.md](/Users/turnstyle/Projects/domain-analyser/LEGAL_USE.md) before operational use. The generated legal analysis is analyst aid only and must be reviewed by a qualified legal officer before it is used for blocking requests, official notices, or court-facing material.
