# AI Malicious Domain Analyser - TAU / I4C

A bulk cybercrime domain analysis pipeline. Input: list of suspicious domains.
Output: Individual forensic reports + consolidated intelligence dashboard on GitHub Pages.

## One-Time Setup (15 minutes)

### Step 1: Fork this repository
Click `Fork` on GitHub. Set visibility to `Private` (recommended for MHA use).

### Step 2: Enable GitHub Pages
Settings -> Pages -> Source: `GitHub Actions`

### Step 3: Add API Keys (all free)
Settings -> Secrets and variables -> Actions -> New repository secret

Add each of these:

| Secret | Where to get it (free) |
|--------|------------------------|
| VT_API_KEY | virustotal.com -> sign up -> profile -> API key |
| URLSCAN_API_KEY | urlscan.io -> sign up -> settings -> API |
| ABUSEIPDB_API_KEY | abuseipdb.com -> sign up -> API |
| OTX_API_KEY | otx.alienvault.com -> sign up -> API |
| GOOGLE_SAFE_BROWSING_KEY | console.cloud.google.com -> APIs -> Safe Browsing -> Credentials |
| GEMINI_API_KEY | aistudio.google.com -> Get API key (free) |

Optional:

| Secret | Where to get it (free) |
|--------|------------------------|
| HACKERTARGET_API_KEY | hackertarget.com -> free tier key for optional enrichment |

### Step 4: Prepare your domain list
Edit [input/domains.txt](/Users/turnstyle/Projects/domain-analyser/input/domains.txt) - one domain or URL per line.
Lines starting with `#` are ignored (use for comments/notes).

## Running an Analysis

### Option A: Via GitHub Actions (recommended)
1. Go to Actions tab -> `Malicious Domain Analysis Pipeline`
2. Click `Run workflow`
3. Enter: Batch name (e.g. `batch-2025-001`), max domains
4. Optionally paste domains directly in the text box
5. Click `Run workflow` - pipeline runs automatically

### Option B: Locally
```bash
pip install --use-deprecated=legacy-resolver -r requirements.txt
pip install grpcio grpcio-status lxml_html_clean
python -m playwright install chromium
cp .env.example .env   # Add your API keys
python run_local.py --batch-name batch-001
```

You can also bootstrap the local environment with:

```bash
./setup.sh
```

## Viewing Results
- Dashboard: `https://{your-github-username}.github.io/{repo-name}/`
- Individual reports: Click any domain in the dashboard table
- Evidence ZIPs: Actions -> completed run -> Artifacts

## API Rate Limits & Expected Runtimes
- 50 domains:  ~45 minutes
- 100 domains: ~90 minutes
- 200 domains: ~3 hours

For 500+ domains, run in batches of 200 on consecutive days.

## Evidence Chain of Custody
Each domain evidence package includes SHA-256 hashes of all screenshots.
The evidence manifest JSON should be signed by the analyst (digital signature)
before use in legal proceedings. See [LEGAL_USE.md](/Users/turnstyle/Projects/domain-analyser/LEGAL_USE.md) for guidance.
