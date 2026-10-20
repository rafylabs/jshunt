# jshunt

Hunt for leaked credentials, API keys, and sensitive tokens in JavaScript files.

Pipeline: collect JS URLs → bulk download → scan with gitleaks + curated gf patterns → consolidate report.

## Why

Client-side JavaScript is frequently a source of unintentional credential exposure. API keys, cloud storage credentials, Firebase configurations, and internal endpoints are routinely bundled into production JS assets. `jshunt` automates the collection, downloading, and pattern inspection across target applications.

## Features

- **JS URL collection** — via `subjs` from an entire target domain, direct file URL, or list of endpoints
- **Bulk download** — parallel retrieval of discovered scripts into a local directory
- **Credential scanning** — runs `gitleaks` against downloaded source files alongside curated `gf` patterns
- **Pattern coverage** — AWS keys, S3 buckets, Firebase tokens, HTTP Basic Auth strings, and internal JSON secrets
- **Clean output** — generates structured Markdown reports with findings and context

## Requirements

- Python 3.10+
- [`subjs`](https://github.com/lc/subjs) — JS URL extractor
- [`subfinder`](https://github.com/projectdiscovery/subfinder) — subdomain discovery
- [`httpx`](https://github.com/projectdiscovery/httpx) — fast HTTP probe
- [`gitleaks`](https://github.com/gitleaks/gitleaks) — secret scanner
- [`gf`](https://github.com/tomnomnom/gf) — pattern matcher with security patterns

## Usage

```bash
# Hunt across an entire domain
python jshunt.py -d target.com

# Scan a single JavaScript file
python jshunt.py -u https://target.com/assets/app.bundle.js

# Scan from a list of URLs
python jshunt.py -l urls.txt

# Specify custom output directory
python jshunt.py -d target.com -o results/
```

## Output Structure

```
results/
├── js-urls.txt        # Discovered JavaScript URLs
├── downloaded/        # Locally saved JS files
├── gitleaks.json      # Structured gitleaks findings
└── report.md          # Consolidated audit report
```

## License

MIT © [Rafylabs](https://rafylabs.com)
