# Domain Threat Intelligence Scanner

**Original defensive Python project by [Ainny1](https://github.com/Ainny1)**

A low-impact command-line security tool that checks public domain DNS records, HTTPS/TLS certificate health, and public RDAP registration events. Designed for authorized cybersecurity assessments and portfolio demonstrations.

## Features

- Validate domain names and internationalized DNS names
- Resolve public IPv4 and IPv6 addresses
- Inspect standard HTTPS TLS verification, negotiated TLS protocol, and certificate expiration
- Retrieve public RDAP registration dates and status (no registrant identities retained)
- Report informational DNS, TLS, and RDAP findings
- Export structured JSON reports
- Python standard library only; automated tests and GitHub Actions CI

**Limitations:** DNS and TLS results cannot determine if a domain is malicious. The tool performs no intrusion, port scanning, brute forcing, credential harvesting, or subdomain enumeration.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/Ainny1/domain-threat-intelligence-scanner.-.git
cd domain-threat-intelligence-scanner.-
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Usage

```bash
domain-intel example.com
domain-intel example.com --timeout 5 --output reports/domain-report.json
```

Without installation (from repository root):

```bash
PYTHONPATH=src python3 -m domain_intel example.com --output reports/example.json
```

## Example JSON (illustrative only)

```json
{
  "domain": "example.com",
  "dns": {"addresses": ["93.184.215.14"], "error": null},
  "tls": {"valid_for_hostname": true, "days_remaining": 75, "error": null},
  "rdap": {"events": {}, "status": [], "error": null},
  "findings": []
}
```

Numbers above are examples, not live scan results.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Repository layout

```text
src/domain_intel/core.py     # DNS, TLS, RDAP, findings
src/domain_intel/cli.py      # CLI and JSON output
tests/test_core.py           # Unit tests using mocks
.github/workflows/tests.yml  # GitHub Actions tests
pyproject.toml               # Package and CLI entry point
```

## Scope and privacy

Run only against domains you own or have authorization to assess. The tool uses regular DNS lookups, a standard HTTPS connection to port 443, and a public RDAP query. It stores no registrant contact information. Public endpoint availability and rate limits may affect results. Findings are informational, not proof of malicious activity.

## Roadmap

- [x] DNS, TLS, RDAP analysis
- [x] Structured JSON output
- [x] Automated tests
- [ ] Interactive mobile-friendly dashboard
- [ ] Printable assessment reports

MIT License.
