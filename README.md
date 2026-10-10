# Firewall Sentinel

**Firewall Sentinel** is a read-only Streamlit application for reviewing firewall-rule CSV files. It helps security teams and students identify risky, invalid, duplicate, and order-dependent policy rules without connecting to or changing a real firewall.

> Configuration findings show policy risks only. They do not prove that a service is reachable, vulnerable, or exploitable.

## Features

- Upload a firewall-rule CSV or load the included demo rules.
- Validate required fields, IP addresses/CIDRs, ports, protocols, and actions.
- Detect unrestricted `Allow` rules that expose any source, destination, port, and protocol.
- Detect unrestricted-source `Allow` access to these TCP services: SSH (22), SMB (445), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), WinRM HTTP (5985), and WinRM HTTPS (5986).
- Identify duplicate rules.
- Identify ordered `Allow`/`Deny` shadowing and potential conflicts.
- Present explainable findings with evidence, potential impact, investigation priority, and a recommendation.
- Show a security dashboard with severity distribution and a heuristic security score.
- Simulate one traffic flow using a simplified first-match policy model.
- Export findings, including explainability details, as a CSV security report.

## Screens and workflow

| Section | What it does |
| --- | --- |
| **Dashboard** | Shows rules analyzed, critical findings, high-risk findings, security score, and a severity chart. |
| **Firewall Analysis** | Uploads a CSV or loads demo rules, runs analysis, filters findings, inspects evidence, and downloads an audit report. |
| **Traffic Simulator** | Tests a source IP, destination IP, destination port, and protocol against the currently loaded rules. |
| **Security Reports** | Previews the latest results and downloads the CSV security report. |

## Requirements

- Python 3.13 (recommended)
- Streamlit
- Pandas

`ipaddress` is part of Python's standard library and needs no separate installation.

## Setup and run

From the project folder:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install streamlit pandas
streamlit run app.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

If port 8501 is already in use, start on another port:

```bash
streamlit run app.py --server.port 8505
```

## CSV format

The CSV must contain these exact column names:

```text
rule_id,source,destination,port,protocol,action
```

Example:

```csv
rule_id,source,destination,port,protocol,action
R001,Any,Any,Any,Any,Allow
R002,192.168.1.10,10.0.0.5,443,TCP,Allow
R003,192.168.1.0/24,10.0.0.8,80,TCP,Deny
```

Supported rule values:

- **Source and destination:** an IPv4 address, IPv4 CIDR, or `Any`.
- **Port:** an integer from `1` to `65535`, or `Any`.
- **Protocol:** `TCP`, `UDP`, `ICMP`, or `Any`.
- **Action:** `Allow` or `Deny`.

## How analysis works

### Ordered rule checks

Firewall Sentinel uses the CSV row order as rule priority for its ordered conflict checks. It assumes a **first-match firewall model**:

1. An earlier rule that completely covers a later rule with the opposite action produces a **Shadowed Allow/Deny Rule** finding.
2. Rules with different actions that overlap only partially produce a **Potential Allow/Deny Conflict** finding.

Actual firewall platforms may use different rule-processing semantics, so confirm results against the target firewall's documentation before changing a policy.

### Traffic simulator

The simulator is also a simplified, read-only first-match model. It evaluates the loaded rules in their original CSV order and reports:

- `ALLOW` or `DENY`
- the first matching rule ID
- why the rule matched
- how many earlier rules were checked
- later opposite-action rules that may be shadowed for that traffic

If no valid rule matches, it reports `DENY` under an explicit **implicit-deny assumption**. Invalid rule rows are skipped safely and reported to the user.

### Security score

The score is a heuristic that starts at 100 and applies one penalty per finding:

| Severity | Penalty |
| --- | ---: |
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 2 |

The final score cannot be lower than 0. It is a prioritization aid, not a compliance score or proof of security.

## Run the automated tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

To check Python syntax first:

```bash
.venv/bin/python -m py_compile app.py analyzer.py tests/test_analyzer.py
```

## Project structure

```text
Firewall-Sentinel/
├── app.py                 # Streamlit interface and report download controls
├── analyzer.py            # Validation, findings, scoring, and simulation logic
├── tests/
│   └── test_analyzer.py   # Automated analyzer and simulator tests
└── .streamlit/
    └── config.toml        # Dark cybersecurity-oriented theme
```

## Safety and limitations

- Firewall Sentinel never changes firewall configuration and never opens network connections to tested services.
- It evaluates the policy values supplied in the CSV only.
- It currently supports IPv4 addresses and CIDRs; invalid rule values are shown as validation findings rather than used for matching or conflict checks.
- Review recommendations are a starting point. Validate intended traffic and platform-specific firewall behavior before applying changes in any environment.
