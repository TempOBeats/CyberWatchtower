# CyberWatchtower

CyberWatchtower is a Python-based defensive security assessment tool for Linux
systems. It inventories host information, firewall tooling, and listening
services, then produces findings, a security score, and local JSON report
history.

CyberWatchtower is intended only for systems you own or are authorized to
assess.

## Current capabilities

- Host and operating-system information collection
- Firewall-tool detection and iptables policy assessment
- Listening TCP/UDP socket discovery through `ss`
- Network exposure, process, PID, and service classification
- Severity-based findings and a 0–100 security score
- Timestamped JSON reports
- Per-host scan comparison and long-term finding intelligence

## Requirements

- Python 3.11 or newer
- Linux for firewall and socket inspection
- `ss` from iproute2 for listening-service inspection
- Optional elevated privileges for complete process and firewall metadata

The project intentionally uses only the Python standard library at runtime.

## Installation

Create a virtual environment and install the project in editable mode:

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

## Usage

Run the installed command:

```bash
.venv/bin/cyberwatchtower
```

The command prints the assessment and saves a JSON report under `reports/`.
Run with elevated privileges only when you are authorized to inspect the local
system and need firewall or process details that are unavailable to your user.

## Development

Run the standard-library test suite without writing bytecode caches:

```bash
.venv/bin/python -B -m unittest discover -s tests -v
```

Compile-check the package:

```bash
.venv/bin/python -m compileall -q src/cyberwatchtower
```

See `AGENTS.md` for project architecture, development rules, and the current
roadmap.
