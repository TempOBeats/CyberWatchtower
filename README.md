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
- Deterministic security posture advice, remediation priorities, and next steps

The AI Advisor v0.1 advisory layer remains grounded in deterministic scan
findings. Its default mode requires no AI provider or network API. Optional
future providers are limited to selecting and ordering known finding and action
identifiers; final explanations and recommendations remain deterministic.

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

Generate a grounded briefing or ask a supported question using already-saved
reports without starting a new scan:

```bash
.venv/bin/cyberwatchtower briefing
.venv/bin/cyberwatchtower ask "What changed?"
.venv/bin/cyberwatchtower ask "What should I fix first?"
.venv/bin/cyberwatchtower ask "Why is this dangerous?" --finding-id FINDING_ID
```

Intelligence Core v0.1 uses the deterministic scanner and Advisor as its source
of truth. Its automatic allowlist can only load reports, compare saved scans,
and explain an existing finding. It does not run shell commands, collect fresh
host data, remediate findings, or contact a model provider.

## Persistent Security Memory

Persistent Security Memory v0.2 is an optional local SQLite index over canonical
CyberWatchtower JSON reports. Enable it explicitly with `--memory-db PATH` or the
`CYBERWATCHTOWER_MEMORY_DB` environment variable. The scanner, JSON reporting,
Advisor, and briefing continue to work when memory is disabled or unavailable.

Memory stores validated report indexes, finding occurrences and lifecycle
derivations, authoritative stored scores, typed user decisions and expiring
presentation exceptions, versioned baselines, structured investigation/audit
records, and short-lived ID-only conversation references. It deliberately does
not store credentials, tokens, environment variables, raw command lines,
stdout/stderr, arbitrary logs, raw conversations, or unsupported evidence.
Canonical JSON reports remain the source records and are never deleted by the
v0.2 retention system.

Retention is plan-first and bounded. A dry-run identifies exact eligible record
IDs without changing the database. Deletion requires a separate, unexpired user
authorization bound to the exact plan and digest, executes transactionally, and
records a minimal append-only audit. Active exceptions, current decisions,
approved baselines, deterministic occurrences, scores, and lifecycle history
are not retention targets. Retention never means that a finding was remediated.

Safe read-only diagnostics are available for an explicitly configured database:

```bash
.venv/bin/cyberwatchtower memory status --system-id SYSTEM_ID --memory-db PATH
.venv/bin/cyberwatchtower memory check --memory-db PATH
```

Diagnostic output excludes database/report paths, raw evidence, raw capability
parameters/results, machine identity source material, and sensitive text. No
automatic repair is performed. If corruption is suspected, preserve the
existing database, make a backup copy before manual intervention, and inspect
read-only diagnostics. A new memory database may later be rebuilt from canonical
JSON reports only through an explicit user-directed workflow; v0.2 does not do
this automatically. Memory never performs remediation or modifies deterministic
security facts.

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
