# CyberWatchtower Development Instructions

## Project Purpose

CyberWatchtower is a Python-based defensive cybersecurity assessment platform.

The long-term goal is to evolve it into an intelligent security assistant capable of:

- host security assessment
- firewall analysis
- listening-service detection
- process attribution
- service intelligence
- security scoring
- persistent scan history
- trend analysis
- recurring finding detection
- remediation recommendations
- future threat intelligence
- future honeypot capabilities
- future AI-assisted analysis

This project is defensive and intended for authorized systems.

## Current Architecture

Source package:

src/cyberwatchtower/

Important modules currently include:

- cli.py
  Main command-line interface and report display.

- scanner.py
  Coordinates the security assessment pipeline.

- system.py
  Collects host/system information.

- firewall.py
  Detects firewall technologies and assesses iptables configuration.

- network.py
  Inspects listening network services, parses socket data, determines exposure, identifies processes/PIDs, and performs network-risk classification.

- service_intelligence.py
  Contains known-service and alternate-port intelligence.

- scoring.py
  Calculates the overall 0-100 security score and severity counts.

- reporting.py
  Saves timestamped JSON security reports under reports/.

- history.py
  Loads previous reports, compares scans, and identifies new/resolved findings.

- intelligence.py
  Performs long-term historical analysis including recurring findings, occurrence counts, score averages, best/worst scores, and long-term trends.

- models.py
  Contains Finding and Severity models.

## Features Already Working

Do not unnecessarily rewrite these working features:

1. System information collection.
2. Firewall technology detection.
3. iptables rule inspection when privileged.
4. Listening TCP/UDP service discovery.
5. Network exposure classification.
6. Process and PID attribution.
7. Service intelligence for known/common ports.
8. Alternate HTTP/HTTPS service recognition.
9. Unknown-service detection.
10. Security findings with evidence and recommendations.
11. Security score from 0-100.
12. Risk-level classification.
13. Timestamped JSON report generation.
14. Historical report loading.
15. Previous-vs-current score comparison.
16. IMPROVED / DECLINED / UNCHANGED trend detection.
17. New finding detection.
18. Resolved finding detection.
19. Persistent historical intelligence.
20. Recurring finding detection and occurrence counting.

## Important Observed Behavior

CyberWatchtower detected Python-based services where `ss` reports the process as python3.

Example:

- process: python3
- command: /usr/bin/wsdd
- UDP service exposed on all interfaces

This revealed a future improvement opportunity:

Process Intelligence should inspect command-line information for interpreter-based processes such as:

- python
- python3
- bash
- sh
- node
- java
- ruby
- perl

Instead of only reporting the interpreter, CyberWatchtower should attempt to identify the actual executed application or script.

Example desired output:

Service: WSDD
Process: python3
Application: /usr/bin/wsdd

## Development Rules

1. Inspect existing code before modifying it.
2. Preserve working functionality.
3. Prefer incremental changes over rewrites.
4. Compile/test after every meaningful change.
5. Keep modules focused and maintainable.
6. Use clear type hints where appropriate.
7. Avoid adding unnecessary dependencies.
8. Do not silently remove existing features.
9. Before major refactors, explain the reason and proposed design.
10. Commit logical milestones separately.

## Testing

At minimum, compile modified Python files:

python -m py_compile <file>

For full scanner testing:

sudo .venv/bin/cyberwatchtower

Useful network inspection:

sudo ss -lntup

Git status should be clean before beginning major work.

## Git Workflow

Main branch: main

Before modifying files:

git status

After a verified milestone:

git add <files>
git commit -m "<clear commit message>"
git push

Do not force-push or rewrite Git history unless explicitly approved.

## Safety

CyberWatchtower is a defensive security project.

Do not implement destructive, unauthorized, persistence, credential-theft, malware, ransomware, or stealth functionality.

Network scanning or active testing features should be designed for systems the operator owns or is authorized to test.

## Immediate Development Priority

The next recommended feature is Process Intelligence.

Goal:

When a socket is owned by an interpreter process such as python3, inspect safe local metadata such as /proc/<pid>/cmdline and identify the actual application or script.

Example:

python3 /usr/bin/wsdd

should be represented as:

Process: python3
Application: /usr/bin/wsdd
Service/Application: WSDD

This should improve service classification and reduce ambiguous "Unknown service" findings.

## First Codex Session

Before changing code:

1. Read this AGENTS.md.
2. Inspect the entire repository.
3. Review Git history.
4. Inspect pyproject.toml and README.md.
5. Run appropriate non-destructive checks.
6. Summarize the current architecture.
7. Identify technical debt or bugs.
8. Propose the next development plan.
9. Do not modify files until the user approves the plan.
