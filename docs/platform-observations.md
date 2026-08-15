# Platform observation architecture

CyberWatchtower obtains host facts through the narrow `PlatformAdapter` protocol.
Adapters produce immutable, typed observations and explicit domain coverage; they
do not create findings, scores, recommendations, or model input.

The v0.3 Linux adapter wraps the existing fixed-purpose Linux collectors. Socket
output remains complete only when the command succeeded, its expected header was
present, and every non-empty row parsed. Raw stderr and arbitrary tool output are
not included in observation failures. Process enrichment exposes only the
existing safe application attribution and never raw command lines.

The deterministic scanner converts normalized observations into the same legacy
service/firewall structures at its interpretation boundary. Existing risk rules,
finding identity, scoring, report history, Advisor, Intelligence Core, and
Persistent Security Memory remain consumers of findings and reports rather than
platform-specific observations.

## Firewall posture and applicable coverage

The platform-neutral inbound-firewall contract describes technology, the
`DEFAULT`, `DOMAIN`, `PRIVATE`, or `PUBLIC` profile, profile activity, firewall
enablement, default inbound `ALLOW`, `BLOCK`, or `UNKNOWN` action, and optional
block-all-inbound state. These immutable values are observations only. Adapters
must not assign findings, severity, scores, recommendations, approvals, or model
evidence.

Report schema 1.2 declares `assessment_domains` explicitly. Assurance is derived
only from those applicable domains. Reports without this field retain the
original conservative Linux-era domain set, so schema 1.0 and 1.1 history is not
reinterpreted. The neutral `firewall_inbound_policy` domain is independent of
the retained `iptables_input_policy` domain. New neutral firewall-policy finding
sources map explicitly to the former; legacy Linux firewall sources retain their
existing coverage mapping.

Linux continues to use its existing iptables observation and deterministic
interpretation path for exact behavior parity. The Linux adapter also exposes a
neutral posture translation for the future adapter boundary, but Phase 0 does
not use that translation to change Linux findings or evidence.

Listener attribution states (`ATTRIBUTED`, `UNAVAILABLE`, `AMBIGUOUS`, and
`NOT_APPLICABLE`) are deferred until the Windows process/service attribution
phase. They are not required to represent firewall posture or applicable
coverage, and adding them here would expand this contract change unnecessarily.

Future adapters must:

- implement the same typed protocol without falling back to Linux behavior;
- report `COMPLETE`, `INCOMPLETE`, or `UNKNOWN` per observation domain;
- validate output structure before claiming `COMPLETE`;
- use bounded trusted failure codes and messages;
- expose no generic command runner, shell, raw argv, stderr, or arbitrary output;
- preserve deterministic ordering for identical inputs;
- pass the reusable platform contract and parity tests before being enabled.

Adding an adapter must not change finding identity, classification, score,
assessment assurance, or the authority of canonical reports and memory.
