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

## Windows native API boundary

The v0.4 Phase 1 `platform.windows` package is a dependency-free, pure-Python
contract layer for future Windows collection. Its method-specific protocol
returns immutable raw system, endpoint, process, service, firewall-profile, and
local-identity DTOs. These internal values are not platform-neutral
observations, findings, report data, memory records, or model input. Future
collectors must validate and normalize them before they can cross the platform
observation boundary.

The package currently contains no native API loading or host collection. A
typed fake and bounded two-call table helper allow buffer growth, unstable
results, access failures, process races, ordering, and privacy behavior to be
tested on non-Windows hosts. Raw local identity has a redacted dedicated type
and may be consumed only by the future trusted system-ID derivation boundary.

Future native implementations must remain behind this facade. They may not add
a generic command runner, caller-supplied script or query text, raw native error
messages, or arbitrary buffer data. Platform-specific API loading must occur
only during an explicit Windows-only implementation path, never at package
import time.

### Windows system information and identity

The v0.4 Phase 2 system collector normalizes a bounded Windows hostname,
kernel version/build, native architecture, and optional current-user display
label into `SystemObservation`. The read-only native facade loads system DLLs
and the registry only inside explicit calls on Windows. It executes no command,
requests no elevation, and remains import-safe on other platforms. Full Windows
scanner selection is still disabled.

Stable identity is read from the local `MachineGuid` registry value under
`HKLM\SOFTWARE\Microsoft\Cryptography`. The raw value exists only in the
dedicated redacted internal identity type and is immediately passed to the
existing CyberWatchtower system-ID derivation. Only the resulting opaque
`cwt-…` identifier may enter a platform-neutral observation. Failure never
falls back to hostname, username, hardware fingerprinting, or a generated seed;
display facts may remain available with `INCOMPLETE` or `UNKNOWN` coverage.

This identity represents a Windows installation rather than hardware. A
properly generalized clone should receive a distinct identity, while an
improper clone or VM snapshot may preserve it and collide. Reinstallation may
produce a new identity; ordinary hardware changes should not. Phase 2 does not
attempt clone detection. Portable fake-driven coverage is verified on Linux;
real native calls require separate execution on a Windows host and are not
claimed as locally validated by this milestone.

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
