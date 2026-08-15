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
