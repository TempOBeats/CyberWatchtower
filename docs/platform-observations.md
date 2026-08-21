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

Report schema 1.4 declares `assessment_domains` explicitly and can carry closed
listener bind/reachability metadata. Assurance is derived only from applicable
domains. Reports without applicability retain the original conservative
Linux-era domain set, and schema 1.0 through 1.2 history is read exactly as
recorded without inferred reachability. The neutral `firewall_inbound_policy`
domain is independent of
the retained `iptables_input_policy` domain. New neutral firewall-policy finding
sources map explicitly to the former; legacy Linux firewall sources retain their
existing coverage mapping.

Schema 1.4 also records an explicit scoring version. Current production scans
use Scoring v2 and carry its closed deterministic penalty breakdown. Advisor,
briefing, and CLI score explanations validate and present that canonical
breakdown; they do not recalculate penalties. Category saturation and confirmed-
severity guardrail adjustments remain explicit, and assessment assurance is
shown separately from risk score. Older reports
without a scoring version normalize as v1 and retain their stored score and risk
level without recomputation. Cross-version score comparisons are methodology
changes, not posture improvements or regressions.

Socket bind exposure and remote reachability are separate contracts. A wildcard
or interface bind is an observed fact, while reachability is a deterministic
derivation. Without complete effective-rule applicability, a non-loopback bind
is only potentially reachable; a restrictive default firewall policy is
context, not proof that the listener is blocked. `network_socket_inspection`
and `network_reachability` retain independent coverage states. Presentation may
group related IPv4/IPv6 listeners, but canonical reports and memory retain every
atomic finding and stable finding ID.

Linux continues to use its existing iptables observation and deterministic
firewall interpretation path. INPUT `ACCEPT` remains a confirmed permissive
policy finding, while `DROP` is restrictive policy context rather than proof
that a particular listener is blocked. The adapter's neutral posture translation
does not create listener conclusions or alter collector authority.

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

### Windows listeners and attribution

The v0.4 Phase 3 boundary reads the IPv4 and IPv6 owner-PID listener tables for
TCP and the corresponding bound-endpoint tables for UDP through fixed-purpose
IP Helper API calls. All four tables must validate for `COMPLETE` network
coverage. A failed family or protocol may preserve already validated endpoint
observations, but coverage remains `INCOMPLETE` or `UNKNOWN`; process or service
enrichment failure does not erase an endpoint or falsely reduce endpoint-table
coverage.

Addresses use canonical IP text. IPv6 link-local scope IDs use the stable
`address%numeric_scope_id` representation when the native scope is nonzero.
TCP records represent listeners; UDP records represent bound endpoints and do
not imply an active session. PID 0 and PID 4 records remain endpoint facts even
when process lookup is unavailable.

Process enrichment requests only `PROCESS_QUERY_LIMITED_INFORMATION` and keeps
only the executable basename. Full image paths are transient internal values;
command lines, environments, tokens, memory, and process privileges are never
collected. Active Windows services are enumerated with minimal Service Control
Manager rights. Exactly one service for a PID may add the stable application ID
`windows-service:<casefolded-service-name>`; multiple services are ambiguous and
none is selected. Service registration does not make an application trusted or
known.

Endpoint ownership is authoritative only for the endpoint-table snapshot.
Later process/service lookup is best-effort enrichment and does not prove
continuous identity across process exit, PID reuse, or service races. Phase 3
does not enable full Windows scanner selection and includes no firewall
collection, command execution, elevation, or durable native diagnostics. Native
runtime tests remain guarded for Windows; portable contract/fixture tests run on
other hosts.

### Windows Firewall profile posture

The v0.4 Phase 4 boundary uses a dependency-free, fixed-purpose `ctypes`
binding to the read-only `INetFwPolicy2` COM interface. COM initialization and
API loading occur only during an explicit Windows call. The boundary has no
generic dispatch/query surface, invokes no command interpreter, and exposes no
policy setters or firewall-rule operations. A pywin32 dependency was therefore
not required for this phase.

The collector retains `DOMAIN`, `PRIVATE`, and `PUBLIC` separately and supports
multiple simultaneously active profiles. For each profile it normalizes active
state, firewall enablement, default inbound `ALLOW`, `BLOCK`, or `UNKNOWN`, and
block-all-inbound `true`, `false`, or unknown. It does not collapse these facts
into an effective action, finding, severity, score, or recommendation. A
restrictive profile therefore cannot hide a concurrently active permissive
profile at the observation boundary.

Firewall-technology coverage is independent from inbound-policy coverage. A
validated `INetFwPolicy2` interface establishes the supported Windows Firewall
technology even when a profile property is partial. Inbound-policy coverage is
`COMPLETE` only when the active profile set is known and every active profile
has readable enablement and default inbound action. Missing, denied, partial,
or invalid required facts remain `INCOMPLETE`; an unavailable or unsupported
interface with no posture is `UNKNOWN`. Block-all-inbound is retained when
available but is not substituted for the default inbound action.

`INetFwPolicy2` exposes the current policy view, which can reflect settings
affected by Group Policy. Phase 4 does not enumerate policy layers or claim
which administrative source supplied a value. It reports only the bounded
current profile facts returned by that interface. Portable fixtures are
verified on Linux; the guarded read-only native test remains skipped there, so
actual Windows runtime behavior is not claimed as locally validated.

### Windows adapter and deterministic interpretation

The v0.4 Phase 5 `WindowsPlatformAdapter` assembles the reviewed system,
endpoint/attribution, and firewall collectors. Deterministic platform selection
now chooses that adapter on Windows, continues to choose `LinuxPlatformAdapter`
on Linux, and fails closed on unsupported systems. The adapter produces only
normalized observations; scanner-owned interpretation creates findings and
scores.

Windows reports declare `firewall_technology`, `firewall_inbound_policy`, and
`network_socket_inspection` as their applicable assessment domains. They never
claim the Linux-only `iptables_input_policy` domain. Inbound policy is evaluated
per active profile: disabled or default-allow profiles are confirmed medium
risks, default-block and block-all states are informational, and unknown facts
remain coverage gaps. Concurrent profiles are never collapsed, so a restrictive
profile cannot hide a permissive one. Listener exposure continues through the
shared deterministic network interpreter.

Raw identity, executable paths, native errors, COM objects, buffers, and SCM
diagnostics do not cross the native boundary into reports, history, memory,
Advisor, Intelligence Core, or provider data. Schema 1.2 and the existing memory
schema are sufficient; no migration is required.

The Windows path is **implemented but native validation is pending**. Portable
fixture integration is covered on Linux, while native system, endpoint,
firewall, and adapter tests are guarded and skipped there. Windows support is
therefore experimental/pre-release rather than production-ready. Native CI is
deferred until a narrowly read-only Windows job can be reviewed without running
a full security scan of a public runner.

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
