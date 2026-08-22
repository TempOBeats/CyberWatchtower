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

Report schema 1.5 declares `assessment_domains` explicitly and can carry closed
listener bind/reachability metadata. Assurance is derived only from applicable
domains. Reports without applicability retain the original conservative
Linux-era domain set, and schema 1.0 through 1.2 history is read exactly as
recorded without inferred reachability. The neutral `firewall_inbound_policy`
domain is independent of
the retained `iptables_input_policy` domain. New neutral firewall-policy finding
sources map explicitly to the former; legacy Linux firewall sources retain their
existing coverage mapping.

Schema 1.5 retains the scoring-version contract introduced in schema 1.4.
Current production scans use Scoring v2 and carry its closed deterministic
penalty breakdown. Advisor,
briefing, and CLI score explanations validate and present that canonical
breakdown; they do not recalculate penalties. Category saturation and confirmed-
severity guardrail adjustments remain explicit, and assessment assurance is
shown separately from risk score. Older reports
without a scoring version normalize as v1 and retain their stored score and risk
level without recomputation. Cross-version score comparisons are methodology
changes, not posture improvements or regressions.

Schema 1.5 adds `runtime_instance_count` to every canonical finding. Multiple
PID-distinct listener observations are represented by one stable security
condition only when every durable finding and scoring semantic is equal. The
bounded count is presentation metadata: it is excluded from finding and scoring
identity, never multiplies score, and contains no PID or endpoint-member list.
Schemas 1.0 through 1.4 normalize a missing count to one. Canonical JSON remains
the durable source for multiplicity; memory lifecycle continues to store one
occurrence per stable condition per report without a SQLite migration.

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
requests no elevation, and remains import-safe on other platforms. Phase 2 did
not enable full Windows scanner selection; the later assembled adapter now owns
that integration.

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
the completed v0.4 validation also exercised the native identity path on one
Windows 11 x64 host.

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
verified on Linux; the completed v0.4 validation also exercised this read-only
native interface on one Windows 11 x64 host.

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
Advisor, Intelligence Core, or provider data. The adapter integration required
no Windows-specific persistence model; current reports use schema 1.5 and
Persistent Security Memory uses schema 8.

The Windows v0.4 path is **validated on one real Windows 11 x64 host**, while
remaining experimental/pre-release rather than universally validated.
Read-only native system collection; TCP and UDP IPv4/IPv6 endpoint-table
collection; Windows Firewall profile collection; and the assembled
`WindowsPlatformAdapter` all completed successfully. Exact native UDPv4 and
UDPv6 duplicates were handled conservatively as representational multiplicity
only after strict table validation, leaving complete listening-service
inspection coverage. A PID-distinct two-instance condition was represented as
one durable finding with `runtime_instance_count = 2`, without destabilizing
finding identity or score.

The production scan completed Scoring v2, wrote a schema 1.5 report, ingested
it through memory schema 8, retained history, and produced the expected
same-version v2 trend comparison. Advisor and presentation projections also
completed successfully. The remaining `PARTIAL` assessment assurance is
intentional: effective firewall-rule applicability and active listener
reachability are not yet assessed.

This validation covers one host, not every supported Windows release,
architecture, network configuration, or policy environment. It did not test
active remote reachability or enumerate effective firewall-rule applicability.
No remediation, firewall modification, privileged exploitation, external
scanning, or offensive behavior was performed. Native CI remains deferred until
a narrowly read-only Windows job can be reviewed without running a full
security scan of a public runner.

Normal CLI output presents a compact projection of the canonical Scoring v2
breakdown: final score, assurance, effective deduction, category totals,
saturation, semantic-group counts, and guardrail state. `--score-details`
enables the full safe deterministic group projection for local audit and debug
work. The flag changes presentation only; it cannot change collection,
findings, scoring, reports, memory, or Advisor authority. Advisor actions and
recurring/new-finding displays may group equivalent listener conditions for
readability while retaining every underlying canonical finding ID and leaving
saved reports and lifecycle counts unchanged.

## Effective network exposure contract boundary

v0.5 Phase 1 defines only the dependency-free, platform-neutral rule and
listener-applicability contracts. It does not enumerate Windows Firewall,
nftables, or iptables rules and does not change the current collectors. The
closed rule model retains normalized technology, enablement, direction, action,
profiles, protocol, bounded port/address predicates, opaque application or
interface digests, canonical service identity, edge-traversal state, and closed
unsupported-feature codes. Native rule names, descriptions, executable paths,
user/domain values, native errors, raw command output, and platform objects are
not members of the contract.

The pure evaluator treats disabled and outbound rules as non-applicable. It
evaluates profile, protocol, local port/address, interface, and application or
service predicates without title or evidence parsing. Unsupported predicates,
restricted remote-address predicates, missing required attribution, and
unproven precedence remain indeterminate. A complete, universally applicable
explicit block can derive `BLOCKED_BY_OBSERVED_POLICY`; a matching allow remains
`POTENTIALLY_REACHABLE` because host policy permission is not end-to-end
reachability proof. `CONFIRMED_REACHABLE` remains unavailable without a later,
separately approved evidence source.

Schema 1.6 adds the `host_firewall_rule_collection` and
`host_firewall_rule_applicability` coverage domains and permits only a bounded
listener-level policy summary in `network_context`: a closed applicability
result, closed basis codes, optional semantic rule digests, and the two policy
coverage states. Full rule inventories are not report content. Schemas 1.0
through 1.5 remain readable and never infer rule applicability. The current
scanner does not declare the new domains applicable until a future collector is
integrated, and no memory migration is required for this additive report data.

Socket disappearance and finding resolution continue to depend on
`network_socket_inspection`, not rule or reachability coverage. Policy-state
changes are attributes of the same durable listener condition and do not alter
finding identity. Scoring v2 ignores the new policy metadata in this phase.

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
