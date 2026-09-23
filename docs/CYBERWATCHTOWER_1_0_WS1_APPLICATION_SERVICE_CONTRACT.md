# CyberWatchtower 1.0 WS1 Application-Service Implementation Contract

Status: FROZEN CONTRACT CANDIDATE — OWNER APPROVED FOR DOCUMENTATION FREEZE

Parent product contract: CyberWatchtower 1.0 Master Specification

Parent repository baseline: `b95f87106a6132000a0be3b2f074f674e3243f8b`

Scope: WS1 Application-Service and Contracts

Implementation authorization: NONE

This document defines the implementation contract for the CyberWatchtower
1.0 application-service boundary. It does not authorize implementation.
WS1-C requires separate owner authorization.

## 1. Repository Integrity

The read-only baseline gate passed.

| Gate | Verified value |
|---|---|
| HEAD | `b95f87106a6132000a0be3b2f074f674e3243f8b` |
| origin/main | `b95f87106a6132000a0be3b2f074f674e3243f8b` |
| Ahead/behind | `0/0` |
| Worktree | Clean |
| Staged files | `0` |
| Master Specification SHA-256 | `530aef833f1eabbe0d70858bb74726d6e28550c4bdcfdf22ea4f544917eb80da` |

The repository confirms:

- `scanner.run_scan()` remains the current assessment authority.
- It returns an explicit `system` mapping whose supported-platform
  implementations provide `operating_system`.
- Linux supplies that field through `collect_system_information()`.
- Windows explicitly supplies `"Windows"` through its normalized
  `SystemObservation`.
- Findings do not contain an authoritative finding-level coverage-domain
  field in `Finding`.
- Existing evidence sanitization uses bounded labels plus defense-in-depth
  sensitive-marker rejection in `memory/sanitization.py`.

No executable tests were needed or run. Evidence is from static source
inspection and repository-integrity commands.

## 2. Contract Goals and Non-Goals

### Goals

WS1 establishes one supported, in-process application boundary that:

- delegates assessment to the frozen deterministic scanner;
- projects mutable backend results into deeply immutable, purpose-specific
  DTOs;
- preserves every authoritative security state without strengthening it;
- separates application metadata from security-domain facts;
- keeps platform adapters, collectors, native helpers, persistence, and
  privileged mechanisms internal;
- is suitable for later consumption by the GUI, assistant, voice, jobs,
  monitoring, and approved automation;
- supports later privacy and authorization layers without allowing those
  consumers to bypass this boundary.

### Permanent invariants

The implementation must preserve:

1. Deterministic observations and deterministic reasoning are authoritative.
2. AI cannot create authoritative security facts.
3. AI cannot promote `POSSIBLE` or `UNKNOWN` evidence.
4. Missing, inaccessible, unsupported, partial, incomplete, and unknown states
   remain explicit.
5. An unavailable collector cannot yield `COMPLETE`.
6. Firewall `ALLOW` is not proof of remote reachability.
7. Firewall evidence cannot create `CONFIRMED_REACHABLE`.
8. Threat Risk, Evidence Confidence, Visibility, Coverage, Assurance, and
   Reachability remain distinct.
9. Privileged work is fixed-purpose, bounded, authorized, and auditable.
10. GUI, assistant, and ordinary application clients remain unprivileged.
11. There is no generic privileged execution.
12. There is no arbitrary command or shell execution.
13. Unsupported platforms fail closed.
14. External AI is not required for deterministic security operation.
15. Privacy policy applies before data crosses a client or provider boundary.
16. Projection cannot infer, reinterpret, manufacture, or strengthen domain
    conclusions.
17. Projection failure must not silently make security state appear cleaner or
    more complete.

### Non-goals

WS1-C does not implement:

- GUI, voice, AI providers, monitoring, event ingestion, background scheduling,
  or jobs;
- report or SQLite persistence;
- report/history repositories;
- privileged brokers;
- vulnerability knowledge;
- remediation or consequential operations;
- wire protocols;
- application API numeric versioning;
- macOS support;
- scanner, scoring, exposure, firewall, or finding-identity redesign.

## 3. Application Namespace and Ownership

The production namespace is:

`src/cyberwatchtower/application/`

This name fits the current package organization and clearly separates
application use cases from deterministic domain logic, platform adapters,
persistence, and presentation.

### Package ownership

The application package owns:

- the single external facade;
- application DTO definitions;
- application error definitions;
- current-system assessment orchestration;
- validation and privacy-safe projection of scanner results;
- operation metadata such as application-generated operation IDs and completion
  time.

It does not own:

- host or platform detection;
- collection;
- scanner orchestration;
- security reasoning;
- finding identity algorithms;
- scoring;
- reachability or firewall-policy evaluation;
- report serialization;
- persistence;
- authorization decisions for future consequential operations;
- provider or GUI integration.

### Import boundary

The package may import:

- `cyberwatchtower.scanner` from the internal assessment implementation;
- platform-neutral closed enums and validation contracts;
- the existing finding-identity resolution helper;
- score validation;
- reachability deserialization/validation;
- the existing pure evidence sanitizer;
- Python standard-library value types and UUID/time primitives.

It must not directly import:

- `platform/linux/*` or `platform/windows/*`;
- native/helper/transport modules;
- Linux nftables parser or native modules;
- Windows native, IPC, COM, helper, or transport internals;
- `subprocess`, `sqlite3`, GUI packages, voice engines, provider SDKs, or
  packaging code;
- low-level memory database, migrations, queries, report directories, or
  arbitrary filesystem APIs;
- `SOURCE_COVERAGE_REQUIREMENTS`;
- Python's `platform` module for application-level platform detection.

The facade itself does not import or expose scanner internals. The internal
assessment use case may call the scanner through the narrow delegation seam
defined in Section 16.

## 4. External Facade Contract

The sole externally supported application object is:

`CyberWatchtowerApplication`

### Construction

Conceptual public construction:

```python
application = CyberWatchtowerApplication()
```

Construction:

- accepts no collector, adapter, command, path, database, provider, or privilege
  configuration;
- performs no I/O;
- performs no platform detection;
- performs no collection;
- performs no persistence;
- starts no thread, worker, event loop, or background job;
- acquires no privileged authority.

The facade is not a service locator. It must not expose internal scanner,
adapter, collector, repository, database, or provider objects.

### WS1-C operation

Conceptual operation:

```python
result = application.assess_current_system(
    CurrentSystemAssessmentRequest()
)
```

The operation:

- is synchronous;
- assesses only the current local system;
- invokes the existing scanner exactly once;
- returns an immutable application result or raises one typed application
  error;
- performs no report or memory persistence.

### Lifecycle and concurrency

For WS1-C:

- no explicit `close()` lifecycle is needed;
- facade instances may be reused sequentially;
- thread safety is not promised;
- concurrent invocation is not part of the contract;
- future job orchestration may wrap the synchronous operation without changing
  request or result semantics;
- the deterministic core remains synchronous behind that future orchestration.

Only names deliberately re-exported from `cyberwatchtower.application` are
public. Internal runners, projection functions, and injected test seams remain
private.

## 5. Assessment Request Contract

`CurrentSystemAssessmentRequest` is a frozen, slotted, zero-field dataclass.

No caller parameters are required by the current scanner authority. WS1-C must
not invent speculative configuration.

The request does not accept:

- hostnames, IP addresses, remote systems, or arbitrary targets;
- collector selection;
- adapter selection;
- platform claims;
- command arguments;
- report or database paths;
- privilege flags;
- generic approval flags;
- caller-supplied operation IDs;
- timeout, retry, scheduling, or persistence configuration.

### Target and privilege semantics

- Target: current local system only.
- Capability class: `READ_ONLY`.
- Privilege assumption: the application facade remains unprivileged and
  receives whatever conservative result the frozen scanner establishes.
- Authorization: no user approval is required for this read-only assessment.
- Unsupported platform: handled as Section 20 defines.

## 6. Assessment Result Contract

`CurrentSystemAssessmentResult` is a frozen, slotted top-level DTO with:

- `operation_id: str`
- `completed_at: datetime`
- `platform: SupportedPlatform`
- `system: SystemSummary`
- `firewall: FirewallTechnologySummary`
- `findings: tuple[ApplicationFinding, ...]`
- `score: SecurityScore`
- `coverage: tuple[DomainCoverage, ...]`
- `assurance: AssessmentAssuranceSummary`
- `projection_notices: tuple[ProjectionNotice, ...]`

### Platform field

`SupportedPlatform` is closed to:

- `LINUX`
- `WINDOWS`

The sole source is the explicit scanner-returned
`system["operating_system"]` field.

Accepted authoritative values are exactly:

- `"Linux"` → `SupportedPlatform.LINUX`
- `"Windows"` → `SupportedPlatform.WINDOWS`

The application must not:

- call `platform.system()`;
- inspect adapters or collectors;
- infer platform from assessment domains;
- infer platform from coverage keys;
- infer platform from firewall technologies, findings, listeners, or observed
  behavior;
- guess, default, or fall back to Linux.

A successful scanner result with missing, non-string, malformed, or unsupported
`system.operating_system` is a `COMPATIBILITY_FAILURE`. A scanner-raised
`UnsupportedPlatformError` is an `UNSUPPORTED_PLATFORM` application failure.

No existing production change is required: the explicit field is already
emitted for supported successful system observations.

### System summary

`SystemSummary` contains:

- `system_id: str | None`
- `hostname: str | None`
- `username: str | None`
- `operating_system: str`
- `os_version: str | None`
- `architecture: str | None`
- `processor: str | None`

`operating_system` is required because it supplies the platform identity. Other
fields may remain absent when the authoritative system observation omits them.

### Firewall technology summary

`FirewallTechnologySummary` contains only:

- `detected_technologies: tuple[str, ...]`

It does not expose executable/tool paths or raw firewall output.

### Score

`SecurityScore` preserves the complete validated Scoring v2 result:

- scoring version;
- score;
- risk level;
- severity counts;
- total effective penalty;
- ordered category breakdowns;
- ordered contributor groups and finding references;
- atomic, base, raw, and applied penalties;
- basis codes;
- guardrail data.

The application validates the returned serialized score using the current score
contract and then projects it into immutable child DTOs. It does not recalculate
any value.

### Metadata versus facts

Application metadata:

- `operation_id`
- `completed_at`
- projection/redaction notices

Authoritative domain facts:

- system fields returned by the scanner;
- findings and multiplicity;
- Scoring v2 result;
- top-level coverage;
- assurance;
- reachability and firewall-policy context already present in findings.

`completed_at` means application operation completion time. It is not a
collector observation timestamp or Report 1.7 `generated_at`.

## 7. Finding DTO Contract

`ApplicationFinding` is a frozen, slotted DTO containing:

- `finding_id: str`
- `title: str`
- `description: str`
- `severity: Severity`
- `recommendation: str`
- `evidence: tuple[ApplicationEvidence, ...]`
- `evidence_projection_state: EvidenceProjectionState`
- `omitted_evidence_count: int`
- `confidence: int`
- `technique_id: str | None`
- `source: str`
- `kind: FindingKind`
- `assessment_state: AssessmentState`
- `network_context: NetworkExposureContext | None`
- `presentation_group_id: str | None`
- `runtime_instance_count: int`

It does not contain `coverage_domains`.

### Finding identity

- The existing canonical helper resolves the ID.
- A present authoritative `Finding.finding_id` remains authoritative.
- When absent, the existing helper may resolve the canonical current identity.
- The application must not duplicate or modify the identity algorithm.
- It must not derive identity from redacted DTO evidence.
- It must validate uniqueness across the assessment.
- It must preserve scoring contributor references to the same canonical
  identities.
- An identity that cannot cross the local application privacy boundary safely
  is a required-field privacy failure; it must not be silently replaced by a new
  hash or synthetic identity.

### Finding-level coverage

The current `Finding` model has no authoritative coverage-domain field.
Therefore:

- `ApplicationFinding` has no `coverage_domains` field in WS1-C;
- the application does not import or use `SOURCE_COVERAGE_REQUIREMENTS`;
- source strings, kind, title, evidence, and network context are never used to
  reconstruct finding-level coverage;
- top-level assessment coverage remains complete and exact.

### Evidence

`ApplicationEvidence` contains only:

- `category: ApplicationEvidenceCategory`
- `value: str`

`ApplicationEvidenceCategory` is a closed enum for the structurally reviewed
labels:

- `ADDRESS`
- `EXPOSURE`
- `FORWARD_POLICY`
- `FIREWALL_ENABLED`
- `DEFAULT_INBOUND_ACTION`
- `BLOCK_ALL_INBOUND`
- `INPUT_POLICY`
- `OUTPUT_POLICY`
- `PORT`
- `PROCESS`
- `PROFILE`
- `PROTOCOL`
- `SERVICE`
- `SERVICE_APPLICATION`

Acceptance additionally requires an allowlisted producer/category pair:

- `network`: `ADDRESS`, `EXPOSURE`, `PORT`, `PROCESS`, `PROTOCOL`, `SERVICE`,
  `SERVICE_APPLICATION`
- `firewall`: `INPUT_POLICY`, `FORWARD_POLICY`, `OUTPUT_POLICY`
- `firewall_inbound_policy`: `PROFILE`, `FIREWALL_ENABLED`,
  `DEFAULT_INBOUND_ACTION`, `BLOCK_ALL_INBOUND`

`Application:` is deliberately excluded because the Linux process-intelligence
path may contain a script, module, or executable path. `PID:`, `Reachability:`,
`Failure code:`, `Detected tools:`, unlabeled text, and unknown labels are also
excluded.

`EvidenceProjectionState` is:

- `COMPLETE` when every evidence item was structurally accepted;
- `REDACTED` when one or more items were withheld.

Evidence redaction:

- increments `omitted_evidence_count`;
- does not remove the finding;
- does not change severity, state, confidence, multiplicity, score, or network
  context;
- does not imply the withheld evidence was false;
- does not authorize provider transmission.

## 8. Coverage / Assurance Contract

`DomainCoverage` contains:

- `domain: ScanDomain`
- `state: CoverageState`

The application requires:

- explicit `assessment_domains`;
- a non-empty, duplicate-free, recognized ordered domain list;
- a coverage mapping with exactly the same domain keys;
- one recognized `CoverageState` for every applicable domain;
- no missing or extra domains.

The DTO preserves scanner domain order and exact states. It does not use a
defaulting path that could silently turn malformed or absent data into
`UNKNOWN`.

`AssessmentAssuranceSummary` contains:

- `level: AssessmentAssurance`
- `limitations: tuple[str, ...]`

The returned assurance must validate exactly against the current deterministic
assurance contract. Validation may compare the returned value with the existing
deterministic contract; the application must not replace it with a newly
interpreted result.

The following remain separate:

- coverage;
- assessment assurance;
- score and threat risk;
- finding confidence;
- reachability;
- future Evidence Confidence;
- future Visibility.

WS1-C does not claim that the future Confidence Engine or unified Visibility
model exists.

Top-level `UNKNOWN` and `INCOMPLETE` are valid authoritative result data, not
application errors.

## 9. Network / Exposure Projection

`NetworkExposureContext` contains:

- `bind_exposure`
- `bind_epistemic_role`
- `reachability_state`
- `reachability_epistemic_role`
- `evidence_basis: tuple[...]`
- `firewall_policy: FirewallApplicabilitySummary | None`

`FirewallApplicabilitySummary` contains the existing bounded values:

- applicability;
- default-policy context;
- evidence basis;
- matching rule digests;
- rule-collection coverage;
- rule-applicability coverage;
- evaluated policy disposition.

Projection uses the existing structured deserializer/validator in
`reachability_from_report()`. This validates and materializes
already-established context; it does not recalculate reachability.

The application does not:

- call `assess_listener_reachability`;
- reconstruct firewall applicability;
- interpret raw firewall rules;
- merge nftables and iptables;
- infer reachability from bind address;
- turn policy `ALLOW` into `CONFIRMED_REACHABLE`.

The invariant is explicit:

`ALLOW != CONFIRMED_REACHABLE`

The DTO does not expose:

- raw nftables or Windows firewall-rule objects;
- raw rules, expressions, stdout, stderr, or JSON;
- helper/transport objects;
- interface conditions;
- raw process command lines;
- executable paths.

The current scanner does not return an authoritative full listener inventory.
WS1-C therefore projects network/exposure context only for returned findings and
does not invent a complete listener list.

## 10. System / Identity Privacy Classification

| Data | Classification | WS1-C treatment |
|---|---|---|
| OS/platform | ALWAYS SAFE FOR LOCAL APPLICATION DTO | Required and exposed |
| OS version | ALWAYS SAFE FOR LOCAL APPLICATION DTO | Optional |
| Architecture | ALWAYS SAFE FOR LOCAL APPLICATION DTO | Optional |
| Processor label | PURPOSE-LIMITED | Optional local system summary |
| Opaque system ID | PURPOSE-LIMITED | Optional; never treated as raw machine identity |
| Hostname | PURPOSE-LIMITED | Optional local system summary |
| Username | PURPOSE-LIMITED | Optional local system summary |
| Raw machine identity source | INTERNAL ONLY | Never exposed |
| PID | INTERNAL ONLY in WS1-C | Not projected |
| Process name | PURPOSE-LIMITED | Only in allowed finding evidence |
| Application display identity | PURPOSE-LIMITED | Only reviewed display name form |
| Raw application/executable/script path | INTERNAL ONLY | Redacted |
| Service identity/display name | PURPOSE-LIMITED | Reviewed evidence only |
| Listener address/IP | PURPOSE-LIMITED | Finding/exposure explanation only |
| Application digest | PURPOSE-LIMITED | Not added to WS1-C unless already required by an approved DTO field |
| Firewall-rule identifiers/details | INTERNAL ONLY except reviewed rule digests | Raw details never exposed |
| Finding identity | PURPOSE-LIMITED | Required stable reference; not a display label or provider-safe token |

Purpose-limited fields are present only where the current assessment use case
requires them. Their inclusion in a local DTO does not authorize their use by
AI providers, logs, support bundles, notifications, or unrelated clients.

## 11. Deep Immutability Rules

All public request, result, error-data, and child DTOs must use:

- frozen dataclasses;
- `slots=True`;
- tuples for ordered collections;
- closed enums;
- immutable scalar values;
- timezone-aware immutable datetime values;
- purpose-built immutable child DTOs.

They must not expose:

- lists, dictionaries, sets, mutable mappings, or mapping views;
- scanner-returned objects;
- `Finding` instances;
- handles, callbacks, services, adapters, repositories, connections, or
  callables;
- caller-owned mutable state.

Every nested mutable scanner value must be copied and validated into immutable
application-owned state.

Arbitrary `Mapping` fields are prohibited. If a future mapping is unavoidable,
it requires a separate contract and must be normalized into a deterministically
ordered immutable representation.

Immutability includes nested children; a frozen dataclass containing a mutable
list or dictionary does not satisfy this contract.

## 12. Application Error Contract

### Error shape

`CyberWatchtowerApplicationError` carries one immutable `ApplicationFailure`:

- `code: ApplicationErrorCode`
- `message: str`
- `retryable: bool`
- `component: ApplicationComponent`
- `operation_id: str`
- `domain: ScanDomain | None`

Safe messages are bounded, stable, and user-facing.

Errors must never contain:

- exception `repr`;
- traceback;
- SQL;
- local filesystem or database paths;
- argv or command lines;
- stdout, stderr, native JSON, or raw rules;
- environment values;
- credentials or secrets;
- provider payloads;
- mutable exception objects.

### Taxonomy

The closed taxonomy reserves:

- `INVALID_REQUEST`
- `NOT_FOUND`
- `CONFLICT`
- `UNSUPPORTED_PLATFORM`
- `COMPONENT_UNAVAILABLE`
- `PERMISSION_DENIED`
- `TIMEOUT`
- `CANCELLED`
- `AUTHORIZATION_REQUIRED`
- `AUTHORIZATION_DENIED`
- `AUTHORIZATION_EXPIRED`
- `PRIVACY_POLICY_BLOCKED`
- `INTEGRITY_FAILURE`
- `STORAGE_FAILURE`
- `COMPATIBILITY_FAILURE`
- `INTERNAL_FAILURE`

WS1-C implements only the categories it can produce:

- `INVALID_REQUEST`
- `UNSUPPORTED_PLATFORM`
- `PRIVACY_POLICY_BLOCKED`
- `COMPATIBILITY_FAILURE`
- `INTERNAL_FAILURE`

The remaining values are reserved for later contracts and must not be emitted
speculatively.

Incomplete or unavailable security evidence is not automatically an
application error. If the scanner returns a valid conservative result, the
application returns that result with its explicit coverage and finding state.

## 13. Privacy Projection Contract

Privacy is allowlist-first.

An external application DTO may contain only fields explicitly approved by
this contract. Absence of a deny rule never grants permission.

### Evidence processing order

For each finding:

1. Require a list of strings as the legacy scanner evidence shape.
2. Apply the existing bounded evidence sanitizer for normalization, controls,
   known labels, and defense-in-depth rejection.
3. Require an application-approved `(finding.source, evidence category)` pair.
4. Convert the accepted item to typed `ApplicationEvidence`.
5. Redact every item that fails any step.
6. Record `REDACTED` plus the exact omitted count.
7. Preserve the finding and its authoritative non-evidence fields.

The existing sensitive-marker scan may reject an otherwise structurally allowed
item. It may never authorize an item.

Specifically:

- lack of words such as `argv`, `stdout`, `stderr`, `password`, or `environment`
  does not prove safety;
- presence of an allowed-looking label is insufficient without approved source
  provenance;
- unclassified free text is redacted even if it appears harmless;
- `Application:` evidence remains redacted even when no sensitive marker is
  present;
- no free-text heuristic may convert an unknown item into approved evidence.

### Field handling

| Data | Rule |
|---|---|
| Executable/script paths | Never projected |
| Raw command lines | Never projected |
| Usernames/hostnames | Only purpose-specific `SystemSummary` fields |
| PIDs | Not projected in WS1-C |
| IP/listener addresses | Purpose-limited structured exposure/evidence |
| Service names | Purpose-limited reviewed evidence |
| Application display names | Reviewed `SERVICE_APPLICATION` only |
| Application digests | Not added speculatively |
| Raw firewall details | Never projected |
| Report/SQLite paths | Never projected |
| Investigation actor names | Deferred |
| Raw exceptions | Never projected |
| Provider payloads | Not present in WS1-C |

A required authoritative field that cannot be represented safely causes atomic
`PRIVACY_POLICY_BLOCKED`.

Optional evidence may be redacted without failing the operation because
redaction:

- is explicit;
- does not remove the finding;
- does not strengthen the finding;
- does not change top-level coverage or assurance.

No DTO or field is labeled `provider_safe`, `safe_to_send`, or equivalent.
Local application DTO safety is not external-provider safety. The later AI
Privacy Firewall must construct a separate purpose-built provider DTO.

## 14. Serialization Contract

WS1-C introduces no wire serialization.

Application DTOs:

- have no `to_dict()` public wire contract;
- have no JSON schema;
- are not Report 1.7 objects;
- are not Memory schema 8 objects;
- are not persistence records;
- are not provider payloads.

This avoids freezing a premature cross-process or GUI wire format.

When serialization becomes necessary, a separately reviewed contract must
define:

- field names;
- enum encoding;
- timestamp encoding;
- tuple/list representation;
- absent versus unknown;
- unknown enum handling;
- compatibility and evolution behavior;
- privacy classifications.

Canonical report serialization remains unchanged.

## 15. Versioning Contract

The following compatibility domains remain independent:

| Domain | Current WS1-C rule |
|---|---|
| Python package version | Existing package mechanism; unchanged |
| Report schema | Frozen at `1.7` |
| Memory schema | Frozen at `8` |
| Scoring | Frozen at `v2` |
| Application-service Python API | Source-level contract; no numeric version yet |
| Application DTO wire schema | Does not exist in WS1-C |
| Capability parameter contracts | Deferred |
| Authorization proposal contracts | Deferred |

An application API or DTO serialization version becomes necessary before:

- an independently deployed consumer relies on it;
- a cross-process transport is introduced;
- persisted application DTOs are introduced;
- compatibility across separately upgraded components is required.

WS1-C must not invent a numeric application API version merely to populate a
field.

## 16. Scanner Delegation / Injection Contract

Production assessment delegates to:

`cyberwatchtower.scanner.run_scan()`

Rules:

- exactly one call per assessment operation;
- no retry;
- no second assessment;
- no adapter argument;
- no duplicate platform selection;
- no direct collector calls;
- no reconstruction of findings, score, reachability, firewall applicability,
  or policy disposition;
- no persistence.

The production implementation imports the scanner module and resolves
`scanner.run_scan` at operation time.

### Private test seam

A private internal assessment runner may accept one narrow callable with the
conceptual type:

```python
Callable[[], dict]
```

This seam:

- is internal to `application.assessment`;
- is not exported from `cyberwatchtower.application`;
- is not accepted by the public facade constructor;
- cannot be used to inject adapters, commands, collectors, paths, or
  privileges;
- exists solely to test projection and exactly-once delegation.

The facade's production path always uses the existing scanner authority.

## 17. Dependency / Import Rules

| Application area | Allowed | Forbidden |
|---|---|---|
| `contracts.py` | stdlib values; platform-neutral closed domain enums | scanner, collectors, persistence, subprocess, providers |
| `errors.py` | stdlib; platform-neutral domain identifier if needed | scanner, storage, native/platform internals |
| `assessment.py` | scanner module; domain validators; finding identity helper; score validator; reachability validator; pure evidence sanitizer | native/platform-specific modules, `SOURCE_COVERAGE_REQUIREMENTS`, database, filesystem persistence, subprocess |
| Facade/public package | application contracts, errors, assessment use case | service locator exposure, injected collectors/repositories |
| Tests | private callable seam; mocks/fakes that return scanner-shaped data | native execution, real collection, SQLite/report writes |

Specific rules:

- `scanner`: internal assessment implementation only.
- `models`: allowed for validating authoritative Finding/enums; mutable
  instances must never escape.
- report contracts: allowed for closed domains and strict validation.
- scoring contracts/report validation: allowed; scoring engine recalculation is
  forbidden.
- reachability: deserialization/validation allowed; reachability assessment
  calculation forbidden.
- advisor/history: not needed in WS1-C.
- memory: only the pure bounded `memory.sanitization` helper is permitted;
  database/service/ingestion imports are forbidden.
- `platform/contracts` and platform-neutral models: validation only where
  required.
- `platform/linux/*` and `platform/windows/*`: forbidden.
- `subprocess`, `sqlite3`, GUI, voice, and provider SDKs: forbidden.
- Python `platform`: forbidden for application platform detection.

Import-boundary tests must enforce these rules structurally.

## 18. Operation Identity / Future Job Compatibility

The application creates an operation ID before request validation and scanner
delegation.

Format:

`assessment:` followed by 32 lowercase hexadecimal characters generated from
UUID4.

Properties:

- generated by the application;
- unique for practical correlation purposes;
- not caller-supplied;
- not a system ID, finding ID, job ID, capability, approval, or authorization;
- not persisted in WS1-C;
- safe for bounded diagnostics and typed errors;
- present in both success and failure paths.

A future background job may carry both a job ID and this assessment operation
ID without changing the assessment result contract.

Operation identity grants no authority.

## 19. Authorization Interaction

Current-system assessment is classified:

`READ_ONLY`

WS1-C does not require artificial approval because the current operation is
already authorized, local, read-only assessment.

The future application boundary will distinguish:

- `READ_ONLY`
- `USER_APPROVAL_REQUIRED`
- `PROHIBITED`

No method may accept:

- `approved=True`;
- generic approval tokens;
- assistant/model intent as approval;
- an operation ID as approval;
- previous unrelated approval;
- GUI navigation or button visibility as approval.

No assistant or model output can satisfy an authorization requirement.

WS1-C does not define privileged proposals, approval lifetimes, brokers,
remediation, or capability execution.

## 20. Unsupported Platform Contract

Unsupported platforms fail closed.

Production behavior:

1. The application calls `scanner.run_scan()` once.
2. The scanner's existing platform selection occurs before collection.
3. If it raises `UnsupportedPlatformError`, the application returns no result
   and raises `UNSUPPORTED_PLATFORM`.
4. The application performs no independent platform detection and no fallback.
5. No native collector is invoked by the application.

A successful scanner-shaped result whose `system.operating_system` is missing,
malformed, or not exactly `Linux` or `Windows` is a `COMPATIBILITY_FAILURE`. It
does not trigger domain-signature inference or a second platform check.

The application does not:

- fall back to Linux;
- guess based on firewall technology;
- infer from coverage domains;
- partially claim authoritative assessment for Darwin/macOS;
- add macOS support.

## 21. Projection Failure Contract

Projection is atomic: either one complete immutable DTO graph is returned, or
one typed application error is raised.

### `COMPATIBILITY_FAILURE`

Use when:

- the top-level scanner result has an unexpected type or key structure;
- required authoritative fields are missing;
- `system.operating_system` is absent, malformed, or unsupported in a returned
  result;
- findings contain unsupported types or closed-enum values;
- score validation fails;
- coverage domains and coverage keys do not match exactly;
- assurance contradicts the authoritative coverage;
- network context or policy structures are invalid;
- stable finding identities conflict or scoring references do not resolve;
- a deterministic relationship cannot be represented without ambiguity.

### `PRIVACY_POLICY_BLOCKED`

Use when:

- a required authoritative field cannot safely cross the local application
  boundary;
- required stable identity or required deterministic content contains
  structurally prohibited material;
- safely substituting or omitting the required value would alter identity or
  meaning.

### Explicit conservative values

Preserve `UNKNOWN`, `INCOMPLETE`, `PARTIAL`, `POTENTIAL`, and other valid
conservative domain values exactly.

### Optional omission/redaction

Optional evidence may be withheld only when:

- the finding remains present;
- redaction state and count are explicit;
- no severity, score, assurance, reachability, multiplicity, or coverage value
  changes.

Optional presentation-only system fields may be `None` only when the
authoritative source omitted them. Projection must not silently erase a present
required field.

No partial result is returned after a projection error.

## 22. WS1-C Test Contract

WS1-C acceptance requires, at minimum, tests proving:

### Delegation and authority

1. Scanner callable is invoked exactly once.
2. Production path uses `scanner.run_scan()`.
3. Public callers cannot inject adapters or collectors.
4. Application code invokes no platform-specific collector.
5. No finding reconstruction occurs.
6. No score recalculation occurs.
7. No reachability recalculation occurs.
8. No firewall applicability or disposition recalculation occurs.
9. Existing canonical finding identity helper is used rather than duplicated.
10. Existing scanner API remains unchanged.

### Requests, results, and immutability

11. Request is deeply immutable.
12. Result is deeply immutable.
13. Findings and evidence children are deeply immutable.
14. No nested list, dictionary, set, mutable mapping, or `Finding` escapes.
15. Operation ID has the specified form and is not caller-controlled.
16. Operation ID is not treated as authorization.
17. Completion time is timezone-aware application metadata.

### Finding and scoring preservation

18. Stable finding identities are preserved.
19. Duplicate/conflicting finding identities fail atomically.
20. Finding multiplicity is preserved.
21. Severity is preserved.
22. Kind and assessment state are preserved.
23. Confidence is preserved.
24. Technique ID is preserved without claiming full ATT&CK mapping.
25. Recommendation is preserved.
26. Scoring version remains v2.
27. Score, counts, breakdown, contributors, and guardrail are preserved.
28. Invalid scoring contributor references fail atomically.

### Coverage and assurance

29. Top-level assessment domains and coverage are preserved exactly.
30. Missing or extra coverage keys fail atomically rather than defaulting.
31. `UNKNOWN` and `INCOMPLETE` remain explicit.
32. Assurance is preserved and validated.
33. Finding DTO has no `coverage_domains`.
34. No import or use of `SOURCE_COVERAGE_REQUIREMENTS`.
35. Finding coverage is not reconstructed from source, title, kind, evidence,
    or network context.

### Platform hardening

36. `SupportedPlatform.LINUX` is projected only from exact
    `system.operating_system == "Linux"`.
37. `SupportedPlatform.WINDOWS` is projected only from exact
    `system.operating_system == "Windows"`.
38. Application code does not call Python `platform.system()`.
39. Platform is not inferred from assessment-domain composition.
40. Platform is not inferred from coverage keys, firewall domains, findings,
    listeners, or firewall technology.
41. Missing platform metadata plus a valid Linux domain signature yields
    `COMPATIBILITY_FAILURE`.
42. Malformed platform metadata plus a valid Windows domain signature yields
    `COMPATIBILITY_FAILURE`.
43. Unsupported returned platform text does not trigger a fallback.
44. Scanner `UnsupportedPlatformError` maps to typed `UNSUPPORTED_PLATFORM`.
45. Unsupported-platform failure yields no result and no second scanner call.
46. Existing scanner/platform tests continue to prove adapter selection precedes
    collection.

### Network and exposure

47. Structured reachability is preserved.
48. Firewall applicability and evaluated policy disposition are preserved.
49. `ALLOW` never becomes `CONFIRMED_REACHABLE`.
50. Missing or malformed network context fails conservatively.
51. Raw rules, native snapshots, command output, and interface details are
    absent.

### Structural privacy

52. Evidence acceptance requires an allowlisted category.
53. Evidence acceptance requires an allowlisted source/category pair.
54. Unknown labels are redacted even without sensitive-marker words.
55. Unlabeled free text is redacted even when apparently harmless.
56. `Application:` evidence is redacted even when it contains no sensitive
    marker.
57. `PID:`, `Reachability:`, `Failure code:`, and `Detected tools:` are not
    exposed as evidence.
58. A structurally allowed item containing a sensitive marker is rejected as
    defense in depth.
59. Absence of a sensitive marker cannot authorize an unclassified item.
60. Existing sanitized, bounded evidence rules remain enforced.
61. Redaction produces `REDACTED` plus the exact omitted count.
62. Redaction does not remove the finding.
63. Redaction does not change severity, state, confidence, multiplicity, score,
    coverage, assurance, or reachability.
64. Required privacy failure is atomic and typed `PRIVACY_POLICY_BLOCKED`.
65. Raw command lines, executable paths, stdout/stderr, environment data,
    credentials, and native output canaries are absent.
66. No DTO has a provider-safe flag or claim.
67. Local DTO projection is not treated as AI-provider authorization.

### Boundaries and side effects

68. No report is written.
69. No SQLite module, database, or memory service is accessed.
70. No filesystem path authority is exposed.
71. No subprocess module is imported.
72. No async, thread, queue, scheduler, or job system is implemented.
73. No dependency is added.
74. No schema version changes.
75. No application API numeric version is introduced.
76. No native command or collector runs in the focused tests.

## 23. WS1-C Exact Implementation Boundary

Exactly seven new files are proposed.

### Production

#### `src/cyberwatchtower/application/__init__.py`

Responsibility:

- export the facade, request/result contracts, and public error types;
- define the deliberate public API.

Allowed dependencies:

- application package modules only.

Forbidden:

- scanner logic;
- projection;
- collection;
- persistence;
- side effects.

#### `src/cyberwatchtower/application/contracts.py`

Responsibility:

- deeply immutable request/result/child DTOs;
- application-only enums such as `SupportedPlatform`, evidence categories,
  projection state, and notices;
- validation local to immutable application values.

Allowed:

- stdlib dataclasses, enums, datetime;
- approved platform-neutral closed domain enums.

Forbidden:

- scanner;
- platform-specific modules;
- projection logic;
- persistence;
- serialization;
- provider-safety claims.

#### `src/cyberwatchtower/application/errors.py`

Responsibility:

- typed error enum;
- immutable failure DTO;
- public application exception.

Forbidden:

- raw exception retention;
- scanner or platform logic;
- persistence or diagnostics storage.

#### `src/cyberwatchtower/application/assessment.py`

Responsibility:

- generate operation identity;
- invoke scanner exactly once;
- map the explicit scanner platform field;
- strictly validate scanner output;
- project immutable DTOs;
- apply structural privacy projection;
- translate exceptions into safe application failures.

Allowed:

- scanner module;
- approved domain validators;
- identity resolver;
- score validator;
- reachability validator;
- pure evidence sanitizer.

Forbidden:

- independent platform detection;
- coverage-source mapping;
- scoring or reachability calculation;
- direct collectors;
- persistence;
- subprocesses;
- provider, GUI, voice, or job code.

### Tests

#### `tests/test_application_contracts.py`

Covers DTO shape, deep immutability, closed enums, operation identity form, and
absence of provider-safe claims.

#### `tests/test_application_assessment.py`

Covers exactly-once delegation, faithful projection, platform metadata
hardening, score/coverage/network preservation, structural evidence projection,
atomic errors, and no persistence.

#### `tests/test_application_boundaries.py`

Covers forbidden imports, no direct platform/native access, no
`SOURCE_COVERAGE_REQUIREMENTS`, no subprocess/SQLite, no persistence authority,
public export restrictions, and the seven-file scope.

### Existing production changes

None.

NO EXISTING PRODUCTION SEMANTIC FILE CHANGES IN WS1-C.

The corrected platform review does not make WS1-C impossible: the explicit
scanner-returned `system.operating_system` field is sufficient. Therefore no
scanner or other existing production semantic file change is authorized.

## 24. WS1-C Acceptance Gate

WS1-C may be accepted only when:

- all focused WS1-C tests pass;
- application imports and modified/new Python files compile;
- relevant existing scanner, platform-contract, finding-identity, scoring,
  coverage, reachability, firewall-policy, privacy, and report-contract tests
  pass;
- the full portable regression suite passes before freeze;
- no native collector or scan is executed;
- no dependencies are added;
- Report schema remains `1.7`;
- Memory schema remains `8`;
- Scoring remains `v2`;
- effective-exposure semantics are unchanged;
- scanner and CLI APIs are unchanged;
- no report or memory persistence is introduced;
- no CLI migration is included;
- no async/job implementation is included;
- only the seven authorized new files change;
- privacy and dependency boundary tests pass;
- the repository diff contains no implementation outside WS1-C scope.

Commit and push require separate authorization.

## 25. Deferred WS1 Contracts

Deferred to later WS1 phases:

- WS1-D report repository and report lifecycle;
- WS1-E memory/history/diagnostics integration;
- WS1-F assistant, capabilities, authorization proposals, and
  application-safe grounding;
- WS1-G CLI migration;
- WS1-H qualification and freeze.

Also deferred:

- background-job contract;
- progress and cancellation;
- scheduling and monitoring;
- expanded application logging and diagnostics;
- event and alert contracts;
- AI Privacy Firewall;
- provider DTOs;
- GUI consumer contract;
- voice consumer contract;
- monitoring consumer contract;
- wire serialization and cross-process transport;
- capability parameter versioning;
- authorization proposal versioning.

WS1-C includes only compatibility hooks: immutable operation identity,
synchronous wrapability, typed errors, purpose-specific DTOs, and a single
facade.

## 26. Contradiction Review

No unresolved frozen-contract contradiction was found.

| Contract area | Result |
|---|---|
| Master Specification | Consistent |
| WS1-A accepted architecture | Consistent |
| Scanner authority | Preserved |
| Report schema 1.7 | Unchanged |
| Memory schema 8 | Unchanged |
| Scoring v2 | Unchanged |
| Effective exposure semantics | Unchanged |
| Windows/Linux boundaries | Preserved |
| Advisor/grounding authority | Not bypassed |
| Authorization invariants | Preserved |
| Platform correction | Resolved using explicit scanner-returned field |
| Finding coverage correction | Resolved by omitting unsupported field |
| Privacy correction | Resolved through structural allowlisting and conservative redaction |

No production semantic-file modification is required.

## 27. Decisions Frozen by This Contract

This contract freezes:

1. One external facade: `CyberWatchtowerApplication`.
2. Namespace: `cyberwatchtower.application`.
3. In-process Python boundary for WS1.
4. Synchronous current-system assessment operation.
5. Zero-field immutable assessment request.
6. Service-generated non-authoritative operation ID.
7. Scanner called exactly once.
8. `scanner.run_scan()` remains sole current assessment authority.
9. No public dependency injection or service locator.
10. No independent application platform detection.
11. Platform comes only from explicit `system.operating_system`.
12. No domain-signature platform inference.
13. Deep immutable purpose-specific DTOs.
14. Exact top-level coverage preservation.
15. No finding-level coverage reconstruction.
16. No `ApplicationFinding.coverage_domains` in WS1-C.
17. Exact score, identity, multiplicity, state, confidence, reachability, and
    firewall-policy preservation.
18. No domain-value recalculation.
19. Structural, allowlist-first evidence projection.
20. Sensitive-marker checks are rejection-only defense in depth.
21. Explicit redaction state and count.
22. No provider-safe claim on local DTOs.
23. Atomic projection.
24. Typed privacy, compatibility, unsupported-platform, invalid-request, and
    internal failures.
25. Current assessment is `READ_ONLY` without artificial approval.
26. No persistence, serialization, jobs, concurrency framework, or numeric API
    version in WS1-C.
27. Seven new files and no existing production semantic-file changes.

## 28. Decisions Explicitly Deferred

This contract does not decide:

- GUI framework;
- voice/STT/TTS engines;
- AI provider;
- provider DTO schema;
- full AI Privacy Firewall policy;
- event storage/index technology;
- monitoring scheduler;
- job execution mechanism;
- cross-process transport;
- application wire schema/version;
- report and memory repository design;
- privileged-broker technology;
- vulnerability source;
- packaging/signing/update mechanisms;
- capability proposal schema;
- authorization token/approval persistence;
- telemetry or SIEM contracts;
- macOS support.

## 29. Repository State After Proposal

| Item | Final state |
|---|---|
| HEAD | `b95f87106a6132000a0be3b2f074f674e3243f8b` |
| origin/main | `b95f87106a6132000a0be3b2f074f674e3243f8b` |
| Ahead/behind | `0/0` |
| Worktree | Clean |
| Staged files | `0` |
| Files modified | `0` |
| Files created | `0` |
| Commits | `0` |
| Pushes | `0` |
| Native collectors/scans | `0` |
| Network activity | `0` |
| Dependencies installed | `0` |
| Tests executed | `0` |
| Implementation work | `0` |

## 30. WS1-B.1 Hardening Corrections

### Correction 1 — Platform identity

**Original issue**

The earlier proposal permitted `SupportedPlatform` to fall back to
assessment-domain composition when `system.operating_system` was unavailable.
That would have turned security-domain composition into an unauthorized
platform-detection mechanism.

**Final resolution**

- The scanner already returns explicit `system.operating_system` metadata.
- Only exact `"Linux"` or `"Windows"` values are accepted.
- Coverage domains, firewall domains, findings, listeners, and other
  observations are never used as platform signals.
- Missing, malformed, or unsupported returned metadata produces
  `COMPATIBILITY_FAILURE`.
- A scanner-raised `UnsupportedPlatformError` produces `UNSUPPORTED_PLATFORM`.
- No application-level `platform.system()` call or fallback exists.

**Affected sections**

Sections 3, 6, 16, 17, 20, 21, 22, 23, and 27.

**Implementation consequence**

WS1-C can retain `SupportedPlatform` without modifying the scanner or any
existing production file.

**Test consequence**

Tests must prove exact-field use, no independent detection, no domain-signature
fallback, and conservative failure for absent or malformed metadata.

### Correction 2 — Finding coverage linkage

**Original issue**

The prior proposal allowed finding-level `coverage_domains` to be reconstructed
through `SOURCE_COVERAGE_REQUIREMENTS`.

**Final resolution**

- Current `Finding` has no authoritative finding-level coverage field.
- `ApplicationFinding.coverage_domains` is removed.
- The application does not import or consult `SOURCE_COVERAGE_REQUIREMENTS`.
- No indirect source, kind, title, evidence, or network-context reconstruction
  is permitted.
- Top-level assessment coverage remains exact and mandatory.

**Affected sections**

Sections 7, 8, 17, 21, 22, 23, and 27.

**Implementation consequence**

Finding projection becomes narrower. No scanner or report-contract behavior
changes.

**Test consequence**

Tests must prove the field is absent, the source map is not imported, source
changes cannot create finding-level coverage, and top-level coverage remains
exact.

### Correction 3 — Structural privacy projection

**Original issue**

The prior proposal placed too much authority in free-text marker matching for
identifying argv, output, credentials, environment material, and paths.

**Final resolution**

- Privacy projection is explicit-field and source/category allowlist first.
- The existing bounded sanitizer is reused only as one validation layer.
- Application evidence requires a closed typed category and approved
  producer/category pair.
- Marker matching can reject but can never authorize.
- Unknown, unlabeled, or unclassified evidence is conservatively redacted.
- Redaction is explicit and counted.
- Findings remain present and unchanged.
- Required fields that cannot safely cross the boundary fail atomically.
- No local DTO is declared provider-safe.

**Affected sections**

Sections 7, 10, 11, 12, 13, 21, 22, 23, and 27.

**Implementation consequence**

WS1-C needs a typed evidence child DTO, closed evidence-category enum,
source/category allowlist, explicit projection state, and omitted count. It must
not rely on substring scanning as its privacy decision.

**Test consequence**

Tests must prove structural authorization, conservative redaction of apparently
harmless unknown text, rejection-only marker behavior, preservation of the
finding, and absence of provider-safety claims.

## 31. Final Consistency Audit

| # | Consistency check | Result |
|---:|---|---|
| 1 | `scanner.run_scan()` remains sole assessment authority | PASS |
| 2 | No application code performs platform detection independently | PASS |
| 3 | No platform is inferred from security-domain signatures | PASS |
| 4 | No finding-level coverage is reconstructed from source mappings | PASS |
| 5 | No score is recalculated | PASS |
| 6 | No reachability is recalculated | PASS |
| 7 | No firewall applicability or disposition is recalculated | PASS |
| 8 | No finding identity algorithm is duplicated | PASS |
| 9 | Existing identity helper only resolves/validates canonical identity | PASS |
| 10 | `UNKNOWN` and `INCOMPLETE` remain explicit | PASS |
| 11 | `ALLOW` cannot become `CONFIRMED_REACHABLE` | PASS |
| 12 | Projection remains atomic | PASS |
| 13 | Deep immutability remains mandatory | PASS |
| 14 | Privacy is allowlist-first | PASS |
| 15 | Free-text heuristics are defense in depth only | PASS |
| 16 | No DTO is declared provider-safe | PASS |
| 17 | Unsupported platforms fail closed | PASS |
| 18 | Current assessment remains `READ_ONLY` without artificial approval | PASS |
| 19 | Operation IDs remain non-authoritative and non-persisted | PASS |
| 20 | No persistence exists in WS1-C | PASS |
| 21 | Report schema remains 1.7 | PASS |
| 22 | Memory schema remains 8 | PASS |
| 23 | Scoring remains v2 | PASS |
| 24 | No wire serialization is introduced | PASS |
| 25 | No numeric application API version is invented | PASS |
| 26 | No existing production semantic file modification is authorized | PASS |

No unresolved contradiction or owner decision is required before the bounded
WS1-C implementation slice.

## 32. Freeze Recommendation

A. FREEZE WS1-B — CONTRACT INTERNALLY CONSISTENT AND WS1-C READY
