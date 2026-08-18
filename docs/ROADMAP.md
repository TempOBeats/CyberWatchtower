# CyberWatchtower Roadmap

This roadmap records product direction and dependency order from the v0.3
checkpoint. It is planning guidance, not authorization to implement a phase,
run collectors, or override the engineering and security rules in
[`AGENTS.md`](../AGENTS.md). Every milestone still requires explicit review and
approval.

## Product vision

CyberWatchtower is evolving into a professional, cross-platform cybersecurity
intelligence assistant for Linux, Windows, and macOS. It should help an operator
understand current posture, meaningful changes, recurring problems, evidence,
and carefully authorized defensive investigations.

The permanent rule is: **deterministic security evidence remains
authoritative**. AI may retrieve, organize, explain, and prioritize trusted
records or propose bounded workflows. Model output is not evidence by itself
and cannot invent findings, grant approval, or modify a system.

## Status legend

- **Complete** — implemented and covered by repository tests.
- **Planned** — accepted direction, but not implemented.
- **Preview candidate** — valuable for 1.0 if its trust and quality gates pass.
- **Post-1.0** — intentionally deferred beyond the first professional release.

## Current status: v0.4 implemented; native Windows validation pending

CyberWatchtower is currently a Linux-validated deterministic security-intelligence
CLI with optional local persistent memory. Its observation boundary is
platform-neutral. The Windows adapter and deterministic scan path are
implemented with portable fixtures, but native Windows validation is still
pending and the support remains experimental/pre-release. There is no macOS
adapter, desktop GUI, external knowledge retrieval, production model
adapter, honeypot runtime, executable investigation capability, fleet
controller, or voice interface.

The current implementation provides:

- Linux system, firewall, listening-socket, process, and service observations;
- safe interpreter-backed application attribution without persisting raw argv;
- explicit finding severity, kind, assessment state, confidence, and stable ID;
- deterministic scoring, risk classification, and separate assessment assurance;
- domain-specific `COMPLETE`, `INCOMPLETE`, and `UNKNOWN` coverage;
- canonical versioned JSON reports, stable local system identity, strict history
  isolation, stable finding identity, and coverage-aware resolution;
- deterministic historical comparison, recurrence analysis, and score trends;
- a deterministic Advisor and supported questions with trusted rendering;
- an Intelligence Core with evidence references, epistemic roles, grounding,
  session references, briefings, and deterministic/no-model operation;
- bounded provider-neutral selection contracts that cannot author authoritative
  findings or remediation prose;
- an execution-grade authorization-envelope foundation, while
  approval-required capabilities remain non-executable;
- optional Persistent Security Memory v0.2 with transactional ingestion,
  lifecycle/reopen tracking, typed queries, decisions, expiring presentation
  exceptions, versioned baselines, investigations, capability audit, structured
  references, retention, integrity diagnostics, and failure isolation;
- Python 3.11–3.13 continuous integration and a standard-library runtime; and
- v0.2.1 trust/correctness hardening plus the v0.3 platform observation
  contracts and `LinuxPlatformAdapter` parity suite.

Milestone labels in this document describe development checkpoints. They do not
by themselves change the version in package distribution metadata.

## Architectural principles

1. **Deterministic authority.** Collectors and deterministic derivations
   establish local facts. Presentation, memory context, external knowledge, and
   models cannot rewrite them.
2. **Explicit uncertainty.** Coverage and assessment assurance remain separate
   from severity scoring. Unsupported or incomplete collection fails
   conservatively.
3. **Evidence provenance.** Observed facts, deterministic derivations, external
   knowledge, user assertions, user decisions, and model interpretations remain
   distinguishable and source/role compatibility is validated.
4. **Stable isolation.** Stable `system_id` is authoritative; hostname is never
   a substitute. Host-bound history, memory, approval, and execution stay
   isolated.
5. **Local-first privacy.** Sensitive host data stays local by default. Cloud
   use is explicit opt-in and receives only sanitized, purpose-built DTOs.
6. **Typed authorization.** Consequential capabilities require a canonical plan
   and exact, expiring authorization bound to system, target, parameters,
   capability, proposal, actor decision, and execution time.
7. **No generic execution.** There is no arbitrary shell/command dispatch,
   autonomous privilege escalation, or automatic remediation.
8. **Hostile content is data.** Logs, files, webpages, retrieved documents,
   network input, and honeypot telemetry are untrusted data, never instructions.
9. **Presentation is not authority.** GUI, model, and voice layers may render
   grounded records but cannot create facts or bypass policy.
10. **Canonical records survive enrichment.** JSON reports remain canonical;
    persistent memory is an optional auditable index and context layer.

## Completed milestones

| Milestone | Status | Delivered foundation |
| --- | --- | --- |
| Deterministic foundation | Complete | Linux scanning, firewall/socket/process/service interpretation, stable findings, scoring, JSON reports, history, recurring findings, and process intelligence. |
| Advisor and Intelligence Core | Complete | Deterministic advice/questions, trusted rendering, evidence and grounding, briefings, constrained provider boundary, session references, and no-model gateway. |
| Persistent Security Memory v0.2 | Complete | Secure SQLite migrations, ingestion, host-isolated lifecycle/queries, decisions/exceptions/baselines, investigations/audit, structured references, optional core context, retention, integrity, and diagnostics. |
| Trust and correctness v0.2.1 | Complete | Coverage-aware JSON resolution, assurance, strict legacy identity, socket privacy/completeness, source-role enforcement, authorization envelopes, and CI. |
| Platform observations v0.3 | Complete | Immutable observations/failures, explicit platform selection, Linux adapter parity, conservative coverage, and future-adapter contracts. |
| Windows observations v0.4 | Implemented; validation pending | Dependency-free native system, listener/attribution, and firewall collectors plus the assembled Windows scan path; guarded native tests still require Windows execution. |

## Road to 1.0

Version labels below are planning envelopes. Scope and numbering can change
after design review, but dependency and trust gates should not be skipped.

### v0.4 — Windows platform adapter

**Objective:** Implement deterministic Windows collection behind the v0.3
contracts while preserving shared finding authority.

**Deliverables**

- Safe stable identity derivation with raw identifiers kept local.
- Normalized system, listener, process/application, service, and firewall
  observations using fixed-purpose Windows APIs or commands.
- Explicit unsupported, unavailable, permission, partial, malformed, and
  complete states per domain.
- Windows fixtures, contract/privacy tests, deterministic ordering, and native CI.
- Shared interpretation only where normalized evidence has equivalent meaning;
  Windows-specific policy stays isolated when semantics differ.

**Dependencies:** v0.3 contracts and adapter test harness.

**Trust gate:** no generic PowerShell/command runner, no raw output or machine-ID
source material in durable/provider data, and no optimistic coverage.

**Test gate:** exact observation, coverage, finding, identity, score, assurance,
privacy, and failure tests on supported Windows environments.

**Non-goals:** GUI, remote management, log ingestion, EDR behavior, remediation,
and macOS collection.

### v0.5 — macOS platform adapter

**Objective:** Add conservative macOS collection through the same contracts.

**Deliverables:** macOS identity, listeners, process/application attribution,
services, and firewall posture where authoritative collection is available;
explicit unsupported/partial domains; platform fixtures, privacy tests, and CI;
documented semantic differences instead of false equivalence.

**Dependencies:** v0.3 contracts and lessons from Windows integration.

**Trust gate:** fixed-purpose collection, safe identity derivation, bounded
failures, and conservative coverage.

**Test gate:** deterministic fixtures and native macOS contract verification.

**Non-goals:** GUI, unified-log analysis, remediation, and fleet collection.

### v0.5.x — cross-platform collector maturity

**Objective:** Prove that Linux, Windows, and macOS feed one stable deterministic
engine without erasing legitimate OS differences.

**Deliverables:** reusable conformance tests, versioned observation DTOs,
granular coverage, fixture provenance, compatibility rules, parser fuzz/property
tests, and a clear boundary between shared interpretation and OS-specific policy.

**Dependencies:** all three adapters.

**Trust gate:** equivalent observations yield equivalent conclusions;
unsupported domains never appear complete.

**Test gate:** cross-platform CI, golden fixtures, finding-ID stability where
semantically equivalent, and backward-compatible reports/memory.

**Non-goals:** new scanner domains and presentation work.

### v0.6 — application-service boundary

**Objective:** Create the sole supported boundary between security core services
and future desktop or automation clients.

**Deliverables**

- Versioned immutable DTOs and typed errors.
- Use cases for dashboard snapshots, scan jobs, progress/cancellation, finding
  detail/evidence, history/trends, briefings/questions, investigations,
  approvals, and memory health.
- Background-job and cancellation semantics that cannot leave partial
  authoritative records.
- Single-writer SQLite ownership, bounded read concurrency, and lifecycle rules.
- Local authentication/origin controls if transport crosses a process boundary.

The GUI must never open SQLite or invoke collectors directly.

**Dependencies:** mature platform boundary and the memory service protocol.

**Trust gate:** DTOs preserve provenance and uncertainty; presentation cannot
mutate findings; authorization remains in trusted application/core services.

**Test gate:** contract, concurrency, lock/failure, cancellation, serialization,
privacy, and compatibility tests.

**Non-goals:** final GUI framework, public network API, plugins, or models.

### v0.7 — curated security knowledge and vulnerability applicability

**Objective:** Add authoritative external context without confusing it with
local observation.

**Deliverables**

- A local curated knowledge format and provenance policy before model-assisted
  retrieval.
- Source trust, signatures/hashes, freshness, caching, update rollback, and
  citations for CyberWatchtower-curated content, CVE/NVD, CISA KEV, MITRE
  ATT&CK, and vendor advisories.
- Structured software/service/version observations and deterministic
  applicability states.
- The correlation chain:

  ```text
  local software/service/version observation
      → authoritative external record
      → applicability analysis
      → grounded explanation with both source classes
  ```

External knowledge is not local observation, and possible applicability is not
a confirmed local vulnerability. Port or product name alone is insufficient.

**Dependencies:** grounding/provenance, mature collectors, and safe update and
package handling.

**Trust gate:** retrieved text is untrusted; applicability requires explicit
local evidence; poisoned sources cannot become local findings.

**Test gate:** source authenticity/freshness, poisoned documents, parser fuzzing,
false-positive applicability fixtures, citation integrity, and offline fallback.

**Non-goals:** open-web RAG, autonomous exploitation, and model-authored findings.

### v0.8 — desktop application foundation

**Objective:** Deliver a professional local desktop experience over the
application-service layer.

PySide6/Qt is the leading candidate because it integrates with the Python core,
has mature native components, and avoids a separate web runtime. Final selection
is deferred until v0.6 packaging, job, update, memory-footprint, accessibility,
and signing prototypes are measured. Tauri or a secured local-web UI should be
reconsidered if team skills, sandboxing, distribution size, or multi-client
requirements change.

**Planned views**

- Dashboard and system posture
- Security score, assessment assurance, and coverage
- Active, resolved, reopened, and recurring findings
- Finding detail and evidence/provenance explorer
- Network/service view and history/trends
- Investigation workspace and exact approval dialogs
- Security briefing and AI Assistant panel
- Vulnerability intelligence
- Honeypot management placeholders until that subsystem is safe
- Memory/integrity health and privacy/settings controls

**Dependencies:** application-service DTOs and cross-platform core behavior.

**Trust gate:** UI state is never authority; approvals show and bind the exact
plan; untrusted content renders inertly; no direct SQLite/collector access.

**Test gate:** service/UI contracts, accessibility, hostile rendering, approval
integrity, packaging smoke tests, and crash/resource testing.

**Non-goals:** model-required operation, fleet console, voice, and broad honeypot
deployment.

### v0.9 — conversational intelligence and bounded investigations

**Objective:** Expand deterministic questions into richer grounded multi-turn
assistance and carefully authorized defensive investigation.

**Deliverables**

- Richer intent/reference resolution for “What changed?”, “Have we seen this
  before?”, “Why is this dangerous?”, “What should I fix first?”, and
  “Investigate this.”
- Professional concise-by-default briefings with beginner/expert depth.
- Meaningful-change summaries and evidence citations.
- Narrow capabilities such as inspect process/service, selected logs/files,
  vulnerability intelligence, rescan, and compare state—only after each has a
  typed implementation and policy.
- Mandatory execution flow:

  ```text
  proposal → canonical typed plan → deterministic policy → exact authorization
      → execution-time validation → fixed-purpose execution → sanitized result
      → evidence and audit → grounded response
  ```

**Dependencies:** application service, authorization envelopes,
investigation/audit memory, and platform-specific capability implementations.

**Trust gate:** no arbitrary execution; models cannot approve or execute;
changed, expired, or cross-system authorization fails closed; completion does
not prove remediation.

**Test gate:** authorization mutation/replay/concurrency, privacy canaries,
failure evidence, prompt injection, and end-to-end audit reconstruction.

**Non-goals:** autonomous remediation, ambient approval, and unrestricted agents.

### v0.9.x — optional model assistance

**Objective:** Improve language understanding and explanation while retaining a
fully useful deterministic/no-model product.

**Sequence**

1. Preserve and continuously test deterministic/no-model mode.
2. Prototype a local model with bounded schemas and sanitized DTOs.
3. Add optional cloud providers only after equivalent privacy/grounding gates;
   cloud use remains explicit opt-in.
4. Consider a future CyberWatchtower-tuned model only after representative,
   privacy-safe evaluation data and governance exist.

Models may select known IDs, intents, bounded enums, and proposed plan elements.
Trusted code resolves those selections and renders authoritative claims. Models
do not author findings, evidence, approvals, shell commands, or remediation truth.

**Dependencies:** stable context DTOs, knowledge provenance, grounding, privacy
policy/consent, and evaluation infrastructure.

**Trust gate:** prompt injection cannot cross into policy; provider payloads are
allowlisted and inspectable; failures preserve deterministic output.

**Test gate:** hallucination/grounding evaluations, source-role tests, provider
privacy snapshots, malicious-context suites, and deterministic fallback.

**Non-goals:** model-required scanning, open-ended execution, and silent cloud use.

### 1.0 — professional cross-platform release

**Objective:** Integrate proven components into a signed, supportable desktop
security-intelligence assistant.

**Release gate**

- Linux, Windows, and macOS adapters meet coverage and privacy contracts.
- The application service and GUI cannot bypass authority or authorization.
- Vulnerability applicability is evidence-backed and conservative.
- Briefings and bounded investigations remain useful with models disabled.
- Memory migrations, locking, corruption, retention, and recovery are tested.
- Installers, signing, update policy, SBOM, privacy documentation, and supported
  platform matrices are ready.
- Independent security review and cross-platform/adversarial acceptance tests
  have no unresolved blockers.

**Non-goals:** enterprise EDR, autonomous remediation, arbitrary plugins,
mandatory cloud services, voice approval, and unrestricted fleet control.

## Honeypot Generator and Honeypot Lab

The Honeypot Lab is a major planned subsystem, not part of the current product.
It has two separate responsibilities.

### Configuration and deployment

- Guided, versioned decoy profiles and safe templates
- Exact interface, port, protocol, and exposure configuration
- Preflight service-collision and environment validation
- Canonical deployment plan and explicit approval
- Isolated start, stop, health, and teardown lifecycle
- Resource, disk, connection, and rate limits
- Safe structured logging and alerting

Initial deployments should prefer **rootless containers** where trustworthy
platform support exists. Higher-interaction or internet-facing deployments
should prefer stronger isolation such as **VMs or dedicated nodes/appliances**.
A raw privileged host process should not be the default.

### Honeypot intelligence

- Connection, session, and activity timelines
- Recurring-source and behavior summaries
- Investigation/evidence integration
- Careful ATT&CK and threat-intelligence correlation
- Dashboard views and proactive briefing signals
- Grounded answers to “Who connected?”, “What did we observe?”, “Is this
  recurring?”, and “Does this resemble known behavior?” without overstating
  attribution

All honeypot input is attacker-controlled and untrusted. Observed traffic and
behavior remain separate from attribution or model speculation.

### Dependencies and threat gate

```text
platform abstraction + application-service boundary + exact authorization
    + isolated execution + investigation/evidence memory
    + hostile-input normalization
    → honeypot deployment → honeypot intelligence
```

Threat modeling must cover escape, host compromise, production-service
collision, excessive exposure, unauthorized third-party traffic, disk/resource
exhaustion, log injection, prompt injection, hostile payloads, and unsafe
teardown. A narrow local lab preview may be considered for 1.0 only after these
gates; broad internet-facing and higher-interaction operation is post-1.0.

**Test gate:** rootless isolation and escape testing, exact authorization and
service-collision fixtures, resource exhaustion limits, hostile telemetry and
prompt-injection suites, deterministic timeline/evidence tests, and reliable
teardown on each supported deployment platform.

**Non-goals for an initial preview:** higher-interaction production exposure,
attribution claims, autonomous response, privileged host deployment by default,
and broad protocol emulation.

## Additional intelligence tracks

### Validated Linux hardening backlog

The following future-hardening items come from an authorized real-world Linux
assessment. They are validated observations, not implemented capabilities, and
are not blockers for Windows v0.4 Phase 3.

- **Narrow privileged collection.** A non-privileged scan correctly reported
  incomplete iptables coverage, while running the entire application with
  `sudo` allowed complete inspection but created root-owned report artifacts.
  Future work should isolate elevation to the narrow collector that requires it
  so reporting, memory, Advisor, Intelligence Core, and user-facing artifacts
  remain in the normal user context. This item does not authorize autonomous
  elevation or a privileged-helper implementation.
- **Effective firewall-posture intelligence.** Read-only validation found
  iptables `INPUT`, `FORWARD`, and `OUTPUT` policies set to `ACCEPT`, with no
  nftables ruleset present, confirming that the existing MEDIUM permissive-input
  finding was valid. Future deterministic analysis may consider effective
  iptables/nftables filtering, listener exposure, and platform-specific firewall
  semantics rather than relying only on the default INPUT policy. This item does
  not change current scoring or findings and does not authorize automatic
  firewall changes.

### Log analysis

Planned authorized ingestion covers Linux logs, Windows Event Logs, macOS
unified logs, CyberWatchtower logs, and honeypot telemetry. It requires
source-specific normalization, explicit provenance, host/time identity, privacy
filtering, volume/rate limits, retention, and inert hostile-text handling. Raw
logs should not enter model prompts by default.

### Baseline and drift intelligence

Memory already stores versioned, user-approved presentation baselines. Future
deterministic drift analysis may cover services, listeners, firewall posture,
processes and startup/persistence, approved applications, and security
configuration. Baselines never suppress current evidence or alter scores; drift
is a derived comparison with explicit provenance.

### Proactive intelligence

Planned signals include periodic authorized assessments, reopened findings,
score and assurance changes, baseline drift, vulnerability/KEV updates, and
honeypot activity. Outputs are meaningful-change alerts and morning, daily, or
weekly briefings—not autonomous remediation. Scheduling, privileges, resource
budgets, stale-data rules, and notification privacy require explicit policy.

### Multi-system progression

```text
single local host → personal devices/home lab → small business → managed fleet
```

Early desktop releases should not carry premature enterprise complexity. Later
stages require authenticated agents/controllers, encrypted synchronization,
per-host authorization, remote-evidence provenance, system/tenant isolation,
multi-user RBAC, conflict handling, and auditable administration.

### Voice

```text
speech-to-text → Intelligence Core → grounded response → text-to-speech
```

Voice is a post-core-maturity presentation layer. Ambient speech cannot grant a
consequential approval, alter findings, bypass policy, or imply identity.
Microphone use, transcription, retention, and cloud transmission must be
visible, local-first, and explicitly controlled.

## Packaging and release engineering

Before 1.0, product engineering must establish:

- coherent package and milestone versioning;
- an explicit license and complete distribution metadata;
- reproducible wheel/sdist and clean-environment tests;
- Linux packages plus Windows and macOS installers;
- Windows signing, macOS signing/notarization, and protected signing keys;
- a secure rollback-aware update architecture and release channels;
- SBOM generation, dependency provenance, pinned build tooling, and supply-chain
  review;
- CI matrices for supported Python and operating-system versions;
- an explicit telemetry policy and privacy-preserving diagnostics; and
- release acceptance, migration, upgrade, downgrade-policy, and uninstall tests.

## 1.0 prioritization

### Must have for 1.0

- Linux, Windows, and macOS deterministic collection with explicit coverage
- Cross-platform adapter and fixture maturity
- Application-service layer and safe single-writer memory ownership
- Professional desktop GUI
- Deterministic/no-model operation
- Grounded vulnerability applicability using curated authoritative knowledge
- Useful deterministic briefings, history, and proactive meaningful changes
- Narrow evidence-producing authorized investigations with exact approval
- Packaging, installers, signing, secure-update policy, SBOM, and privacy controls

### Should have for 1.0

- Local AI, if grounding and privacy evaluations pass
- Structured authorized log analysis for high-value platform sources
- Deterministic baseline drift for services, listeners, firewall, and startup
- Proactive daily/weekly briefings and local notifications
- A limited rootless-container Honeypot Lab preview, only if isolation gates pass
- Basic honeypot activity timelines if that preview ships

### Nice to have / preview for 1.0

- Optional opt-in cloud AI with sanitized provider DTOs
- Bounded model-assisted RAG over curated verified sources
- Vulnerability-feed updates with explicit freshness controls
- Small home-lab multi-system preview
- Additional investigation and log-source adapters

### Post-1.0

- Broad managed-fleet and enterprise RBAC/controller features
- Higher-interaction or broadly internet-facing honeypots
- Full honeypot intelligence and large-scale threat correlation
- Broad log analytics or EDR-like response
- Voice interaction
- CyberWatchtower-specific fine-tuned models
- Autonomous remediation, unless reconsidered under a future major safety design

## Dependency graph

```text
v0.3 observation contracts
    ├─→ Windows adapter ─┐
    ├─→ Linux adapter ───┼─→ cross-platform maturity
    └─→ macOS adapter ───┘        │
                                  ├─→ application-service layer
                                  │       ├─→ desktop GUI
                                  │       ├─→ packaging/installers
                                  │       ├─→ proactive monitoring UI
                                  │       └─→ future voice/UI consumers
                                  └─→ platform investigation tools

evidence provenance + grounding
    ├─→ curated knowledge → vulnerability applicability → grounded RAG
    └─→ deterministic conversation → local AI → optional cloud AI

authorization envelope + capability registry
    → fixed-purpose capabilities → executable investigations
    → isolated honeypot control → honeypot intelligence/proactive alerts

stable identity + per-host authorization + encrypted synchronization
    + application service
    → home-lab multi-system → small business → managed fleet/RBAC

mature Intelligence Core + application service + local-first STT/TTS privacy
    → voice presentation (never approval authority)
```

## Security and test evolution

| Area | Required evolution |
| --- | --- |
| Collectors | Native OS contracts, parser fuzz/property tests, hostile output, permission, cancellation, and coverage parity. |
| Memory/service | Migration matrices, locking/concurrency, corruption, rollback, performance, isolation, and privacy canaries. |
| Knowledge | Source authenticity, freshness, poisoning, applicability false positives, offline behavior, and citation correctness. |
| Authorization | Plan mutation, replay, expiry, revocation, cross-system, race-at-start, and audit reconstruction. |
| Models | Hallucination/grounding evaluations, prompt injection, provider privacy, bounded-schema rejection, and deterministic fallback. |
| GUI | Inert untrusted rendering, approval integrity, accessibility, cancellation, crash recovery, and packaging. |
| Honeypots | Isolation/escape, collision, exposure, resource exhaustion, hostile telemetry, teardown, and evidence provenance. |
| Supply chain | Reproducible builds, dependency review, SBOM, signing, update rollback, and installer tests. |

Threat models must progressively address a local desktop attacker, malicious
files/logs/network input, poisoned knowledge, compromised honeypots, model
prompt injection, malicious providers or future extensions, approval spoofing,
cross-host contamination, and build/update compromise.

## CyberWatchtower 1.0 experience

For a normal user, 1.0 should feel calm and clear:

- “How secure is my computer?” shows score, assurance, limitations, and priorities.
- “What changed?” identifies evidence-backed meaningful changes.
- “What should I fix first?” prioritizes trusted deterministic actions.
- “Explain this.” resolves context safely and adjusts explanation depth.
- “Have we seen this before?” uses host-isolated lifecycle evidence.
- “Give me my morning security briefing.” summarizes current and changed posture
  when proactive briefing support is enabled.

For a security professional, 1.0 should expose depth and traceability:

- “Show reopened findings.”
- “Compare this host to the approved baseline.”
- “Investigate this listener.” proposes an exact plan for approval.
- “Show evidence and provenance.” separates facts, derivations, decisions, and
  external knowledge.
- “Check vulnerability applicability.” correlates observed version evidence with
  cited authoritative sources.
- “Show honeypot activity.” is available only if a safe preview ships.

“Set up a safe honeypot” and “What happened in the honeypot overnight?” remain
future workflows until isolation, authorization, and hostile-input gates pass.
The product should develop its own professional identity: concise by default,
technically precise, non-alarmist, and explicit about uncertainty.

## Immediate next milestone

The recommended next implementation milestone is the **Windows platform
adapter**. It tests the v0.3 abstraction against a genuinely different OS,
reveals which observation semantics are portable, and unlocks later
application-service and GUI work without coupling them to Linux.

Its scope should remain collection parity and conservative Windows coverage.
GUI, models/RAG, executable investigations, honeypots, proactive scheduling,
multi-system control, and voice should wait for their prerequisite gates and
separate approval.
