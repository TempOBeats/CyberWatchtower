# CyberWatchtower 1.0 Master Specification

**Status:** FROZEN PRODUCT CONTRACT

**Owner approval:** APPROVED

**Frozen from repository baseline:** `07126ab77123b34f829cd4c8eed4d822810bbf08`

**Purpose:** Defines the required CyberWatchtower 1.0 product scope, architecture boundaries, acceptance criteria, release blockers, workstreams, and Definition of Done.

Implementation status may change as development progresses, but changes to the required CORE 1.0 product contract require separate owner approval.

This specification does not itself authorize implementation, dependency changes, native execution, privileged execution, packaging changes, or network activity.

---

## 1. Executive Product Definition

CyberWatchtower 1.0 is a polished, installable, launchable local security product for Windows and Linux.

It is not complete merely because its scanner or backend works. A 1.0 user must be able to:

- Install and launch CyberWatchtower on a clean supported machine.
- Complete guided first-run setup.
- Assess the local system using clear privilege choices.
- Understand findings, risk, evidence, confidence, and visibility.
- Review effective network exposure without mistaking firewall policy for proof of remote reachability.
- Schedule assessments and monitor meaningful security changes.
- Receive and manage local alerts.
- Investigate findings and supported local security events.
- Review historical posture through Security Time Machine.
- Explore evidence through the local Watchtower Security Graph.
- Use the Watchtower Assistant through text and push-to-talk voice.
- Optionally enable enhanced provider-backed conversation through the AI Privacy Firewall.
- Generate, inspect, compare, and export reports.
- Manage privacy, retention, notifications, voice, diagnostics, updates, and model-provider configuration.
- Operate all major capabilities through Watchtower View, the production desktop GUI.

The defining product promise is:

> CyberWatchtower knows what it knows, knows what it does not know, and can prove the difference.

Deterministic security facts remain authoritative. Deterministic observations and deterministic security reasoning define those facts.

AI may explain, summarize, correlate, and assist. AI may not silently turn uncertainty into observed fact, create authoritative security facts, authorize itself, or execute arbitrary commands.

### Status model

Every feature has independent fields:

- Current state: `DONE`, `PARTIAL`, `NOT BUILT`
- 1.0 requirement: `REQUIRED`, `OPTIONAL`, `DEFERRED`
- Scope tier: `CORE 1.0`, `1.x`, `2.0 / RESEARCH`

A planned requirement does not upgrade current implementation status.

---

## 2. Design Principles

1. **Deterministic facts remain authoritative.**
2. **Uncertainty is explicit.** Missing, stale, inaccessible, unsupported, partial, and contradictory evidence remain visible.
3. **Threat risk, evidence confidence, and visibility are independent.**
4. **Important conclusions are traceable to evidence.**
5. **Observed and derived relationships remain distinct.**
6. **Collection and interpretation fail closed.**
7. **Firewall `ALLOW` is not proof of remote reachability.**
8. **No firewall evidence may produce `CONFIRMED_REACHABLE`.**
9. **Least privilege is the default.**
10. **The GUI and assistant remain unprivileged.**
11. **Privileged work is fixed-purpose, bounded, authorized, and auditable.**
12. **Privacy is enforced at collection, storage, reporting, diagnostics, AI, voice, and notification boundaries.**
13. **Security operation is local-first and meaningfully offline.**
14. **External generative AI is optional for the user, disabled by default, and not required for security-engine correctness.**
15. **A real production conversational model path is nevertheless a release requirement.**
16. **Consequential actions require explicit, exact authorization.**
17. **No arbitrary command execution or generic privileged execution exists.**
18. **Presentation is not authority.**
19. **The GUI never reads SQLite or calls collectors directly.**
20. **The assistant cannot bypass deterministic reasoning or the application-service boundary.**
21. **Unsupported platforms and semantics fail closed.**
22. **Schema and API evolution is versioned and migration-safe.**
23. **No silent cloud telemetry is assumed.**

---

## 3. Supported Platforms

### Officially supported for 1.0

- Windows 11 x64
- Current Ubuntu LTS x86_64
- Current Debian stable x86_64

The release manifest must bind “current” to exact qualified versions at release time.

### Validated advanced/developer target

- Kali Rolling x86_64

Kali remains important to engineering and native validation but is not part of the initial consumer support guarantee. Kali qualification failures must still be reviewed before release.

### Deferred

- Windows ARM64: `1.x`
- Additional Linux distributions and package families: `1.x`
- macOS: `2.0 / RESEARCH`

Unsupported platforms must fail closed rather than falling back to another adapter.

### Qualification requirements

Every officially supported platform must pass:

- Clean-machine installation
- First launch and onboarding
- Unprivileged operation
- Explicitly authorized privileged collection
- Native system, listener, process, and firewall validation
- Scheduled assessment and restart recovery
- GUI, assistant, voice, report, update, upgrade, and uninstall tests
- Conservative permission, unavailable, malformed, and unsupported behavior

---

## 4. Current Verified Baseline

| Item | Frozen baseline |
|---|---|
| HEAD | `07126ab77123b34f829cd4c8eed4d822810bbf08` |
| origin/main | `07126ab77123b34f829cd4c8eed4d822810bbf08` |
| Windows/Linux Effective Network Exposure | Frozen |
| Linux L5 | Closed green |
| Report schema | `1.7` |
| Memory schema | `8` |
| Distribution version | `0.1.0` |
| Portable test organization | 850 tests, 10 expected skips at accepted baseline |
| Windows native collection | Implemented and previously validated |
| Linux native L3B/parser/provenance path | Implemented and validated |
| GUI | Not built |
| Monitoring/local SOC | Not built |
| Production conversational provider | Not built |
| Voice | Not built |
| Installers/updater | Not built |

Existing effective-exposure, coverage, provenance, and fail-closed semantics remain authoritative unless separately calibrated and approved.

---

## 5. CyberWatchtower 1.0 Scope

### CORE 1.0 product pillars

1. Windows and Linux local host assessment
2. System, software, network, process, application, and service inventory
3. Firewall posture, rule applicability, and effective network exposure
4. Vulnerability context and exposure correlation
5. Scheduled monitoring and background jobs
6. Bounded local Windows/Linux security telemetry
7. Deterministic built-in detections
8. Local alerts, notifications, and basic investigations
9. Watchtower Security Graph
10. Evidence Chain and bounded Attack Story
11. Independent risk, confidence, and visibility
12. Deterministic behavioral baselines
13. Security Time Machine
14. AI Privacy Firewall
15. Two-layer Watchtower Assistant
16. At least one qualified external/provider-neutral conversational model path
17. Push-to-talk voice with offline STT/TTS
18. Watchtower View production GUI
19. Application-service and authorization architecture
20. Versioned configuration, secure secrets, logging, and diagnostics
21. Installers, signing, updates, rollback, and clean-machine qualification

### Not CORE 1.0

- Enterprise fleet scale
- Full enterprise SIEM ingestion
- Full Sigma ecosystem compatibility
- UEBA
- Enterprise SOAR
- Autonomous remediation
- Autonomous purple-team attacks
- Large deception networks
- Multi-agent autonomous investigations
- Predictive attack-path analysis
- Always-listening voice
- macOS support

---

## 6. Security Engine

### Existing authority to preserve

The deterministic engine remains authoritative for:

- Windows and Linux host assessment
- System identity and current-user context
- TCP/UDP and IPv4/IPv6 listeners
- Process intelligence
- Application and service attribution
- Firewall technology and posture
- Normalized firewall-rule collection
- Listener-specific firewall applicability
- Effective network exposure
- Findings and stable finding identity
- Severity and risk scoring
- Recommendations
- Coverage and assessment assurance
- Reports, history, changes, and trends

### Complete local inventory

The application-service layer must expose versioned, immutable DTOs for:

- System identity and supported platform
- Current user/session context where authoritative
- Installed software and package versions
- Security-relevant processes
- Applications and services
- Listeners and bindings
- Firewall technology, posture, snapshots, and applicability
- Findings, coverage, and freshness

Raw command lines, credentials, secrets, and unnecessary personal information must not be persisted.

### Vulnerability context

CORE 1.0 must:

- Use a versioned vulnerability knowledge set.
- Record source, provenance, license status, release date, freshness, and version.
- Verify knowledge-set integrity.
- Support rollback to the last trusted set.
- Remain usable offline with the last known good set.
- Show stale or missing knowledge as a visibility limitation.
- Match software only when identity and version evidence is adequate.
- Represent applicability uncertainty.
- Avoid version-only confirmation.

`VULNERABILITY KNOWLEDGE SOURCE = ADR REQUIRED`

### Vulnerability/exposure correlation

A vulnerability may be correlated to exposure only when CyberWatchtower can prove an identity chain such as:

`installed package/application → process/service → listener → firewall applicability`

Port number, title, process-name resemblance, or service-name resemblance alone is insufficient.

A broken or ambiguous link produces `POSSIBLE` or `UNKNOWN`, not confirmed exposure.

### Acceptance criteria

- Frozen scanner and exposure semantics remain green.
- No firewall evidence creates `CONFIRMED_REACHABLE`.
- No unavailable collector creates `COMPLETE`.
- Every finding has stable identity, severity, confidence basis, evidence references, coverage, source, and source version.
- Shared normalized facts have shared conclusions unless documented platform semantics differ.
- Report and memory compatibility is preserved through explicit versioning.

---

## 7. Monitoring and Local SOC

CyberWatchtower 1.0 provides a bounded local SOC, not enterprise SIEM scale.

### Scheduled assessments

Users can configure:

- Manual assessments
- Daily or weekly scheduled assessments
- Run-on-login or run-on-startup when explicitly enabled
- Quiet hours
- Resource-aware behavior where supported
- Privilege policy for scheduled collectors

No privileged credential may be stored in plaintext.

### Background jobs

Every job has:

- Stable job ID
- Job type and target
- Creation, start, and completion times
- Progress and current stage
- `QUEUED`
- `RUNNING`
- `CANCELLING`
- `CANCELLED`
- `SUCCEEDED`
- `FAILED`
- `PARTIAL`
- Cancellation checkpoints
- Per-operation timeouts
- Structured failure reason
- Recovery behavior after restart
- Privacy-safe audit record

Cancellation must not leave a partial canonical report presented as successful.

`BACKGROUND-JOB CONTRACT = IMPLEMENTATION CONTRACT REQUIRED`

### Bounded local telemetry

CORE 1.0 includes only explicitly approved security-relevant telemetry:

1. Assessment and finding lifecycle events
2. Listener, service, application, firewall, software, and vulnerability changes
3. Collector health and coverage changes
4. Authorization and privilege-boundary audit events
5. Selected local authentication/session events
6. Selected privilege/elevation events
7. Selected service lifecycle events
8. CyberWatchtower application health events

Each source requires:

- Explicit allowlist
- Documented security purpose
- Bounded expected volume
- Privacy classification
- Parser and version provenance
- Coverage semantics
- Failure behavior
- Retention classification
- Test fixtures

The Master Specification does not select exact log sources or event IDs.

- `WINDOWS CORE EVENT ALLOWLIST = IMPLEMENTATION CONTRACT REQUIRED`
- `LINUX CORE EVENT ALLOWLIST = IMPLEMENTATION CONTRACT REQUIRED`

### Alerts

Every alert includes:

- Stable alert ID
- Detection/rule ID and version
- Severity and threat-risk basis
- Evidence confidence
- Visibility
- Evidence references
- First/last observed time
- Affected entities
- Coverage and missing evidence
- Lifecycle status

Lifecycle:

`OPEN → ACKNOWLEDGED → INVESTIGATING → RESOLVED`

An alert may be `DISMISSED` with actor, timestamp, and rationale. Dismissal does not alter evidence.

### Notifications

CORE 1.0 includes:

- In-app notifications
- Native local desktop notifications
- Severity controls
- Quiet hours
- Spoken-alert controls
- Privacy-safe notification summaries
- No sensitive lock-screen content by default

Email, webhook, mobile push, and fleet routing are deferred to `1.x`.

### Retention

CORE requirements:

- Bounded defaults
- User-visible retention state
- Configurable supported windows
- Storage-growth visibility
- Dry-run deletion
- Exact explicit authorization
- Deletion audit
- Canonical-report protection unless separately selected

`DEFAULT RETENTION VALUES = PRODUCT CONFIGURATION DECISION REQUIRED`

Storage growth must be benchmarked before defaults are frozen.

---

## 8. SIEM Foundation

| Capability | Scope |
|---|---|
| Bounded Windows local security telemetry | CORE 1.0 |
| Bounded Linux local security telemetry | CORE 1.0 |
| Normalized local event schema | CORE 1.0 |
| Local event storage | CORE 1.0 |
| Bounded local event search | CORE 1.0 |
| Deterministic built-in detection engine | CORE 1.0 |
| Versioned built-in detection rules | CORE 1.0 |
| Curated ATT&CK mapping | CORE 1.0 |
| Basic local event/alert correlation | CORE 1.0 |
| Basic incidents/investigations | CORE 1.0 |
| Centralized multi-host telemetry | 1.x |
| Network/security-device telemetry | 1.x |
| Sigma compatibility | 1.x |
| IOC storage and matching | 1.x |
| Threat-intelligence feeds | 1.x |
| Campaign/TTP context | 1.x |
| Entity risk | 1.x |
| Threat hunting | 1.x |
| Retro-hunting | 1.x |
| Detection-engineering workflow | 1.x |
| UEBA | 2.0 / RESEARCH |
| Enterprise SOAR | 2.0 / RESEARCH |
| Autonomous response | 2.0 / RESEARCH |

### Event envelope

The normalized event schema must include:

- Event ID
- Schema version
- System ID
- Observed and ingested timestamps
- Source and source version
- Event type
- Subject and object references
- Sanitized structured attributes
- Evidence provenance
- Parser version
- Coverage and collection status
- Privacy classification
- Optional minimized local raw-record reference

`EVENT SCHEMA = IMPLEMENTATION CONTRACT REQUIRED`

### Local event search

CORE 1.0 requires:

- Structured filters
- Time range
- Event type
- Severity where applicable
- Entity
- Source
- Alert association
- Text search over explicitly indexed sanitized fields where safe

CORE 1.0 does not require:

- A custom query language
- Distributed search
- Arbitrary raw-log search
- Enterprise-scale indexing

`EVENT STORAGE/INDEX STRATEGY = ADR REQUIRED`

### Detection requirements

- Built-in rules are versioned and testable.
- Rules declare required evidence and coverage.
- Missing required evidence cannot become a positive fact.
- ATT&CK mapping is curated metadata, not proof that a technique occurred.
- Rule and content updates are integrity-verified and rollback-capable.
- Detection execution is deterministic for the same normalized input and rule version.

`DETECTION RULE FORMAT = IMPLEMENTATION CONTRACT REQUIRED`

---

## 9. Watchtower Security Graph

The CORE 1.0 graph is a provenance graph for one monitored system.

It is not a full enterprise graph-database requirement. Relational or adjacency storage is acceptable if it satisfies required graph queries, history, and provenance.

A dedicated graph-database dependency is not required.

### CORE entities

- Machine
- User/session identity where observed
- Process
- Application
- Service
- Listener/socket
- Firewall snapshot/policy/rule
- Finding
- Vulnerability
- Alert
- Incident/investigation
- ATT&CK technique

### Conditional entities

Only when actually observed by an authorized source:

- Connection
- Domain
- IP address
- Remote peer
- Device relationship

### CORE edges

- `OBSERVED_ON`
- `RUNS_AS`
- `INSTANCE_OF_APPLICATION`
- `HOSTS_SERVICE`
- `OWNS_LISTENER`
- `BINDS_TO_ADDRESS`
- `GOVERNED_BY_FIREWALL_SNAPSHOT`
- `MATCHED_BY_RULE`
- `BLOCKED_BY_RULE`
- `ALLOWED_BY_RULE`
- `FINDING_ABOUT`
- `VULNERABILITY_AFFECTS`
- `EVIDENCED_BY`
- `ALERT_ABOUT`
- `INCIDENT_CONTAINS`
- `MAPPED_TO_TECHNIQUE`

Every edge contains:

- System scope
- Evidence reference
- Observed or derived timestamp
- Validity interval where applicable
- Epistemic state
- Confidence basis
- Coverage/visibility
- Derivation rule and version where derived
- Provenance

No AI-suggested edge becomes authoritative without deterministic validation or explicit labeling as a human/model hypothesis.

### Acceptance

- Every displayed edge exposes its evidence.
- Current and stale edges are distinguishable.
- Contradictions are retained and shown.
- Missing relationships are not synthesized.
- Cross-system graph merging is not CORE 1.0.

`GRAPH SCHEMA = IMPLEMENTATION CONTRACT REQUIRED`

---

## 10. Attack Story and Evidence Chain

### Scope

CORE 1.0 Attack Story is:

- Local
- Evidence-backed
- Deterministically assembled
- Based on findings, alerts, supported local events, investigations, and proven graph relationships

It is not:

- Campaign attribution
- Threat-actor attribution
- Speculative kill-chain completion
- Fleet-wide campaign reconstruction
- AI-authored forensic truth

### Epistemic states

- `OBSERVED`: directly supported by a trusted observation.
- `STRONGLY SUPPORTED`: deterministically derived from sufficient authoritative evidence without a material unresolved contradiction.
- `POSSIBLE`: plausible but dependent on missing, ambiguous, or incomplete evidence.
- `UNKNOWN`: evidence is insufficient.

Only deterministic policy may assign `OBSERVED` or `STRONGLY SUPPORTED`. AI may summarize but cannot promote states.

### Story stages

When supported:

1. Context or precondition
2. Observed activity or change
3. Affected asset/entity
4. Security-control context
5. Exposure or potential consequence
6. Detection/alert
7. Human investigation or decision
8. Resolution or continuing uncertainty

Stages may be absent. Missing stages must not be fabricated.

### Story item

Each story item includes:

- Story-item ID
- Stage
- Epistemic state
- Timestamp or bounded interval
- Claim
- Evidence references
- Confidence basis
- Visibility
- Missing evidence
- Contradictions
- Provenance
- Derivation version
- Human annotations
- AI-summary indicator where applicable

### Universal evidence question

Every important finding, alert, incident conclusion, graph relationship, risk explanation, and assistant claim must answer:

> Why does CyberWatchtower believe this?

The answer presents:

- Conclusion
- Observed or derived status
- Supporting evidence
- Source and time
- Coverage limitations
- Contradictions and missing evidence
- Deterministic rule or reasoning step
- Human decision or model interpretation, separately labeled

Full historical evidence re-execution is deferred.

---

## 11. Confidence Engine

Three independent concepts are mandatory.

### Threat Risk

Answers:

> How harmful could this be?

It reuses:

- Existing 0–100 security scoring
- Finding severity
- Deterministically supported applicability
- Exposure and affected-asset context
- Alert severity

The frozen score is not replaced without separate calibration.

### Evidence Confidence

Answers:

> How strongly is this conclusion supported?

It considers:

- Direct versus derived evidence
- Source authority
- Collector/parser reliability
- Identity linkage
- Corroboration
- Contradictions
- Evidence freshness

Existing numeric finding confidence remains but gains explicit reason codes and calibration documentation.

### Visibility

Answers:

> How much of the relevant environment could CyberWatchtower see?

It derives from:

- Domain coverage
- Collector availability
- Privilege/access
- Freshness
- Unsupported semantics
- Telemetry gaps
- Required evidence fields

Visibility is never inferred from the number of findings.

### GUI requirements

Threat Risk, Evidence Confidence, and Visibility are shown separately.

High risk with low visibility must not look equivalent to high risk with strong evidence and high visibility. No single combined color or score may conceal the distinction.

---

## 12. Behavioral Baseline

CORE 1.0 implements a deterministic **Behavioral Baseline**, not a full Behavioral Digital Twin.

### CORE observations

Where authoritatively available:

- Usual listeners and bindings
- Usual services
- Usual applications
- Relevant recurring processes
- Current/login context
- Firewall posture
- Installed software
- Assessment schedule and typical coverage
- Selected security-event frequency
- Network peers or DNS only when an authorized telemetry source observes them

### Requirements

- System-scoped
- Versioned
- Explicit learning period
- User review and approval
- Explainable frequency/statistical methods
- No automatic “safe” classification
- No suppression of underlying facts
- Deviations stored as changes
- Alert generation only through deterministic rules
- Baseline decisions separated from evidence

The full “Behavioral Digital Twin” concept is deferred to `1.x` or later.

---

## 13. Security Time Machine

CORE 1.0 must answer:

- What changed?
- When did it change?
- What was the before/after state?
- When did a finding appear, recur, change, resolve, or reopen?
- How did score, visibility, exposure, software, vulnerability context, firewall posture, alerts, and incidents change?
- What evidence was available at the time?

### Required history

- Assessment snapshots
- Finding lifecycle
- Score and coverage history
- Listener/exposure history
- Firewall posture/applicability history
- Software/vulnerability history
- Baseline versions and deviations
- Alert and investigation timelines
- User decisions and authorizations

### Rules

- Original records retain original schema and rule versions.
- Recalculated views are labeled and do not overwrite originals.
- Missing historical evidence is explicit.
- Full evidence replay is deferred to `1.x`.

---

## 14. AI Privacy Firewall

The AI Privacy Firewall is CORE 1.0.

### Classifications

- `LOCAL_ONLY`
- `SAFE_TO_SEND`
- `SAFE_AFTER_REDACTION`
- `SECRET`
- `PROHIBITED`

### Required controls

- Closed per-purpose allowlists
- Field-level classification
- Secret/credential detection
- Redaction and deterministic tokenization
- Provider-specific policy
- Purpose limitation
- Explicit user consent
- Local-only default
- Pre-transmission category preview
- Request-level audit
- Immediate provider revocation
- Fail-closed handling for unknown fields or redaction failure

### External AI network boundary

External AI is:

- Disabled by default
- Explicitly enabled
- Visibly active
- Provider-configured
- Purpose-bound
- Privacy-filtered
- Audited
- Immediately revocable

The provider receives only a purpose-built sanitized DTO produced after the AI Privacy Firewall.

Never sent by default:

- Raw logs
- Raw firewall rules
- Raw command lines
- Credentials
- API keys
- Unclassified event attributes
- Arbitrary database records
- Full reports
- Audio
- Unfiltered transcripts
- Local filesystem contents

Provider failure cannot modify authoritative local state.

### GUI states

- `LOCAL ONLY`
- `SAFE TO SEND`
- `REDACTION REQUIRED`
- `BLOCKED`

---

## 15. Watchtower Assistant

**WATCHTOWER ASSISTANT** is a working product role, not final branding.

`FINAL ASSISTANT NAME = OWNER BRAND DECISION REQUIRED`

### Personality

- Calm
- Professional
- Direct
- Evidence-oriented
- Protective without alarmism
- Comfortable saying “I do not know”
- Not over-anthropomorphized

Preferred language includes:

- “I observed…”
- “CyberWatchtower derived…”
- “The available evidence supports…”
- “Visibility is incomplete because…”
- “This is possible, not confirmed.”
- “Here is the evidence chain.”

### Layer A — Deterministic Assistant

Always available locally.

Handles:

- Security briefing
- Known finding explanations
- What changed
- Fix-first recommendations
- Coverage/visibility explanations
- Basic history and navigation questions
- Privacy/configuration guidance
- Provider-unavailable fallback

Layer A requires no Internet connection.

### Layer B — Enhanced Conversational Assistant

Uses the qualified production model-provider path only when explicitly enabled.

Handles:

- Natural conversational phrasing
- Multi-turn explanation
- Summarization
- Navigation assistance
- Evidence-grounded synthesis
- Investigation assistance

Layer B cannot:

- Create security facts
- Upgrade epistemic states
- Rewrite findings
- Execute arbitrary commands
- Authorize itself
- Bypass the application-service API
- Bypass the AI Privacy Firewall
- Hide source or visibility limitations

### Production model requirement

At least one provider-neutral production conversational model path must be implemented and qualified for 1.0.

It must provide:

- Explicit opt-in
- Disabled-by-default configuration
- Secure secret storage
- Provider-specific allowlists
- Purpose limitation
- AI Privacy Firewall enforcement
- Auditing
- Deterministic grounding
- No model-authored security facts
- No arbitrary execution
- Deterministic fallback

No commercial provider is selected by this specification.

`PRODUCTION MODEL-PROVIDER IMPLEMENTATION = ADR REQUIRED`

A local model provider remains optional for `1.x`.

### Conversation handling

- Ephemeral by default
- Optional local persistence of summaries/references
- No raw transcript persistence without explicit consent
- Cross-system references prohibited
- Authoritative claims carry evidence references
- Provider unavailability is clearly disclosed
- Provider failure is not classified as security-engine failure

### Tool boundary

The assistant uses the application-service capability API. It cannot directly access collectors, SQLite, privileged brokers, or arbitrary shell execution.

---

## 16. Voice

Push-to-talk voice is `CORE 1.0`, `REQUIRED`, and release-blocking.

Always-listening and wake-word behavior are deferred.

### Required capabilities

- Push-to-talk
- Local/offline speech-to-text
- Local/offline text-to-speech
- Visible microphone state
- Explicit capture gesture
- Mute
- Volume
- Voice selection where supported
- Spoken-alert controls
- Privacy/source indicator
- Text fallback
- No default audio retention

### Privacy requirements

- Audio capture begins only after a deliberate user gesture.
- Active microphone state is unmistakable.
- Local versus cloud processing is shown before capture.
- Cloud speech, if later enabled, requires explicit opt-in and the AI Privacy Firewall.
- Audio is not retained by default.
- Transcripts are sensitive local data.
- Unfiltered transcripts are not sent externally.
- Voice failure never blocks assessment, monitoring, alerts, GUI, deterministic assistance, or reporting.

### Speaking behavior

Normal mode is concise. Urgent spoken alerts occur only when enabled and permitted by mute and quiet-hour settings.

`VOICE ENGINE SELECTION = ADR REQUIRED`

The ADR must evaluate:

- Licensing
- Package size
- CPU/GPU requirements
- Quality
- Privacy
- Windows/Linux support
- Offline behavior
- Accessibility
- Maintenance risk

The Master Specification does not select an STT/TTS engine.

---

## 17. Watchtower View GUI

Watchtower View is a production Windows/Linux desktop GUI.

### Frozen architectural requirements

- Uses the application-service boundary only
- No direct collector access
- No direct SQLite access
- Runs unprivileged
- Accessible
- Supports required graph/history/assistant/voice visualizations
- Packageable and updateable
- Reasonable desktop resource use
- Preserves evidence and uncertainty

`GUI TECHNOLOGY SELECTION = ADR REQUIRED`

No GUI framework is selected by this specification.

### Global navigation

1. Home / Command Center
2. Assets / This Device
3. Network
4. Findings
5. Exposure / Firewall
6. Monitoring
7. Alerts
8. Investigations
9. Security Graph
10. History / Time Machine
11. Reports
12. Watchtower Assistant
13. Settings
14. Privacy
15. Diagnostics

### Core views

#### Home / Command Center

- Current posture
- Threat Risk
- Evidence Confidence
- Visibility
- Last/next assessment
- Active alerts
- Important changes
- Monitoring/collector health
- Recommended actions
- Assistant briefing

#### Assets / This Device

- System identity
- OS and architecture
- User/session context
- Installed software
- Services/applications
- Data freshness and coverage

#### Network

- TCP/UDP listeners
- IPv4/IPv6
- Binding scope
- Process/application/service attribution
- Coverage
- Explicit absence of remote-reachability proof

#### Findings

- Filtering, sorting, search
- Severity, state, confidence, visibility
- Evidence Chain
- Recommendation
- Lifecycle
- Related graph entities, alerts, and vulnerabilities

#### Exposure / Firewall

- Firewall technology/posture
- Rule-collection status
- Listener-specific applicability
- Namespace/profile authority
- Unsupported/incomplete semantics
- Distinction between host policy and remote reachability

#### Monitoring

- Schedules
- Background jobs
- Progress/cancellation
- Collector health
- Coverage changes
- Retention/storage status

#### Alerts

- Alert lifecycle
- Risk/confidence/visibility
- Evidence
- Acknowledge, investigate, resolve, dismiss
- Notification controls

#### Investigations

- Status
- Findings/alerts/entities
- Evidence timeline
- Questions and annotations
- Decisions/authorizations
- Final disposition

#### Security Graph

- Provenance-aware nodes and edges
- Time filtering
- Evidence inspection
- Observed/derived/possible/unknown styling

#### History / Time Machine

- Before/after comparison
- Finding/score history
- Exposure, software, firewall, baseline, alert, and investigation history

#### Reports

- Generate, view, export, verify, compare
- Schema/version display
- Export privacy warnings

#### Assistant

- Deterministic/provider mode indicator
- Text conversation
- Evidence citations
- Voice controls
- Capability/approval cards
- Local/cloud/privacy status

#### Settings / Privacy / Diagnostics

- Versioned settings
- Provider/secret configuration
- Retention
- Notifications
- Voice
- External network use
- Health checks
- Support bundles
- Recovery guidance

### Onboarding

1. Welcome and boundaries
2. Supported-platform check
3. Local/cloud choices
4. Storage location
5. Assessment scope
6. Privilege explanation
7. Notifications
8. Monitoring schedule
9. Voice setup
10. Optional provider setup and consent
11. Initial assessment
12. Results and limitations tour

Provider setup may be skipped. Skipping it leaves deterministic assistance operational.

### UI states

- Empty
- Loading
- Progress
- Partial
- Incomplete
- Permission-limited
- Unsupported
- Stale
- Error
- Offline
- Provider unavailable
- Healthy

### Accessibility

- Keyboard navigation
- Screen-reader semantics
- Visible focus
- Scalable text
- High contrast
- No color-only meaning
- Reduced motion
- Voice transcript/text equivalents
- WCAG 2.2 AA-equivalent desktop target

### Visual identity

- Calm “night watch” design language
- Deep neutral foundation
- Operational cyan/teal accents
- Standardized severity colors
- Light and dark themes
- Evidence and visibility styling distinct from severity
- Minimal decorative animation
- Professional rather than militarized or alarmist

Final brand assets remain an owner decision.

---

## 18. Investigations and Authorization

### Basic investigations

Users can:

- Create an investigation from a finding or alert
- Attach related findings, alerts, graph entities, and reports
- Add typed annotations
- Review evidence and decision timelines
- Record investigation questions
- Pause, resume, complete, or cancel
- Record final disposition
- Export a sanitized summary

### Authorization contract

Every approval-controlled capability requires:

- System ID
- Capability ID and version
- Exact target scope
- Parameter digest
- Proposal ID
- Actor
- Decision
- Issued/expiry times
- One-time/reuse policy
- Expected side effects
- Privacy classification
- Audit outcome

The assistant cannot issue or infer approval.

### Privilege model

Frozen requirements:

- GUI unprivileged
- Assistant unprivileged
- Privileged work narrowly scoped
- Fixed-purpose protocol
- Explicit authorization where required
- No generic privileged command execution
- No long-lived unrestricted privileged service unless separately justified
- No plaintext stored privileged credential
- Auditable privilege boundary
- Fail-closed behavior

- `WINDOWS PRIVILEGE BROKER DESIGN = ADR REQUIRED`
- `LINUX PRIVILEGE BROKER DESIGN = ADR REQUIRED`

No specific broker technology is mandated here.

CORE 1.0 does not require automated host remediation.

---

## 19. Deception / Honeypots

No honeypot runtime is required for CORE 1.0.

### 1.x candidate: Local Honeypot Lab

Only if it has:

- Explicit authorization
- Strong isolation
- Port/resource collision checks
- Explicit exposure choice
- Fixed approved fake services
- No real credentials or sensitive files
- Hostile-input-safe telemetry
- Resource/time limits
- Reliable teardown
- Recovery guidance
- Evidence provenance
- Alert integration
- No autonomous Internet exposure

Honey credentials, fake shares/hosts, high interaction, broad deception networks, and adaptive deception are deferred.

---

## 20. Purple-Team / Training Foundation

CORE 1.0 includes only safe foundations:

- Detection-rule fixture testing
- Offline synthetic/sanitized event replay
- Authorization contracts for future active validation
- Scope and target models
- Audit records
- Training explanations that do not modify or probe the host

Not CORE:

- Autonomous attack execution
- Exploit execution
- Credential simulation
- Network probing
- Continuous autonomous purple-team loops

Cyber Range/Training Mode is a `1.x` candidate. Autonomous Purple-Team Loop is `2.0 / RESEARCH`.

---

## 21. Application Architecture

```text
Platform Collectors / Narrow Privileged Brokers
                       ↓
       Normalization and Versioned Contracts
                       ↓
       Deterministic Security Reasoning
                       ↓
         Local Telemetry and Detection
                       ↓
Reports / Events / Memory / Provenance Graph
                       ↓
 Application-Service and Use-Case Boundary
                       ↓
 Jobs / Authorization / Notifications / Privacy
          ↙                  ↓                 ↘
 Provider Gateway       Watchtower View        Voice
          ↘                  ↓                 ↙
         Assistant Orchestration and Grounding
```

### Rules

- OS-specific code ends at collection/normalization.
- Privileged work uses fixed-purpose protocols and bounded lifetimes.
- The application service owns database access and transactions.
- GUI, voice, and assistant consume versioned DTOs.
- Background jobs own lifecycle, progress, cancellation, timeouts, and recovery.
- Deterministic reasoning creates authoritative conclusions.
- External models receive only privacy-approved DTOs.
- Notifications receive privacy-filtered summaries.
- Schemas and APIs are versioned.
- No generic local network API is exposed by default.

`APPLICATION-SERVICE API = IMPLEMENTATION CONTRACT REQUIRED`

---

## 22. Data / Storage

### Storage roles

- Canonical assessment reports
- Versioned normalized observation snapshots
- Local operational SQLite database or approved equivalent
- Local event and alert store
- Provenance graph
- Investigation and audit records
- Versioned configuration
- Secure secrets outside general application databases

### Requirements

- Report schema 1.7 remains readable.
- Memory schema 8 remains migratable.
- New schemas use forward-only checksummed migrations.
- Failed migration leaves the previous store recoverable.
- Database ownership belongs to the application service.
- Raw sensitive telemetry is minimized and separately controlled.
- Durable records include system identity, time, provenance, and schema version.
- Exports disclose coverage and provenance.
- Deletion distinguishes canonical evidence, derived indexes, and audit obligations.
- Backup/restore is explicit and integrity-checked.
- Storage growth is visible.

A dedicated graph database is not required.

---

## 23. Configuration / Secrets

### Configuration

- Versioned schema
- Safe defaults
- Atomic writes
- Validation before activation
- Migration and rollback
- Privacy and privilege descriptions
- Export/import without secrets
- No environment-variable-only production configuration

### Secrets

- Platform-supported secure secret storage
- No plaintext API keys in config, logs, reports, SQLite, support bundles, or diagnostics
- Provider disconnect and key deletion
- Secret-use audit without secret value
- External provider remains disabled when secure storage is unavailable

Exact platform mechanisms are implementation decisions, not frozen here.

---

## 24. Logging / Diagnostics

### Operational logging

Logs must be:

- Structured
- Local
- Rotated and bounded
- Privacy-safe
- Correlated with request/job IDs
- Separate from authoritative security evidence
- Free of raw secrets
- Free of raw firewall output
- Free of arbitrary raw command lines
- Free of raw provider prompts/responses by default

### Diagnostics

CORE diagnostics include:

- Application/schema versions
- Collector availability
- Last success/failure per domain
- Monitoring/job health
- Database integrity
- Configuration validity
- Update/signature state
- Provider and voice health without secrets
- Storage/resource warnings
- Privilege-broker health

### Support bundles

- Preview before creation
- Redacted
- Secrets excluded
- Raw telemetry excluded by default
- Explicitly generated
- Manifested and integrity-digested
- Never automatically uploaded

---

## 25. Packaging / Installation / Updates

### Windows

- Installer and uninstaller
- Start Menu shortcut
- Optional desktop shortcut
- Per-user installation by default where feasible
- Explicit elevation only for narrowly required components
- Documented application-data locations
- Upgrade preserving data/configuration
- Repair/uninstall behavior
- Unprivileged GUI

### Linux

- Supported signed package for Ubuntu LTS and Debian stable
- Desktop entry and launcher
- Unprivileged application process
- Narrow privilege broker chosen by ADR
- XDG-compliant config/data/cache/log locations
- Upgrade preserving data/configuration
- Documented CLI availability

Additional package families are `1.x`.

### Both

- Coherent semantic product version
- Verifiable/reproducible build process
- Checksums
- SBOM
- Release manifest
- Signed/verifiable artifacts
- Signature verification before update
- Explicit update consent
- Rollback/recovery
- Clean-machine install, upgrade, rollback, and uninstall tests

### Signing boundary

Product requirement:

- CyberWatchtower supports signed and verifiable releases.
- Public artifacts must be verifiable.
- Update content must be integrity-checked.

Owner/operational requirement:

- Real signing credentials and protected custody must exist before public release.
- Private signing material must never be embedded in the repository.

`SIGNING CERTIFICATE / KEY CUSTODY = OWNER RELEASE DECISION REQUIRED`

Automatic unattended updates are not required. Integrity-verified update checks and user-directed upgrades are required.

---

## 26. Security and Privacy Requirements

- GUI and assistant run without administrative privilege.
- Elevation is bounded to exact operations.
- Collectors use fixed-purpose APIs/argv, `shell=False`, timeouts, bounds, trusted executable resolution, and cleanup.
- No generic privileged command execution.
- No namespace traversal without a future explicit contract.
- Collection follows minimization and purpose limitation.
- Secrets use secure storage.
- External AI is off by default.
- No silent analytics or cloud telemetry.
- Retention is visible and user-controlled.
- Deletion is previewed, authorized, and audited.
- Consequential capabilities require exact authorization.
- Audit records are append-oriented and tamper-evident.
- Updates, detections, and vulnerability content are integrity-verified.
- Network behavior is visible.
- Security operation remains meaningful offline.
- Safe errors exclude secrets, raw evidence, command lines, and provider payloads.
- Partial failure cannot become false completeness.
- AI, voice, logs, diagnostics, and notifications use the same privacy-classification system.
- Provider failure cannot alter authoritative local state.

---

## 27. Performance and Reliability

Numerical targets require measurement and are `TBD-BENCHMARK`.

| Area | Requirement |
|---|---|
| Startup | Interactive GUI becomes usable promptly; target `TBD-BENCHMARK`. |
| Cached state | Prior state renders before a new assessment finishes. |
| Progress | Long operations expose current stage and do not freeze the GUI. |
| Cancellation | Bounded, tested, and safely reaps collectors/helpers. |
| Timeouts | Explicit per operation; frozen native bounds preserved. |
| Memory/CPU | Appropriate for desktop monitoring; targets `TBD-BENCHMARK`. |
| Database growth | Measured, visible, and retention-controlled. |
| Long-running use | Multi-day testing finds no unbounded growth/deadlock. |
| Restart recovery | Interrupted jobs become cancelled/failed, never false success. |
| Crash containment | Collector, provider, voice, and helper failures do not crash the GUI or corrupt records. |
| Partial failure | Healthy domains remain usable with explicit limitations. |
| Offline security | Assessment, findings, exposure, monitoring, built-in detections, alerts, history, graph, evidence, Time Machine, reports, deterministic assistant, local GUI/configuration/diagnostics remain usable. |
| Provider outage | Enhanced conversation degrades to deterministic assistance. |
| Voice failure | Text operation remains available; security operation continues. |
| Update failure | Previous version/data remains recoverable. |
| Corruption | Detected, isolated, and accompanied by safe recovery guidance. |

Full generative conversation is not required offline. Provider availability is not a security-engine dependency and provider uptime is not a release criterion.

---

## 28. Testing and Release Quality

### Required test layers

- Unit tests
- Integration tests
- Platform-contract tests
- Report/API/event/config/schema compatibility
- Migration and rollback tests
- Failure injection
- Privacy and secret-canary tests
- Authorization and audit tests
- Native Windows validation
- Native Linux validation
- Guarded `CYBERWATCHTOWER_VALIDATE_NATIVE_LINUX` test
- GUI component/workflow tests
- Accessibility tests
- Installer/uninstaller tests
- Upgrade/rollback tests
- Clean-machine tests
- Long-running monitoring tests
- Performance/resource tests
- Assistant grounding tests
- Production provider integration/contract tests
- Provider-unavailable fallback tests
- Prompt-injection/adversarial-content tests
- AI Privacy Firewall tests
- Voice privacy/offline/fallback tests
- Update/signature/SBOM tests

### Release blockers

- False observed fact
- False `COMPLETE`
- False firewall `BLOCK` or `ALLOW`
- Firewall-derived `CONFIRMED_REACHABLE`
- Cross-system evidence contamination
- Untraceable authoritative conclusion
- Unauthorized privilege or consequential action
- Secret/raw-sensitive-data leak
- External transmission without consent
- Privileged GUI or unsafe broker
- Broken install/upgrade/uninstall
- Data loss or unrecoverable migration
- Unsupported platform presented as supported
- Critical/high security defect
- Failed native validation on an officially supported environment
- Missing production conversational provider path
- Broken deterministic provider fallback
- Release-blocking voice failure on a supported platform
- Accessibility failure preventing core operation
- Unbounded monitoring growth
- Unsigned/unverifiable public release artifact

Cloud-provider uptime is not a release blocker.

---

## 29. Feature Matrix

| ID | Feature | Category | Type | Current state | 1.0 requirement | Scope tier | Dependencies/decisions | Acceptance summary | Evidence/current implementation |
|---|---|---|---|---|---|---|---|---|---|
| PLAT-01 | Windows 11 x64 support | Platform | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Native qualification | Clean-machine supported product | Windows adapter/native collectors |
| PLAT-02 | Ubuntu LTS x86_64 support | Platform | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Package/native qualification | Exact release version qualified | Linux adapter, Ubuntu CI |
| PLAT-03 | Debian stable x86_64 support | Platform | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Package/native qualification | Exact release version qualified | Linux architecture exists |
| PLAT-04 | Kali Rolling x86_64 validation | Platform | FOUNDATIONAL INFRASTRUCTURE | DONE | REQUIRED | CORE 1.0 | Engineering qualification | Advanced/developer target, not consumer guarantee | Linux L5 on Kali |
| PLAT-05 | Windows ARM64 | Platform | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Platform qualification | Native/package support | Architecture enum only |
| PLAT-06 | Additional Linux distributions | Platform | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Package strategy | Explicit qualified matrix | None |
| PLAT-07 | macOS | Platform | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 2.0 / RESEARCH | New adapter/native evidence | Fail closed until implemented | Unsupported-platform handling |
| ENG-01 | System inventory | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Platform collectors | Versioned host DTO/freshness | `SystemObservation` |
| ENG-02 | Identity/user context | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | System inventory | Stable system ID, bounded context | `system_identity.py` |
| ENG-03 | TCP/UDP IPv4/IPv6 listeners | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Network collectors | Complete/partial bindings | Linux/Windows collectors |
| ENG-04 | Process intelligence | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Listener collection | Privacy-safe attribution | `process_intelligence.py` |
| ENG-05 | Application identity | Security engine | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Process inventory | Stable identity where provable | Linux enrichment/Windows digests |
| ENG-06 | Service identity | Security engine | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Process/service collectors | Bounded equivalent attribution | Service catalog/Windows services |
| ENG-07 | Installed software inventory | Security engine | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Platform collectors | Trusted identity/version inventory | None |
| ENG-08 | Firewall posture | Security engine | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Platform collectors | Explicit platform semantics | Windows profiles/Linux posture |
| ENG-09 | Firewall rule collection | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Privilege broker ADRs | Trusted bounded read-only collection | Windows COM/Linux nft |
| ENG-10 | Rule applicability | Security engine | WATCHTOWER DIFFERENTIATOR | DONE | REQUIRED | CORE 1.0 | Rules/listeners | Same-subject provenance | Frozen L2/L4 |
| ENG-11 | Effective network exposure | Security engine | WATCHTOWER DIFFERENTIATOR | DONE | REQUIRED | CORE 1.0 | ENG-03/10 | No reachability overclaim | Frozen implementation |
| ENG-12 | Coverage/completeness | Security engine | WATCHTOWER DIFFERENTIATOR | DONE | REQUIRED | CORE 1.0 | All collectors | Independent domain coverage | Report contracts |
| ENG-13 | Findings/stable identity | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Reasoning | Stable IDs/lifecycle | Findings and memory |
| ENG-14 | Severity/risk score | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Findings | Preserve versioned semantics | Scoring v2 |
| ENG-15 | Recommendations | Security engine | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Findings | Deterministic recommendations | Advisor/findings |
| ENG-16 | Reports | Reporting | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Schemas | View/export/compare/provenance | Report 1.7 |
| ENG-17 | History/change/trends | History | INDUSTRY BASELINE | DONE | REQUIRED | CORE 1.0 | Reports/memory | Coverage-aware lifecycle | History/intelligence |
| ENG-18 | Behavioral baseline/drift | Security engine | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | Monitoring/inventory | Approved versions/deviations | Memory baselines |
| ENG-19 | Vulnerability context | Security engine | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Vulnerability-source ADR | Provenance/freshness/uncertainty | None |
| ENG-20 | Vulnerability/exposure correlation | Security engine | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | ENG-07/11/19, graph | No version/port-only proof | None |
| MON-01 | Background jobs | Monitoring | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Job contract | Progress/cancel/recovery | None |
| MON-02 | Scheduled assessments | Monitoring | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | MON-01/config | Daily/weekly/explicit startup | None |
| MON-03 | Normalized local event schema | Local SOC | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Event contract | Versioned provenance DTO | None |
| MON-04 | Windows local telemetry | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Windows allowlist contract | Bounded reviewed sources | None |
| MON-05 | Linux local telemetry | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Linux allowlist contract | Bounded reviewed sources | None |
| MON-06 | Detection engine/rules | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Rule-format contract | Versioned deterministic rules | None |
| MON-07 | Alerts/lifecycle | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | MON-06/graph | Evidence-backed states | None |
| MON-08 | Local notifications | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Alerts/privacy | Native/in-app/quiet hours | None |
| MON-09 | Basic local correlation | Local SOC | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Events/graph | Time/entity/evidence correlation | None |
| MON-10 | Retention controls | Data | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Retention config decision | Growth, dry-run, authorization | Memory retention |
| SIEM-01 | Local event storage/search | SIEM | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Storage/index ADR | Structured bounded sanitized search | None |
| SIEM-02 | ATT&CK mapping | SIEM | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Detection knowledge | Curated mapping, not proof | `technique_id` scaffold |
| SIEM-03 | Basic incidents/investigations | SIEM | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Alerts/graph/UI | Evidence-backed investigation flow | Memory investigations |
| SIEM-04 | Centralized telemetry | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Fleet architecture | Multi-host ingestion | None |
| SIEM-05 | Network-device telemetry | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Event ingestion | Reviewed device sources | None |
| SIEM-06 | Sigma compatibility | SIEM | INDUSTRY BASELINE | NOT BUILT | OPTIONAL | 1.x | Detection model | Safe supported subset | None |
| SIEM-07 | IOC/threat intelligence | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Knowledge/update trust | Provenance/freshness/matching | None |
| SIEM-08 | Entity risk | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Graph/correlation | Evidence-backed entity score | None |
| SIEM-09 | Hunting/retro-hunting | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Event query/rules | Saved and historical hunts | None |
| SIEM-10 | Detection engineering | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Rule APIs | Draft/test/version/publish | None |
| SIEM-11 | UEBA | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Behavioral corpus | Explainable analytics | None |
| SIEM-12 | Enterprise SOAR | SIEM | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Actions/fleet/auth | Safe playbooks | None |
| DIF-01 | Local Security Graph | Differentiator | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | Graph contract/storage | One-system provenance graph | None |
| DIF-02 | Evidence Chain | Differentiator | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | Evidence/graph | Universal why-believe view | Core evidence/grounding |
| DIF-03 | Local Attack Story | Differentiator | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | Graph/events/alerts | Deterministic bounded stories | None |
| DIF-04 | Confidence Engine | Differentiator | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | Score/confidence/coverage | Three independent concepts | Existing primitives |
| DIF-05 | Security Time Machine | Differentiator | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | History/graph/monitoring | Before/after/evidence history | Reports/memory |
| DIF-06 | Behavioral Digital Twin | Differentiator | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 1.x | Baseline/graph | Richer evolving model | None |
| DIF-07 | Predictive attack paths | Differentiator | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Fleet graph | Evidence-bounded predictions | None |
| DIF-08 | Cryptographic evidence attestation | Differentiator | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Key infrastructure | Signed evidence chains | Digests only |
| AI-01 | Two-layer Watchtower Assistant | Assistant | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | App service/evidence/GUI | Deterministic plus enhanced layers | Advisor/Core |
| AI-02 | Deterministic assistant | Assistant | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | Existing Core expansion | Always available locally | Current bounded intents |
| AI-03 | Enhanced conversational assistant | Assistant | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | AI-05/06 | Grounded multi-turn synthesis | None |
| AI-04 | Deterministic fact boundary | Assistant | FOUNDATIONAL INFRASTRUCTURE | DONE | REQUIRED | CORE 1.0 | Evidence/grounding | Model cannot author facts | Existing grounding |
| AI-05 | AI Privacy Firewall | Privacy | WATCHTOWER DIFFERENTIATOR | PARTIAL | REQUIRED | CORE 1.0 | Classification/secrets | Allowlist/redaction/consent/audit | DTO/sanitization primitives |
| AI-06 | Provider-neutral production model capability | Assistant | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Provider ADR, secrets, AI-05 | At least one opt-in qualified path; grounded, audited, fallback | Protocols only |
| AI-07 | Local model provider | Assistant | WATCHTOWER DIFFERENTIATOR | NOT BUILT | OPTIONAL | 1.x | Resource/model strategy | Optional safe local enhancement | None |
| AI-08 | Capability/authorization interface | Assistant | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | App API/auth | Exact proposals/approval/audit | Registry/envelopes |
| AI-09 | Multi-agent investigations | Assistant | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Mature cases/actions | Bounded cooperating agents | None |
| VOI-01 | Push-to-talk voice | Voice | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | Voice ADR/GUI/privacy | Release-blocking, visible, text fallback | None |
| VOI-02 | Offline STT/TTS | Voice | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | Voice ADR | Release-blocking local path | None |
| VOI-03 | Wake word/always listening | Voice | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Mature privacy | Explicit opt-in if ever built | None |
| UX-01 | Watchtower View shell | GUI | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | GUI ADR/app API | Production desktop GUI | CLI only |
| UX-02 | Required product views | GUI | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | UX-01/DTOs | Complete navigation/states | None |
| UX-03 | Graph/Time Machine views | GUI | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | DIF-01/05 | Provenance/history visualization | None |
| UX-04 | Assistant/voice UI | GUI | WATCHTOWER DIFFERENTIATOR | NOT BUILT | REQUIRED | CORE 1.0 | AI/voice | Mode/privacy/evidence visible | None |
| UX-05 | Accessibility/themes | GUI | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Design system | Keyboard/screen reader/contrast | None |
| UX-06 | First-run onboarding | Product | INDUSTRY BASELINE | NOT BUILT | REQUIRED | CORE 1.0 | Config/jobs/privacy | Complete setup with optional provider | None |
| INV-01 | Basic investigations | Investigation | INDUSTRY BASELINE | PARTIAL | REQUIRED | CORE 1.0 | Alerts/evidence/UI | Status/evidence/annotations/timeline | Memory records |
| INV-02 | Approval-gated remediation | Response | INDUSTRY BASELINE | NOT BUILT | DEFERRED | 1.x | Broker/auth/actions | Fixed safe action set | Envelopes only |
| HNY-01 | Local Honeypot Lab | Deception | WATCHTOWER DIFFERENTIATOR | NOT BUILT | OPTIONAL | 1.x | Isolation/telemetry | Bounded opt-in preview | None |
| HNY-02 | Deception Network | Deception | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Fleet/isolation | Broad managed deception | None |
| PUR-01 | Detection fixture/replay testing | Purple team | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Event/rule contracts | Synthetic offline validation | Current tests are not runtime replay |
| PUR-02 | Cyber Range/Training Mode | Purple team | WATCHTOWER DIFFERENTIATOR | NOT BUILT | OPTIONAL | 1.x | PUR-01/isolation | Guided safe training | None |
| PUR-03 | Autonomous Purple-Team Loop | Purple team | WATCHTOWER DIFFERENTIATOR | NOT BUILT | DEFERRED | 2.0 / RESEARCH | Mature range/actions | Explicit scoped active validation | None |
| ARC-01 | Application-service boundary | Architecture | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | API contract | Sole GUI/assistant boundary | Direct CLI orchestration today |
| ARC-02 | Background job/cancellation system | Architecture | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Job contract | Transaction-safe jobs | None |
| ARC-03 | Versioned configuration | Operations | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | App service | Atomic validation/migration | CLI/env only |
| ARC-04 | Secure secrets | Operations | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Platform secret-store design | No plaintext credentials | None |
| ARC-05 | Operational logging | Operations | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Privacy classification | Bounded structured logs | None |
| ARC-06 | Diagnostics/support bundle | Operations | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Logging/health | Redacted previewable bundle | Memory diagnostics only |
| ARC-07 | Backup/recovery | Operations | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Storage/migrations | Integrity-checked recovery | Manual guidance |
| ARC-08 | Privilege brokers | Security | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Windows/Linux ADRs | Fixed-purpose authorized brokers | Current collectors rely on caller privilege |
| ARC-09 | Installers/packages | Release | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | GUI/build/signing | Official clean-machine artifacts | Editable pip only |
| ARC-10 | Signing/SBOM | Release | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | Owner key-custody decision | Verifiable artifacts/content | None |
| ARC-11 | Secure update/rollback | Release | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | ARC-10 | Explicit verified upgrade/recovery | None |
| QA-01 | Portable test suite | Quality | FOUNDATIONAL INFRASTRUCTURE | DONE | REQUIRED | CORE 1.0 | All workstreams | Zero release failures | Existing test organization |
| QA-02 | Native Windows qualification | Quality | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Supported matrix | Guarded clean-host validation | Existing limited native evidence |
| QA-03 | Native Linux qualification | Quality | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Supported matrix | Guarded Linux test plus clean-host runs | L5 validated; guard missing |
| QA-04 | GUI/installer/upgrade tests | Quality | FOUNDATIONAL INFRASTRUCTURE | NOT BUILT | REQUIRED | CORE 1.0 | GUI/packaging | Automated clean-machine workflows | None |
| QA-05 | Long-run/performance/security tests | Quality | FOUNDATIONAL INFRASTRUCTURE | PARTIAL | REQUIRED | CORE 1.0 | Monitoring/AI/voice | Resource/adversarial/privacy gates | Boundary tests, no long-run suite |

---

## 30. Implementation Workstreams

### WS1 — Application-service and contracts

- Objective: establish the sole supported use-case API.
- Dependencies: frozen platform/report/memory contracts.
- Deliverables: versioned DTOs, typed errors, service ownership, API contract, job interfaces.
- Acceptance: GUI and assistant need no direct collector or database access.
- Constraints: preserve provenance and uncertainty.

### WS2 — Platform maturity and inventory

- Objective: qualify supported platforms and complete software/application/service inventory.
- Dependencies: WS1.
- Deliverables: platform conformance, installed software, native qualification, Linux guard.
- Acceptance: official support matrix passes clean-host validation.
- Constraints: fixed-purpose collection and no false completeness.

### WS3 — Vulnerability knowledge and exposure correlation

- Objective: add trusted vulnerability context.
- Dependencies: WS2 inventory, WS6 graph identity, update-integrity components from WS12.
- Deliverables: knowledge adapter, applicability, freshness, rollback, correlation.
- Acceptance: no version-only or port-only confirmation.
- Constraints: external knowledge never becomes observed host fact.

### WS4 — Local telemetry and deterministic detections

- Objective: establish the bounded local SOC event foundation.
- Dependencies: WS1, early WS11 configuration/logging, event/rule contracts.
- Deliverables: event schema, Windows/Linux sources, local store/search, rule engine, ATT&CK metadata.
- Acceptance: provenance, privacy, failure, and rule-fixture gates.
- Constraints: reviewed allowlists and bounded retention.

### WS5 — Monitoring, jobs, alerts, notifications

- Objective: scheduled operation and alert lifecycle.
- Dependencies: WS1, WS4.
- Deliverables: scheduler, job execution, cancellation, alerts, notifications.
- Acceptance: restart, cancellation, long-run, and privacy qualification.
- Constraints: no stored privileged credentials.

### WS6 — Graph, Evidence Chain, confidence

- Objective: implement the primary Watchtower differentiators.
- Dependencies: WS1, WS2 inventory, WS4 event identity.
- Deliverables: graph contract/store, evidence traversal, confidence model.
- Acceptance: every edge/conclusion is traceable.
- Constraints: no model-created authoritative relationship.

### WS7 — Baseline, Time Machine, investigations

- Objective: make historical change and investigation operational.
- Dependencies: WS5, WS6, memory migrations.
- Deliverables: approved baselines, deltas, timelines, investigation workflow.
- Acceptance: before/after reconstruction and coverage-aware lifecycle.
- Constraints: user decisions never rewrite evidence.

### WS8 — AI Privacy Firewall and Assistant

- Objective: deliver deterministic and provider-enhanced assistance.
- Dependencies: WS1, early WS11 secrets/config, WS6/7 evidence, provider ADR.
- Deliverables: classification/redaction, provider gateway, grounding, two assistant layers.
- Acceptance: one qualified production provider path plus deterministic fallback.
- Constraints: no external raw telemetry, no arbitrary execution.

### WS9 — Voice

- Objective: add release-blocking push-to-talk voice.
- Dependencies: WS8, WS10 shell, WS11 configuration/privacy, voice ADR.
- Deliverables: offline STT/TTS adapters, controls, indicators, text fallback.
- Acceptance: supported-platform offline voice/privacy/failure tests.
- Constraints: no always-listening or default audio retention.

### WS10 — Watchtower View

- Objective: deliver the complete desktop surface.
- Dependencies: WS1 contracts; feature views integrate incrementally as WS2–WS8 mature.
- Deliverables: shell, onboarding, required views, design system, accessibility.
- Acceptance: end-to-end workflows and accessibility qualification.
- Constraints: no database, collector, or authority logic.

### WS11 — Configuration, secrets, logging, diagnostics

- Objective: provide operational foundations early.
- Dependencies: WS1 ownership boundaries.
- Deliverables: versioned configuration, secure secrets, safe logs, health checks, support bundle.
- Acceptance: secret-canary and corruption/recovery tests.
- Constraints: no sensitive diagnostic leakage.

### WS12 — Packaging, signing, updates

- Objective: produce trustworthy installable artifacts.
- Dependencies: stable GUI/service architecture; can develop build infrastructure earlier.
- Deliverables: Windows installer, Linux package, SBOM, signing, update/rollback.
- Acceptance: clean-machine install/upgrade/rollback/uninstall.
- Constraints: protected signing credentials and unprivileged GUI.

### WS13 — Release qualification

- Objective: prove the integrated product.
- Dependencies: all required workstreams.
- Deliverables: native validation, provider qualification, voice qualification, long-run tests, benchmarks, threat-model closure.
- Acceptance: Definition of Done and zero release blockers.
- Constraints: no waiver for false facts, privacy leaks, unsafe privilege, or data loss.

### Critical path

```text
WS1 application-service/contracts
→ early WS11 config/logging/secrets
→ WS2 platform inventory maturity
→ WS4 telemetry/event foundation
→ WS5 monitoring/alerts
→ WS6 graph/evidence/confidence
→ WS7 history/investigations
→ WS3 vulnerability correlation
→ WS8 privacy/assistant/provider
→ WS10 integrated GUI
→ WS9 voice
→ WS12 final packaging/update integration
→ WS13 qualification
```

### Parallelizable work

- WS11 foundations can proceed after service ownership is established.
- WS12 build/signing infrastructure can begin before final GUI completion.
- WS3 knowledge-format research can proceed while telemetry and graph work mature.
- WS10 shell/design/accessibility can proceed after the GUI ADR and initial service API.
- WS8 AI Privacy Firewall design can proceed alongside graph/evidence work.
- WS9 engine evaluation can proceed independently after the voice ADR begins.
- Native platform qualification fixtures can grow continuously.
- Detection-rule fixture work can proceed with event-contract design.

### Major dependency gates

1. Application-service API contract
2. Background-job contract
3. Event/rule/graph schema contracts
4. Configuration and secure-secret foundation
5. Supported-platform inventory identity
6. Privilege-broker ADRs
7. Vulnerability-source ADR
8. Production-provider ADR
9. GUI ADR
10. Voice-engine ADR
11. Signing/key-custody readiness
12. Integrated clean-machine qualification

---

## 31. Out-of-Scope Register

### 1.x

- Windows ARM64
- Additional Linux distributions/package families
- Centralized multi-host telemetry
- Network/security-device telemetry
- Sigma compatibility
- IOC matching
- Threat-intelligence feeds
- Entity risk
- Threat hunting and retro-hunting
- Detection-engineering UI
- Advanced correlation
- Optional local model provider
- Approval-gated fixed remediation
- Local Honeypot Lab
- Cyber Range/Training Mode
- Full evidence replay
- Behavioral Digital Twin expansion
- Email/webhook/mobile notifications

### 2.0 / RESEARCH

- Enterprise fleet scale
- Full UEBA
- Multi-agent autonomous investigations
- Autonomous Purple-Team Loop
- Broad deception network
- Security Genome
- Predictive attack paths
- Cryptographic evidence attestation
- Wake-word/always-listening voice
- Enterprise SOAR
- Autonomous remediation
- Campaign or threat-actor attribution
- Fleet-wide campaign reconstruction
- macOS

---

## 32. Definition of Done

CyberWatchtower 1.0 is complete only when every required CORE 1.0 acceptance gate is met.

### Product checklist

- [ ] Signed Windows installer works on clean Windows 11 x64.
- [ ] Signed Linux packages work on qualified Ubuntu LTS and Debian stable.
- [ ] Kali advanced/developer qualification completes.
- [ ] Application launches unprivileged.
- [ ] First-run onboarding works.
- [ ] Initial assessment completes or clearly reports limitations.
- [ ] Windows native validation passes.
- [ ] Linux native validation passes.
- [ ] Guarded Linux native test exists and passes.
- [ ] System/software/network/process/application/service inventory works.
- [ ] Frozen effective-exposure semantics remain intact.
- [ ] Vulnerability knowledge is trusted, versioned, fresh/stale-aware, and rollback-capable.
- [ ] Vulnerability/exposure correlation requires proven identity linkage.
- [ ] Scheduling and background jobs work.
- [ ] Progress, cancellation, restart, and partial failure behave safely.
- [ ] Reviewed bounded Windows/Linux telemetry works.
- [ ] Built-in detections produce evidence-backed alerts.
- [ ] Alerts and local notifications work.
- [ ] Basic investigations work.
- [ ] Security Graph exposes provenance.
- [ ] Attack Story remains local, bounded, and deterministic.
- [ ] Required epistemic states are enforced.
- [ ] “Why does CyberWatchtower believe this?” works for important conclusions.
- [ ] Threat Risk, Evidence Confidence, and Visibility are independently presented.
- [ ] Behavioral baselines and deviation history work.
- [ ] Time Machine reconstructs supported before/after state.
- [ ] Reports generate, display, compare, export, and verify.
- [ ] Deterministic Assistant works locally without a provider.
- [ ] At least one provider-neutral production conversational model path is implemented and qualified.
- [ ] External AI is disabled by default and explicitly enabled.
- [ ] AI Privacy Firewall fails closed.
- [ ] Provider failure falls back to deterministic assistance.
- [ ] Security operation remains meaningful when the provider is disabled, unconfigured, offline, or unavailable.
- [ ] Provider availability cannot modify authoritative local state.
- [ ] Push-to-talk offline STT/TTS works on supported platforms.
- [ ] Voice failure falls back to text and does not block security operation.
- [ ] Local/cloud AI and voice status is visible.
- [ ] Secrets use supported secure storage.
- [ ] Configuration, logging, diagnostics, and support bundles work.
- [ ] Retention/deletion is visible, previewed, authorized, and audited.
- [ ] Every required GUI view and state works.
- [ ] GUI does not access collectors or SQLite directly.
- [ ] Accessibility gate passes.
- [ ] Offline security operation is meaningful.
- [ ] Upgrade and rollback preserve data.
- [ ] SBOM, checksums, signatures, and release manifest are produced.
- [ ] Clean-machine install, upgrade, rollback, and uninstall pass.
- [ ] Long-running monitoring and performance gates pass.
- [ ] No release-blocking security, privacy, authority, integrity, or data-loss defect remains.

“Backend complete” or “scanner complete” cannot satisfy this checklist. Cloud-provider uptime is not a release requirement.

---

## 33. Owner / Architecture Decision Register

### Frozen product decisions

| Decision | Frozen outcome |
|---|---|
| Official Windows target | Windows 11 x64 |
| Official Linux targets | Current Ubuntu LTS x86_64 and current Debian stable x86_64 |
| Advanced/developer target | Kali Rolling x86_64 |
| Windows ARM64 | 1.x |
| Additional Linux distributions | 1.x |
| macOS | 2.0 / RESEARCH |
| Push-to-talk voice | CORE 1.0, required, release-blocking |
| Wake word/always listening | Deferred |
| Conversational model capability | At least one production provider path required |
| External AI default | Disabled/off by default |
| Local model | Optional 1.x |
| Offline security operation | Required |
| Offline generative conversation | Not required |
| AI Privacy Firewall | CORE 1.0 |
| Local Security Graph | CORE 1.0 |
| Attack Story | CORE 1.0, local and deterministic |
| Enterprise SIEM | Deferred |
| Honeypot runtime | Deferred |
| Arbitrary command execution | Prohibited |
| Generic privileged execution | Prohibited |
| GUI/assistant privilege | Unprivileged |
| Deterministic security authority | Permanent product invariant |

### ADR required before implementation

| ADR | Required decision scope |
|---|---|
| GUI technology | Framework/runtime, packaging, accessibility, resource use, update compatibility |
| Voice engines | Offline STT/TTS, license, package size, performance, quality, platform parity |
| Windows privilege broker | Protocol, lifecycle, authorization, installation, audit, attack surface |
| Linux privilege broker | Protocol, lifecycle, authorization, installation, audit, attack surface |
| Vulnerability knowledge source/update | Source, license, format, signing, freshness, rollback |
| Production model-provider implementation | Provider-neutral gateway plus at least one qualified implementation |
| Event storage/index strategy | SQLite/relational/other local approach, indexes, retention, migration |
| Signing/build strategy | Artifact types, signing workflow, reproducibility, verification |

### Implementation contracts required

| Contract | Required before |
|---|---|
| Application-service API | GUI, assistant, automation construction |
| Background-job contract | Scheduler/monitoring construction |
| Event schema | Event collectors |
| Windows event allowlist | Windows telemetry collector |
| Linux event allowlist | Linux telemetry collector |
| Detection rule format | Detection engine/rule authoring |
| Graph schema | Graph persistence and visualization |
| Provider DTOs/purpose allowlists | External provider integration |
| Privileged-helper protocols | Privileged collector integration |

### Product configuration decisions before release

- Default retention values
- Supported retention windows
- Quiet-hour defaults
- Notification defaults
- Update-check defaults
- External AI defaults beyond “off”
- Provider request/consent defaults
- Voice defaults
- Spoken-alert defaults
- Raw local event retention defaults
- Support-bundle inclusion defaults

### Owner release/brand decisions

- Final assistant name
- Final visual brand assets
- Signing certificate/key custody
- Public distribution endpoints
- Public update endpoints
- Release-channel ownership
- Vulnerability-content distribution endpoint
- Support/contact and disclosure information

---

## Final Review Conclusions

### A. Corrections from owner review

1. Made a real provider-neutral production conversational model path `CORE 1.0 / REQUIRED`.
2. Kept local model support `1.x / OPTIONAL`.
3. Split assistant behavior into deterministic local Layer A and enhanced provider-backed Layer B.
4. Corrected offline language: offline security operation is required; offline generative conversation is not.
5. Required deterministic assistant fallback when the provider is disabled or unavailable.
6. Made push-to-talk and offline STT/TTS explicitly release-blocking.
7. Added the voice-engine ADR and prohibited premature engine selection.
8. Froze Windows 11, Ubuntu LTS, and Debian stable as official targets.
9. Reclassified Kali as an advanced/developer validation target.
10. Kept Windows ARM64, additional Linux distributions, and macOS deferred.
11. Removed any implied GUI-framework decision and added the GUI ADR.
12. Made Windows/Linux privilege-broker designs technology-neutral ADRs.
13. Added vulnerability-source/update ADR requirements.
14. Replaced fixed telemetry-source assumptions with reviewed Windows/Linux allowlist contracts.
15. Replaced invented retention durations with benchmark-driven configuration decisions.
16. Strengthened the external AI network boundary and explicit prohibited payload list.
17. Bounded Attack Story to local deterministic evidence.
18. Bounded Security Graph to one monitored system and removed any graph-database requirement.
19. Bounded event search to structured local sanitized fields.
20. Separated product signing requirements from owner credential/key custody.
21. Made “Watchtower Assistant” a working product role rather than final branding.
22. Corrected AI-06, AI-07, VOI-01, VOI-02, and platform entries in the matrix.
23. Added the Owner / Architecture Decision Register.
24. Clarified the critical path, parallel work, and dependency gates.
25. Hardened Definition of Done around provider qualification, fallback, offline security, and voice.
26. Removed polkit or any other privilege technology as a prematurely frozen choice.

### B. Unresolved decisions

All unresolved items are intentionally classified, not contradictions:

- GUI technology
- Offline STT/TTS engines
- Windows privilege broker
- Linux privilege broker
- Vulnerability knowledge source and update mechanism
- Production model-provider implementation
- Local event storage/index strategy
- Signing/build strategy
- Windows and Linux event allowlists
- Event, detection, graph, job, and service API contracts
- Retention and notification defaults
- Final assistant name and brand assets
- Signing credential/key custody
- Public distribution/update endpoints

### C. Critical implementation path

```text
WS1 application-service/contracts
→ early WS11 config/logging/secrets
→ WS2 platform inventory maturity
→ WS4 telemetry/event foundation
→ WS5 monitoring/alerts
→ WS6 graph/evidence/confidence
→ WS7 history/investigations
→ WS3 vulnerability correlation
→ WS8 privacy/assistant/provider
→ WS10 integrated GUI
→ WS9 voice
→ WS12 packaging/update integration
→ WS13 qualification
```

### D. Parallelizable work

- Configuration/logging/secrets can begin after service ownership is established.
- Packaging/signing infrastructure can begin before final GUI completion.
- Vulnerability-format research can proceed while telemetry and graph work mature.
- GUI shell/design/accessibility can proceed after the GUI ADR and initial service API.
- AI Privacy Firewall design can proceed alongside graph/evidence work.
- Voice-engine evaluation can proceed independently after the voice ADR begins.
- Platform fixtures and native qualification can grow continuously.
- Detection-rule fixture work can proceed with event-contract design.

### E. Top five engineering risks

1. Building the application-service/job boundary without changing frozen security semantics.
2. Cross-platform event collection and privilege separation.
3. Safe evolution of report, memory, event, graph, configuration, and API schemas.
4. Reliable identity/provenance correlation across inventory, vulnerabilities, events, graph edges, and stories.
5. Integrating GUI, provider-backed conversation, offline voice, installers, updates, and long-running monitoring into one supportable release.

### F. Top five security/privacy risks

1. Privileged-broker compromise or excessive privilege scope.
2. Leakage of logs, host data, credentials, transcripts, audio, or reports to providers or diagnostics.
3. Prompt injection or hostile telemetry influencing assistant claims or action proposals.
4. Supply-chain compromise through installers, updates, detection content, model integration, or vulnerability knowledge.
5. Authorization, audit, evidence, or graph tampering that makes a conclusion or action appear trustworthy.

### G. Consistency audit result

Result: **PASS — no unresolved internal contradiction identified.**

Checked and reconciled:

- CORE versus 1.x
- REQUIRED versus OPTIONAL
- Offline security versus offline generative AI
- Production provider requirement versus provider-off default
- Voice release-blocking status versus text fallback
- Official support versus Kali qualification
- GUI/database/collector boundaries
- Technology-neutral privilege model
- Local graph scope
- Bounded SIEM scope
- Attack Story authority
- Vulnerability applicability authority
- Signing product requirement versus key custody
- Feature Matrix versus Definition of Done
- Workstream dependencies and critical path

The remaining ADRs, implementation contracts, configuration decisions, and owner release decisions are explicitly categorized and do not weaken the product contract.

### H. Freeze recommendation and owner decision

Recommendation: **FREEZE**

Owner decision: **APPROVED FOR FINAL FREEZE**

This document is the authoritative CyberWatchtower 1.0 product contract. It does not authorize implementation. Required early ADRs and implementation contracts must be separately reviewed and authorized before their corresponding work begins.
