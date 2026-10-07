# CyberWatchtower 1.0 WS1-F Application Assistant Contract

**Status:** FROZEN CONTRACT CANDIDATE — READY FOR OWNER REVIEW

**Phase:** WS1-F.2 — Assistant / Capability / Proposal Contract Freeze

**Parent authorities, in precedence order:**

1. `CYBERWATCHTOWER_1_0_MASTER_SPECIFICATION.md`
2. `CYBERWATCHTOWER_1_0_WS1_APPLICATION_SERVICE_CONTRACT.md`
3. This WS1-F contract

**Parent repository baseline:** `0d984c2a3f8fdaf0afe3fd1f4e91f913ae7a4844`

**Implementation authorization:** NONE

This document resolves only the WS1-F decisions deferred by the parent WS1
contract. It is subordinate to both parent authorities. It MUST NOT reinterpret,
weaken, replace, or contradict any behavior frozen by WS1-A through WS1-E. If a
future implementation discovers a contradiction, it MUST stop and return for
owner review rather than changing a parent contract implicitly.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, `MAY`, and `DEFERRED` have their
ordinary requirements meaning. `DEFERRED` means outside WS1-F and not authorized
by this document.

---

## 1. Frozen Baseline and Compatibility Domains

| Authority | Frozen value |
|---|---|
| Repository HEAD and `origin/main` | `0d984c2a3f8fdaf0afe3fd1f4e91f913ae7a4844` |
| Master Specification SHA-256 | `530aef833f1eabbe0d70858bb74726d6e28550c4bdcfdf22ea4f544917eb80da` |
| WS1 Application-Service Contract SHA-256 | `6a980d7df0129de0aa5b4d0b49de0aaa27102a9063930692b645e2796ec66223` |
| Report schema | `1.7` |
| Memory schema | `8` |
| Scoring authority | `v2` |
| Windows secure report persistence | `OPEN / FAIL-CLOSED` |

WS1-F MUST NOT change a report schema, Memory schema, migration, scoring rule,
finding identity, firewall interpretation, reachability interpretation, platform
adapter, or frozen A-E public operation.

## 2. Purpose and Non-Goals

WS1-F is the local deterministic application boundary for:

- a report-grounded security briefing;
- bounded deterministic assistant questions;
- descriptive capability metadata and discovery;
- ephemeral, non-authorizing capability proposals; and
- application-safe evidence grounding.

WS1-F does **not** provide and MUST NOT invoke:

- generative or provider AI;
- external-provider or other network I/O;
- the AI Privacy Firewall implementation or provider-safe DTOs;
- capability execution;
- authorization decisions, issuance, validation, or persistence;
- privileged execution, remediation, or system-state changes;
- generic commands, shells, executable paths, or arbitrary subprocesses;
- background jobs, threads, schedulers, retries, or cancellation machinery;
- conversation or proposal persistence;
- SecurityMemory reads, enrichment, ingestion, or writes;
- GUI, voice, CLI migration, WS1-G, or another workstream.

Provider integration and the AI Privacy Firewall remain owned by WS8. Job and
cancellation behavior remain owned by later application/job contracts.

## 3. Exact Public Operations

WS1-F adds exactly four public facade methods and no aliases or convenience
variants:

```python
get_security_briefing(
    request: SecurityBriefingRequest,
) -> SecurityBriefingResult

ask_assistant(
    request: AssistantQuestionRequest,
) -> AssistantQuestionResult

list_capabilities(
    request: ListCapabilitiesRequest,
) -> CapabilityCatalogResult

propose_capability(
    request: ProposeCapabilityRequest,
) -> ProposeCapabilityResult
```

All four operations:

- MUST be synchronous;
- MUST generate an operation ID before validating the request;
- MUST return a complete immutable result or raise one
  `CyberWatchtowerApplicationError`;
- MUST NOT return partial results after an application failure;
- MUST NOT start background work; and
- MUST NOT accept caller-supplied operation IDs.

The operation-ID format is exactly:

`assistantop:<32 lowercase UUID4 hexadecimal characters>`

The regular expression is `^assistantop:[0-9a-f]{32}$`. The application MUST
generate the value from UUID4. The identifier is correlation metadata only. It
is not a capability, target, proposal, approval, authorization, or authority.

## 4. Global Public DTO Rules

Every new public F request, result, child DTO, and error-visible value MUST:

- be an application-owned frozen dataclass with `slots=True`, or a closed enum;
- be deeply immutable;
- validate its complete graph at construction;
- use tuples for ordered collections;
- use only immutable scalar values, closed enums, timezone-aware `datetime`
  values, `ReportId`, or purpose-built frozen/slotted child DTOs;
- reject boolean values where an integer is required;
- reject empty required text, surrounding whitespace on stable identifiers,
  disallowed controls, invalid closed values, and values over their bounds.

Public F contracts MUST NOT expose a mutable list, dictionary, set, mapping,
mapping view, arbitrary object, callable, path object, file descriptor, database
handle, provider object, platform object, raw report mapping, scanner object, or
legacy capability handler.

Unless a field-specific rule is stricter, text MUST be Unicode NFC, MUST already
be in NFC form rather than being silently normalized, and MUST reject characters
whose Unicode general category is `Cc` or `Cf`. New ASCII-safe identifiers MUST
match their field-specific ASCII grammar. Existing `system_id`, `ReportId`, and
finding identity rules remain authoritative and MUST NOT be rewritten.

UTC timestamps are Python `datetime` values whose offset is exactly zero and
whose `tzinfo` is `datetime.timezone.utc`. They use microsecond precision. An
implementation MUST reject a naive or non-UTC value rather than infer a zone.
Any future wire serialization is DEFERRED and requires a separate contract.

## 5. Effect and Permission Models

### 5.1 `EffectClass`

The application owns this closed enum with exactly these values:

| Value | Meaning |
|---|---|
| `PURE` | No application-visible I/O and no persistent mutation. Reading the standard-library clock or UUID entropy solely for required correlation metadata does not change this classification. |
| `LOCAL_READ` | Reads existing local application-owned or application-authorized state without mutation. |
| `LOCAL_DERIVED_STATE_CHANGE` | Changes derived local CyberWatchtower state only. |
| `LOCAL_AUTHORITATIVE_STATE_CHANGE` | Creates or changes authoritative local CyberWatchtower records. |
| `SYSTEM_OBSERVATION` | Actively observes or collects from the host without intentionally changing host state. |
| `SYSTEM_STATE_CHANGE` | Intentionally changes host or operating-system state. |
| `EXTERNAL_IO` | Transmits to or interacts with a non-local external service or provider. |
| `PROHIBITED` | Outside permitted CyberWatchtower execution policy. |

`EffectClass` describes the governing effect of an operation or capability. It
does not grant permission. When a capability has several expected effects, its
single `effect_class` is the most consequential effect for authorization policy,
and `expected_effects` MUST enumerate every material effect.

### 5.2 `PermissionClass`

The application owns this closed enum with exactly these values:

| Value | Meaning |
|---|---|
| `READ_ONLY` | The operation or future capability execution does not require a separate approval under its frozen contract. It does not mean that all effects are `PURE`. |
| `USER_APPROVAL_REQUIRED` | A future execution MUST have exact, current, independently issued user authorization. F cannot issue or validate it. |
| `PROHIBITED` | Execution is forbidden. No approval can make it executable. |

The application API MUST NOT depend on the legacy executable capability
registry as the enum authority. Any later compatibility translation MUST be
private and one-way into the application vocabulary.

### 5.3 F operation mappings

| Operation | EffectClass | PermissionClass |
|---|---|---|
| `get_security_briefing` | `LOCAL_READ` | `READ_ONLY` |
| `ask_assistant` | `LOCAL_READ` | `READ_ONLY` |
| `list_capabilities` | `PURE` | `READ_ONLY` |
| `propose_capability` | `PURE` | `READ_ONLY` |

`propose_capability` being `READ_ONLY` means only that creating an inert,
ephemeral proposal needs no approval. The proposal separately carries the
target capability's effect and permission classes. It grants no permission to
execute that target.

## 6. Report Selection, Storage, and Snapshot Rules

`get_security_briefing` and `ask_assistant` MUST consume canonical saved reports
through the existing WS1-D application repository boundary. Canonical reports
remain authoritative observations. F MUST NOT independently open a report path,
accept an arbitrary path, use a raw report loader, or write a canonical report.

Both operations use explicit selection:

- `system_id`
- `current_report_id`
- optional `previous_report_id`

There is no implicit latest report, hostname fallback, directory override, or
"load all history" behavior. A supplied previous report MUST have the same exact
`system_id` as the current report. The requested report or pair MUST be acquired
from one complete WS1-D catalog snapshot and revalidated through that same
snapshot. An incomplete snapshot fails with `INTEGRITY_FAILURE`; F MUST NOT
silently answer from a partial catalog.

If a previous report is supplied, the frozen chronology key is:

`(generated_at normalized to UTC, report_id.value)`

The previous key MUST be strictly less than the current key. Equal IDs or
invalid chronology produce `INVALID_REQUEST`. Comparison MUST reuse the frozen
WS1-E comparison semantics, including scoring-version incomparability and
coverage-aware uncertain disappearance. F MUST NOT infer resolution without
those semantics.

F storage access is frozen as follows:

| Operation | Canonical reports | SecurityMemory | Other persistent state |
|---|---|---|---|
| `get_security_briefing` | READ, authoritative | NONE | NONE |
| `ask_assistant` | READ, authoritative | NONE | NONE |
| `list_capabilities` | NONE | NONE | NONE |
| `propose_capability` | NONE | NONE | NONE |

Questions, responses, catalogs, and proposals are ephemeral. F persists
nothing and creates no storage authority. Memory remains derived state and is
available only through the six frozen WS1-E operations. Automatic Memory
enrichment is prohibited in F 1.0.

## 7. Report-Grounded Request and Result Contracts

### 7.1 `SecurityBriefingRequest`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `system_id` | `str` | yes | Existing application `system_id` rules; maximum 4,096 code points | Exact requested system scope |
| `current_report_id` | `ReportId` | yes | Existing `report:<64 lowercase hex>` contract | Current canonical observation |
| `previous_report_id` | `ReportId \| None` | no | Existing `ReportId`; if present, distinct and chronologically earlier | Optional comparison observation |

The DTO has exactly these fields.

### 7.2 `AssistantQuestionRequest`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `system_id` | `str` | yes | Existing application `system_id` rules; maximum 4,096 code points | Exact requested system scope |
| `current_report_id` | `ReportId` | yes | Existing `ReportId` contract | Current canonical observation |
| `previous_report_id` | `ReportId \| None` | no | Existing `ReportId`; if present, distinct and earlier | Optional comparison observation |
| `question` | `str` | yes | 1–4,096 Unicode code points after trimming; NFC; no `Cc` or `Cf` controls | Ephemeral user input, never evidence or authority |

The DTO has exactly these fields. The raw question MUST NOT appear in its public
result or a public failure.

### 7.3 `SecurityBriefingResult`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `operation_id` | `str` | yes | `assistantop` format | Correlation only |
| `system_id` | `str` | yes | Must exactly equal the request and both reports | Scope |
| `current_report` | `SavedReportReference` | yes | Existing immutable report reference | Authoritative report identity/time |
| `previous_report` | `SavedReportReference \| None` | no | Must match request and chronology | Authoritative report identity/time |
| `response` | `AssistantGroundedResponse` | yes | Sections, claims, and evidence validate atomically | Explanatory presentation only |

### 7.4 `AssistantQuestionStatus`

This closed enum has exactly:

- `ANSWERED`
- `UNSUPPORTED`
- `AMBIGUOUS`
- `MISSING_CONTEXT`

### 7.5 `AssistantQuestionResult`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `operation_id` | `str` | yes | `assistantop` format | Correlation only |
| `system_id` | `str` | yes | Exact request/report system | Scope |
| `current_report` | `SavedReportReference` | yes | Exact selected current report | Authoritative reference |
| `previous_report` | `SavedReportReference \| None` | no | Exact selected previous report | Authoritative reference |
| `status` | `AssistantQuestionStatus` | yes | Closed enum | Safe outcome |
| `intent` | `AssistantIntent \| None` | conditional | Required for `ANSWERED` or `MISSING_CONTEXT`; absent otherwise | Deterministic classification, not a security fact |
| `response` | `AssistantGroundedResponse \| None` | conditional | Required only for `ANSWERED` | Explanatory presentation only |

`UNSUPPORTED`, `AMBIGUOUS`, and `MISSING_CONTEXT` are successful structured
outcomes, not guessed answers. They contain no free-text notice and never echo
the question. An unknown explicitly addressed finding is not such an outcome;
it raises `NOT_FOUND`.

## 8. Assistant Grounding DTOs

### 8.1 `EpistemicState`

The application owns this closed enum with exactly:

- `OBSERVED`
- `STRONGLY_SUPPORTED`
- `POSSIBLE`
- `UNKNOWN`

No numeric confidence field is permitted on F claims. Risk score, finding
confidence, evidence confidence, visibility, coverage, and epistemic state MUST
remain distinct.

### 8.2 Section identifiers and precedence

`AssistantSectionId` is closed to:

- `POSTURE`
- `CHANGES`
- `PRIORITIES`
- `EXPLANATION`
- `COVERAGE`
- `NEXT_STEPS`

Their canonical string values are the lowercase identifiers `posture`,
`changes`, `priorities`, `explanation`, `coverage`, and `next_steps`. Each is
ASCII-safe and below the 128-character section-ID ceiling.

Global section precedence is exactly the order above. A response MUST contain
at most one section of each identifier and MUST follow this precedence.

### 8.3 `AssistantClaim`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `claim_id` | `str` | yes | 1–128 ASCII chars; `^[a-z][a-z0-9_.:-]{0,127}$`; unique per response | Stable presentation identity only |
| `text` | `str` | yes | 1–2,048 Unicode code points; NFC; no controls; privacy-safe | Explanatory text only |
| `epistemic_state` | `EpistemicState` | yes | Closed enum | Deterministic statement of support |
| `evidence_refs` | `tuple[str, ...]` | yes | 1–16 unique evidence IDs, ordered as the response evidence tuple | References only |

Every claim MUST have evidence. It MUST reference only evidence present in the
same response. Duplicate claim IDs, duplicate evidence IDs within a claim,
missing references, or a claim/evidence role contradiction produce
`INTEGRITY_FAILURE`.

### 8.4 `AssistantSection`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `section_id` | `AssistantSectionId` | yes | Closed enum; unique per response | Presentation category |
| `title` | `str` | yes | 1–128 Unicode code points; NFC; no controls | Display text only |
| `claims` | `tuple[AssistantClaim, ...]` | yes | 0–64; response total remains at most 64 | Grounded presentation |
| `omitted_item_count` | `int` | yes | Non-boolean integer from 0 through 65,536 | Explicit bounded-selection count |

An empty section is permitted only for `PRIORITIES`; it states, through the
section identity and zero omission count, that no actionable current finding
was selected. Other returned sections MUST contain at least one claim.

### 8.5 `AssistantGroundedResponse`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `sections` | `tuple[AssistantSection, ...]` | yes | 1–16, unique IDs, section precedence | Explanatory structure |
| `evidence` | `tuple[AssistantEvidenceReference, ...]` | yes | 1–128, unique and canonically ordered | Stable references only |

The response MUST contain at most 64 claims and at most 65,536 total claim-text
Unicode code points. Every evidence item MUST be referenced by at least one
claim. No raw question, report mapping, report fragment, path, command, SQL,
stdout/stderr, native JSON, or provider payload may appear.

## 9. Evidence Model and Compatibility Rules

### 9.1 `AssistantEvidenceSourceKind`

The closed source-kind enum is exactly:

- `CANONICAL_REPORT`
- `REPORT_FINDING`
- `REPORT_COMPARISON`
- `DETERMINISTIC_ADVISOR`

### 9.2 `AssistantEvidenceRole`

The application-owned closed role enum is exactly:

- `OBSERVED_FACT`
- `DETERMINISTIC_DERIVATION`

The compatibility table is:

| Source kind | Permitted role |
|---|---|
| `CANONICAL_REPORT` | `OBSERVED_FACT` |
| `REPORT_FINDING` | `OBSERVED_FACT` |
| `REPORT_COMPARISON` | `DETERMINISTIC_DERIVATION` |
| `DETERMINISTIC_ADVISOR` | `DETERMINISTIC_DERIVATION` |

This is the F subset of the frozen core source/role rules. F has no external
knowledge, user-decision, Memory, or model-output evidence source.

### 9.3 `AssistantEvidenceReference`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `evidence_id` | `str` | yes | 1–128 ASCII chars; same grammar as `claim_id`; unique per response | Reference identity only |
| `source_kind` | `AssistantEvidenceSourceKind` | yes | Closed enum | Evidence category |
| `source_id` | `str` | yes | 1–512 code points; NFC; no controls; no raw fragment | Existing stable application ID or deterministic rule/action ID |
| `evidence_role` | `AssistantEvidenceRole` | yes | Closed enum and compatibility table | Observed versus derived distinction |
| `report_ids` | `tuple[ReportId, ...]` | yes | 1 for report/finding; exactly 2 chronological IDs for comparison; 1 or 2 for advisor | Exact canonical source binding |

`CANONICAL_REPORT.source_id` MUST equal its sole `ReportId.value`.
`REPORT_FINDING.source_id` MUST be the exact stable finding identity in its sole
report. `REPORT_COMPARISON` MUST carry `(previous, current)` report IDs in frozen
chronology order. `DETERMINISTIC_ADVISOR` MUST use an existing stable advisor
action/rule identity and the exact report IDs it consumed.

Evidence references are unique both by `evidence_id` and by the semantic tuple
`(source_kind, source_id, evidence_role, report_ids)`. Duplicate semantic
identity is `INTEGRITY_FAILURE`; aliases are prohibited. Ordering is by
`source_kind.value` ASC, `source_id` by Unicode code-point order ASC,
`evidence_role.value` ASC, report-ID tuple lexicographically ASC, then
`evidence_id` ASC.

Missing mandatory evidence, incompatible roles, a finding absent from its
bound report, or contradictory report binding is `INTEGRITY_FAILURE` when the
claim cannot safely be built. A forged or unknown public report/finding request
is `NOT_FOUND` as Section 24 defines.

### 9.4 Claim support

- `OBSERVED` claims MUST copy or faithfully summarize an authoritative report
  fact and MUST use only `OBSERVED_FACT` evidence.
- `STRONGLY_SUPPORTED` claims MUST be produced by a deterministic frozen rule,
  MUST include qualifying observed evidence and, where used, deterministic
  derivation evidence, and MUST have no material unresolved contradiction.
- `POSSIBLE` claims MUST preserve the source uncertainty and MUST NOT be
  presented as observed or strongly supported.
- `UNKNOWN` claims MUST identify a report-grounded insufficiency, unsupported
  shape, or coverage limitation. They MUST NOT fill the gap with an inference.

Assistant text is explanatory and presentational. It does not become an
authoritative security fact by appearing in an assistant result.

No F operation may manufacture evidence, promote `POSSIBLE`, promote `UNKNOWN`,
recalculate a score, reinterpret firewall state, reinterpret reachability,
override finding identity, or infer resolution without frozen coverage-aware
comparison semantics.

## 10. Security Briefing Contract

`get_security_briefing` is deterministic, report-grounded, and offline. It MAY
use existing deterministic Advisor algorithms only through an application-owned
bounded adapter over WS1-D projected report data. It MUST NOT use the legacy
briefing builder directly when that would load Memory, raw mappings, or
unbounded history.

The result sections are:

1. `POSTURE` — exactly one claim preserving the current report's existing score,
   risk label, authoritative finding counts, and assurance without rescoring.
2. `CHANGES` — present only when `previous_report_id` was supplied; score change
   is stated only when scoring versions are comparable; added, resolved, and
   uncertain disappearances reuse WS1-E semantics.
3. `PRIORITIES` — zero to five highest-priority existing non-observation
   findings selected by the existing deterministic Advisor priority policy.
   `omitted_item_count` records additional eligible findings.
4. `COVERAGE` — one or more claims preserving assessment assurance, each
   coverage limitation, and incomplete/unknown visibility. It never claims
   completeness not present in the report.
5. `NEXT_STEPS` — one to three deterministic Advisor actions; if no action is
   derived, one evidence-backed monitoring/review statement. Additional actions
   are counted in `omitted_item_count`.

The returned subset follows global section precedence. A briefing never
contains a recurring-history section because F does not read Memory. A report
with no eligible priority finding returns the empty `PRIORITIES` section rather
than manufacturing a finding.

Finding/action priority MUST reuse the existing deterministic Advisor ranking.
Within comparison categories, claims order by category `SCORE`, `ADDED`,
`RESOLVED`, `UNCERTAIN`, then stable finding ID ASC. Coverage claims order by
coverage category, then `ScanDomain.value` ASC. No presentation order may alter
the authoritative score or severity.

Epistemic assignment is exact:

- `POSTURE` is `STRONGLY_SUPPORTED` and cites the current canonical report plus
  the deterministic Advisor rule. It states that it is a report-derived posture,
  not a direct raw host observation.
- A priority or explanation derived from `AssessmentState.CONFIRMED` is
  `STRONGLY_SUPPORTED`; `POTENTIAL` is `POSSIBLE`; `INCOMPLETE` is `UNKNOWN`;
  and `INFORMATIONAL` is `OBSERVED` only when the text merely preserves the
  report observation without a risk inference.
- Coverage/assurance claims that preserve explicit report fields are
  `OBSERVED`. A claim about what missing coverage might conceal is `UNKNOWN`,
  never `OBSERVED`.
- A compatible deterministic score/change, an added finding, or a
  coverage-qualified resolution is `STRONGLY_SUPPORTED`. An uncertain
  disappearance is `POSSIBLE`. Incompatible scoring versions produce a
  `STRONGLY_SUPPORTED` statement that versions are incomparable and MUST NOT
  produce a numeric trend claim.
- A next-step claim inherits the addressed finding's mapping above. The
  no-action statement is `STRONGLY_SUPPORTED` only as the narrow statement that
  the deterministic Advisor derived no action; it MUST NOT claim that the
  system is safe or complete.

## 11. Deterministic Assistant Intent Contract

### 11.1 `AssistantIntent`

The supported intent vocabulary is exactly:

- `SUMMARY`
- `WHY_FINDING`
- `WHAT_CHANGED`
- `WHAT_TO_FIX_FIRST`
- `COVERAGE`

These five are supported by existing local report, comparison, briefing, and
Advisor behavior. No navigation, configuration, history, provider, free-form
conversation, or execution intent is implied.

### 11.2 Deterministic classification

Before classification, the validated question is trimmed, internal Unicode
whitespace runs are collapsed to one ASCII space, and text is Unicode-casefolded
without locale-sensitive processing. The raw question is retained only for the
duration of the call.

Intent cues are frozen as follows:

| Intent | Cue |
|---|---|
| `SUMMARY` | Normalized question is exactly `summary`, `summarize`, `security summary`, `summarize this report`, or `what is my security posture` |
| `WHY_FINDING` | Trimmed question has the exact case-insensitive prefix `why finding ` followed by one non-empty exact, case-sensitive finding ID |
| `WHAT_CHANGED` | Normalized question contains `what changed` or `since the previous` |
| `WHAT_TO_FIX_FIRST` | Normalized question contains `fix first`, `do first`, or `should i fix` |
| `COVERAGE` | Normalized question contains `coverage`, `visibility`, `what could you see`, `what could you not see`, or `limitations` |

For all intents except the dedicated `WHY_FINDING` grammar, matching more than
one intent yields `AMBIGUOUS`; matching none yields `UNSUPPORTED`. The dedicated
grammar is recognized only when the entire suffix is one finding identity. If
that identity is absent from the current report, the operation raises
`NOT_FOUND`. It MUST NOT search another report or system.

`WHAT_CHANGED` without a previous report returns `MISSING_CONTEXT` with intent
`WHAT_CHANGED` and no response. F MUST NOT choose a previous report implicitly.

### 11.3 Answer shapes

| Intent | Returned sections | Rule |
|---|---|---|
| `SUMMARY` | `POSTURE`, `PRIORITIES`, `COVERAGE` | Same bounded deterministic projections as the briefing |
| `WHY_FINDING` | `EXPLANATION` | Exactly one explanation claim for the addressed current finding, using its authoritative state and existing deterministic Advisor rationale |
| `WHAT_CHANGED` | `CHANGES` | Frozen WS1-E comparison semantics only |
| `WHAT_TO_FIX_FIRST` | `NEXT_STEPS` | Exactly the first deterministic Advisor action, or one grounded no-action statement |
| `COVERAGE` | `COVERAGE` | Current report assurance and coverage limitations only |

The assistant MUST NOT silently guess an intent, finding, previous report, or
answer. It MUST NOT route an unsupported question to a provider.

## 12. Question Privacy

Question text is classified `SENSITIVE_LOCAL_DATA`. F MUST:

- keep it ephemeral;
- never persist it or write it to SecurityMemory;
- never place it in a result, public error, proposal identifier, evidence
  reference, diagnostic, or log added by F;
- never send it externally;
- validate it before classification; and
- discard the operation-local reference when the call completes.

The result MUST NOT echo a sanitized or unsanitized question. Public failures
use fixed bounded messages and MUST NOT interpolate question content.

## 13. Capability Vocabulary and Metadata Purpose

F capability metadata is descriptive policy metadata for supported application
operations. It is not an executable registry. A catalog entry MUST NOT contain
or expose a callable, handler, command, argv, shell string, executable path,
arbitrary filesystem path, database handle, provider client, collector,
adapter, or privilege object.

### 13.1 Stable capability ID syntax

F uses the project-owned equivalent stable namespace:

`cyberwatchtower.application.<public_operation_name>`

The complete grammar is
`^cyberwatchtower\.application\.[a-z][a-z0-9_]{0,95}$`, with a total maximum
of 128 ASCII characters. The leaf is the exact snake-case public application
operation name. This syntax does not assert ownership of an Internet DNS name.

### 13.2 Capability version

`capability_version` is a positive decimal integer represented as a string. Its
grammar is `^[1-9][0-9]*$`, maximum 20 ASCII digits, with no sign or leading
zero. Every initial capability version is exactly `"1"`.

The version MUST change whenever authorization-relevant semantics change,
including accepted parameters or defaults, target semantics, effect class,
permission class, expected side effects, privacy classification, or execution
meaning. Display-only title or summary changes do not require a version change.

### 13.3 `PrivacyClass`

The application owns this smallest F closed enum:

| Value | Meaning |
|---|---|
| `PUBLIC_METADATA` | Product-defined identifiers, titles, versions, and policy metadata that contain no host/user-specific security data. |
| `LOCAL_SECURITY_DATA` | System-scoped posture, score, timestamps, coverage, and operational security metadata intended to remain local absent a later policy. |
| `SENSITIVE_LOCAL_DATA` | Host, user, network, process, service, finding, evidence, or question data whose disclosure can create material privacy or security risk. |
| `SECRET` | Credentials, API keys, authorization material, private keys, recovery material, or equivalent secret values. F never accepts or emits the value. |

These are local application classifications. None means provider-safe or grants
external transmission. A capability with a `SECRET` parameter MUST be
`UNAVAILABLE` or `PROHIBITED`; F MUST NOT approximate it or place the secret in
a proposal parameter DTO, digest input, error, evidence, diagnostic, or display.

### 13.4 `CapabilityAvailability`

The structured availability enum is exactly:

- `AVAILABLE` — the corresponding application operation is implemented in this
  build; this does not assert that a requested report or configured component
  currently exists.
- `UNAVAILABLE` — known metadata exists, but the operation cannot be offered by
  this build or frozen policy.
- `PROHIBITED` — execution policy forbids the capability.

Availability is static application metadata in F. `list_capabilities` MUST NOT
probe storage, Memory, platform, provider, or network state to compute it.

## 14. Capability Metadata DTOs

### 14.1 `CapabilityExpectedEffect`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `effect_id` | `str` | yes | 1–128 ASCII; `^[a-z][a-z0-9_]{0,127}$` | Stable effect category |
| `effect_class` | `EffectClass` | yes | Closed enum | Effect description, never permission |
| `summary` | `str` | yes | 1–512 Unicode code points; NFC; no controls | Bounded display explanation |

Each metadata entry has 1–16 effects, ordered by `effect_id` ASC, with no
duplicate effect ID or semantic `(effect_class, summary)` pair.

### 14.2 `CapabilityParameterKind`

The closed parameter-kind enum is exactly:

- `TEXT`
- `INTEGER`
- `BOOLEAN`
- `UTC_TIMESTAMP`

### 14.3 `CapabilityParameterSpec`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `key` | `str` | yes | 1–64 ASCII; `^[a-z][a-z0-9_]{0,63}$` | Stable parameter name |
| `kind` | `CapabilityParameterKind` | yes | Closed enum | Canonical scalar type |
| `required` | `bool` | yes | Exact bool | Presence policy |
| `privacy_class` | `PrivacyClass` | yes | Closed enum; MUST NOT be `SECRET` in an available F capability | Local classification |

Parameter specs are a tuple of 0–32 entries, ordered by key ASC, with unique
keys. Defaults and value ranges are frozen by the capability table in Section
15 and are authorization-relevant semantics.

### 14.4 `CapabilityMetadata`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `capability_id` | `str` | yes | Stable syntax; maximum 128 ASCII chars | Capability identity |
| `capability_version` | `str` | yes | Positive decimal grammar; maximum 20 chars | Immutable semantics version |
| `title` | `str` | yes | 1–128 Unicode code points | Display only |
| `summary` | `str` | yes | 1–1,024 Unicode code points | Display only |
| `effect_class` | `EffectClass` | yes | Closed enum | Governing effect |
| `permission_class` | `PermissionClass` | yes | Closed enum | Future execution policy |
| `privacy_class` | `PrivacyClass` | yes | Closed enum | Highest data classification accepted or returned |
| `availability` | `CapabilityAvailability` | yes | Closed enum | Static implementation/policy state |
| `expected_effects` | `tuple[CapabilityExpectedEffect, ...]` | yes | 1–16, canonical order, unique | Complete material effects |
| `target_kinds` | `tuple[CapabilityTargetKind, ...]` | yes | 1–4, enum declaration order, unique | Permitted target shapes |
| `parameters` | `tuple[CapabilityParameterSpec, ...]` | yes | 0–32, key ASC, unique | Accepted scalar parameter contract |

Unknown effect, permission, privacy, availability, target, or parameter-kind
values fail closed. Duplicate `(capability_id, capability_version)` is
`INTEGRITY_FAILURE`.

## 15. Frozen Initial Capability Catalog

The initial catalog contains exactly the eleven frozen A-E application
operations below. It does not contain the four F orchestration/discovery
operations, because those operations define this metadata boundary rather than
future executable targets. It contains no process inspection, service
inspection, remediation, shell, provider, external scan, or arbitrary host
scan capability.

All entries have version `"1"` and availability `AVAILABLE`.

| Capability ID | Target | Parameters | EffectClass | PermissionClass | PrivacyClass |
|---|---|---|---|---|---|
| `cyberwatchtower.application.assess_and_save_current_system` | `SYSTEM` | none | `LOCAL_AUTHORITATIVE_STATE_CHANGE` | `USER_APPROVAL_REQUIRED` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.assess_current_system` | `SYSTEM` | none | `SYSTEM_OBSERVATION` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.compare_saved_reports` | `REPORT` (two ordered reports) | none | `LOCAL_READ` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.get_finding_timeline` | `FINDING` (system-scoped) | `limit` | `LOCAL_READ` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.get_latest_saved_report` | `SYSTEM` | none | `LOCAL_READ` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.get_memory_health` | `APPLICATION` | none | `LOCAL_READ` | `READ_ONLY` | `LOCAL_SECURITY_DATA` |
| `cyberwatchtower.application.get_saved_report` | `REPORT` (one report) | none | `LOCAL_READ` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.get_score_history` | `SYSTEM` | `end_at`, `limit`, `scoring_version`, `start_at` | `LOCAL_READ` | `READ_ONLY` | `LOCAL_SECURITY_DATA` |
| `cyberwatchtower.application.ingest_saved_report_into_memory` | `REPORT` (one report) | none | `LOCAL_DERIVED_STATE_CHANGE` | `USER_APPROVAL_REQUIRED` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.list_recurring_findings` | `SYSTEM` | `active_only`, `limit` | `LOCAL_READ` | `READ_ONLY` | `SENSITIVE_LOCAL_DATA` |
| `cyberwatchtower.application.list_saved_reports` | `SYSTEM` | none | `LOCAL_READ` | `READ_ONLY` | `LOCAL_SECURITY_DATA` |

The direct A-E facade behavior remains frozen. The two
`USER_APPROVAL_REQUIRED` catalog classifications govern any future capability
execution path; F adds no execution path and does not retrofit or weaken A-E.

Initial display text is exact:

| Capability leaf | Title | Summary |
|---|---|---|
| `assess_and_save_current_system` | Assess and save this system | Run the frozen current-system assessment and create one canonical saved report. |
| `assess_current_system` | Assess this system | Run the frozen read-only current-system assessment without persistence. |
| `compare_saved_reports` | Compare saved reports | Compare two exact same-system canonical saved reports with frozen history semantics. |
| `get_finding_timeline` | Get finding timeline | Read one bounded exact-system finding lifecycle timeline from SecurityMemory. |
| `get_latest_saved_report` | Get latest saved report | Read the latest canonical saved report for one exact system. |
| `get_memory_health` | Get Memory health | Read bounded privacy-safe SecurityMemory health information. |
| `get_saved_report` | Get saved report | Read one exact canonical saved report. |
| `get_score_history` | Get score history | Read bounded score history for one exact system and time range. |
| `ingest_saved_report_into_memory` | Ingest report into Memory | Idempotently derive SecurityMemory state from one trusted canonical report. |
| `list_recurring_findings` | List recurring findings | Read a bounded recurring-finding view for one exact system from SecurityMemory. |
| `list_saved_reports` | List saved reports | Read bounded canonical saved-report metadata for one exact system. |

Parameter semantics are exact:

| Capability | Key | Kind | Required | Default / range | PrivacyClass |
|---|---|---|---:|---|---|
| `list_recurring_findings` | `active_only` | `BOOLEAN` | no | effective default `false` | `LOCAL_SECURITY_DATA` |
| `list_recurring_findings` | `limit` | `INTEGER` | no | effective default `50`; range 1–200 | `PUBLIC_METADATA` |
| `get_finding_timeline` | `limit` | `INTEGER` | no | effective default `100`; range 1–500 | `PUBLIC_METADATA` |
| `get_score_history` | `end_at` | `UTC_TIMESTAMP` | yes | must not precede `start_at`; range at most 366 days | `LOCAL_SECURITY_DATA` |
| `get_score_history` | `limit` | `INTEGER` | no | effective default `100`; range 1–500 | `PUBLIC_METADATA` |
| `get_score_history` | `scoring_version` | `TEXT` | no | absent means all supported series; if present exactly `1` or `2` | `PUBLIC_METADATA` |
| `get_score_history` | `start_at` | `UTC_TIMESTAMP` | yes | must not follow `end_at` | `LOCAL_SECURITY_DATA` |

`propose_capability` MUST materialize optional defaults into the returned
proposal parameter tuple before computing the digest. A semantically equivalent
request with an omitted default and one with the explicit default therefore has
the same returned parameters and digest. Optional `scoring_version` remains
absent when omitted because absence has the distinct frozen meaning "all
supported series."

Expected effects are exact and ordered by effect ID:

| Capability leaf | Expected effects `(effect_id, class, summary)` |
|---|---|
| `assess_current_system` | `observe_current_system`, `SYSTEM_OBSERVATION`, "Observe the current local system through the frozen assessment boundary." |
| `assess_and_save_current_system` | `observe_current_system`, `SYSTEM_OBSERVATION`, "Observe the current local system through the frozen assessment boundary."; `write_canonical_report`, `LOCAL_AUTHORITATIVE_STATE_CHANGE`, "Create one canonical saved assessment report." |
| `list_saved_reports` | `read_report_catalog`, `LOCAL_READ`, "Read bounded canonical saved-report metadata for one exact system." |
| `get_saved_report` | `read_canonical_report`, `LOCAL_READ`, "Read one exact canonical saved report." |
| `get_latest_saved_report` | `read_report_catalog`, `LOCAL_READ`, "Read the latest canonical saved-report metadata and report for one exact system." |
| `compare_saved_reports` | `read_canonical_reports`, `LOCAL_READ`, "Read and compare two exact same-system canonical saved reports." |
| `ingest_saved_report_into_memory` | `read_canonical_report`, `LOCAL_READ`, "Read one exact canonical saved report."; `write_derived_memory`, `LOCAL_DERIVED_STATE_CHANGE`, "Idempotently derive SecurityMemory state from that report." |
| `list_recurring_findings` | `read_derived_memory`, `LOCAL_READ`, "Read a bounded recurring-finding view from SecurityMemory." |
| `get_finding_timeline` | `read_derived_memory`, `LOCAL_READ`, "Read a bounded exact-system finding timeline from SecurityMemory." |
| `get_score_history` | `read_derived_memory`, `LOCAL_READ`, "Read bounded score-history series from SecurityMemory." |
| `get_memory_health` | `read_memory_health`, `LOCAL_READ`, "Read bounded privacy-safe SecurityMemory health state." |

Catalog titles and summaries are bounded display text and MAY be editorially
reworded without a version change only when meaning, scope, effects, privacy,
and permission remain identical.

## 16. Proposal Parameter Representation and Digest

### 16.1 `ProposalParameter`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `key` | `str` | yes | Parameter-key grammar; 1–64 ASCII chars | Must match the selected capability spec |
| `kind` | `CapabilityParameterKind` | yes | Must equal the selected spec | Type binding |
| `value` | `str` | yes | 1–1,024 Unicode code points; kind-specific canonical lexical form | Exact proposed scalar value |

The tuple contains at most 32 entries, is ordered by key ASC, and rejects
duplicate keys. Nested objects, arrays, mappings, nulls, floats, bytes, paths,
callables, and arbitrary objects are prohibited.

Canonical lexical forms are:

- `TEXT`: NFC Unicode, non-empty after trimming, no surrounding whitespace,
  no `Cc` or `Cf`, and otherwise exact; no silent normalization.
- `INTEGER`: ASCII `0` or `-?[1-9][0-9]*`, no `+`, leading zero, or `-0`, and
  within signed 64-bit range.
- `BOOLEAN`: exactly lowercase ASCII `true` or `false`.
- `UTC_TIMESTAMP`: exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ`, a valid Gregorian UTC
  timestamp with six fractional digits.

Only allowlisted parameters for the selected capability are accepted. Unknown,
missing required, extra, wrong-kind, out-of-range, or mutually inconsistent
parameters produce `INVALID_REQUEST`.

### 16.2 Secret and injection rejection

Before canonicalization, keys and text values are scanned using the existing
application rejection-only sensitive markers: `api-key`, `api_key`, `apikey`,
`authorization:`, `bearer `, `command line`, `credential`, `cookie:`,
`environment=`, `password`, `raw argv`, `stderr`, `token=`, and `token:`,
case-insensitively. F additionally rejects a value containing a PEM private-key
header, `$(`, a backtick, `sh -c`, `bash -c`, `cmd.exe`, or `powershell`.

Obvious path forms are also rejected: a value beginning `/`, `./`, `../`, `~`,
`\\`, or an ASCII drive-letter root; containing `/../` or `\\..\\`; or beginning
`file:`. These checks can reject; their absence never proves provider safety.

A sensitive, secret-looking, raw-command, argv, shell, or path value produces
`PRIVACY_POLICY_BLOCKED`. The raw value MUST NOT enter the digest input, error,
diagnostic, evidence, display, or log.

### 16.3 Canonical parameter bytes

Canonicalization occurs only after full validation and default materialization.
It is completely defined as follows:

1. Start with the exact ASCII bytes `CWT-PARAMETERS-V1` followed by one zero
   byte.
2. Sort parameters by ASCII key ascending.
3. For each parameter append, in order:
   - key byte length as an unsigned 16-bit big-endian integer;
   - UTF-8 bytes of the key;
   - one ASCII kind tag: `T`, `I`, `B`, or `D` for `TEXT`, `INTEGER`, `BOOLEAN`,
     or `UTC_TIMESTAMP`;
   - canonical value byte length as an unsigned 32-bit big-endian integer;
   - UTF-8 bytes of the canonical lexical value.
4. Append no separator, terminator, BOM, capability ID, version, target, locale,
   or platform-dependent data.

The length prefixes make the representation unambiguous. The maximum field
bounds ensure every length fits. Empty parameters canonicalize to the header and
zero byte only.

`parameter_digest` is lowercase hexadecimal SHA-256 over exactly those bytes,
matching `^[0-9a-f]{64}$`. `repr()`, unordered mappings, locale formatting,
implementation-specific serialization, and insertion order are prohibited.

Capability ID, version, system, and target are deliberately bound as separate
proposal fields and MUST all be checked alongside the parameter digest by any
future authorization/execution contract.

## 17. Target Model and Canonicalization

### 17.1 `CapabilityTargetKind`

The closed enum is exactly:

- `APPLICATION`
- `SYSTEM`
- `REPORT`
- `FINDING`

### 17.2 `CapabilityTarget`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `kind` | `CapabilityTargetKind` | yes | Closed enum | Target shape |
| `system_id` | `str` | yes | Existing exact system-ID rules, maximum 4,096 | Mandatory system binding for every proposal |
| `report_ids` | `tuple[ReportId, ...]` | yes | 0–2, unique; capability-specific cardinality | Exact canonical report references |
| `finding_id` | `str \| None` | conditional | Existing finding-ID rules, maximum 512; no surrounding whitespace | Exact stable finding reference |

Shape rules are exact:

- `APPLICATION`: zero report IDs and no finding ID. `system_id` is the required
  proposal/authorization context; it is not claimed to be an argument of a
  store-wide diagnostic operation.
- `SYSTEM`: zero report IDs and no finding ID.
- `REPORT`: one report ID, except `compare_saved_reports`, which requires exactly
  two in `(previous, current)` order; no finding ID.
- `FINDING`: a finding ID and zero or one report ID. The initial
  `get_finding_timeline` capability requires zero because its frozen finding
  target is system-scoped. A future report-bound finding capability would
  require one through a new capability version.

No path, hostname substitute, URL, command, argv, shell, executable, IP-based
remote target, or arbitrary mapping is accepted. New target text is limited to
512 characters; `system_id` alone retains its frozen 4,096 maximum.
Target textual identifiers are subject to the same secret, path, command, and
shell rejection patterns in Section 16.2. A rejected value is never
canonicalized or digested.

`ProposeCapabilityRequest.system_id` and `target.system_id` MUST be identical.
This enforces exact-system binding without a hostname fallback.

Because `propose_capability` is `PURE`, a syntactically valid report or finding
reference remains an opaque asserted target in F. The proposal does not assert
that it exists or belongs to the system. Report-reading F operations validate
ownership through WS1-D. Any future authorization/execution MUST revalidate the
same target against its authoritative source and fail closed if forged,
cross-system, changed, or stale. The inert proposal itself grants nothing.

### 17.3 Canonical target bytes and digest

The target canonical form is:

1. Exact ASCII bytes `CWT-TARGET-V1` plus one zero byte.
2. One ASCII kind tag: `A`, `S`, `R`, or `F`.
3. System-ID UTF-8 byte length as unsigned 32-bit big-endian, then its exact
   UTF-8 bytes.
4. Report count as one unsigned byte, followed for each report in tuple order by
   its UTF-8 byte length as unsigned 16-bit big-endian and exact UTF-8 bytes.
5. One byte `0x00` when no finding is present; otherwise `0x01`, then the
   finding-ID UTF-8 byte length as unsigned 16-bit big-endian and exact UTF-8
   bytes.

No normalization or sorting occurs after validation. Report tuple order is
semantic. `target_digest` is lowercase hexadecimal SHA-256 over exactly these
bytes and matches `^[0-9a-f]{64}$`.

## 18. Proposal Contracts

### 18.1 `ReusePolicy`

The closed enum contains exactly one value: `ONE_TIME`.

It states the required future authorization/execution reuse policy. F performs
no consumption and persists no consumed state.

### 18.2 `ProposeCapabilityRequest`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `system_id` | `str` | yes | Existing system-ID rules; exact target match | Proposal scope assertion |
| `capability_id` | `str` | yes | Stable capability grammar | Catalog lookup only |
| `capability_version` | `str` | yes | Positive decimal version grammar | Exact catalog version |
| `target` | `CapabilityTarget` | yes | Capability-specific shape | Inert exact target metadata |
| `parameters` | `tuple[ProposalParameter, ...]` | yes | 0–32, key ASC, unique, selected schema | Inert exact parameter metadata |

The DTO has exactly these fields and no mapping. Construction validates generic
shape. The operation validates catalog-specific target, parameters, defaults,
privacy, and availability.

### 18.3 `CapabilityProposal`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `proposal_id` | `str` | yes | `proposal:<32 lowercase UUID4 hex>` | Correlation identity only |
| `system_id` | `str` | yes | Exact request and target system | Scope binding |
| `capability_id` | `str` | yes | Exact catalog ID | Capability binding |
| `capability_version` | `str` | yes | Exact catalog version | Semantics binding |
| `target` | `CapabilityTarget` | yes | Deeply immutable validated target | Target binding |
| `target_digest` | `str` | yes | 64 lowercase SHA-256 hex from Section 17 | Canonical target binding aid |
| `parameters` | `tuple[ProposalParameter, ...]` | yes | Complete effective tuple, defaults included | Exact parameter set |
| `parameter_digest` | `str` | yes | 64 lowercase SHA-256 hex from Section 16 | Canonical parameter binding |
| `effect_class` | `EffectClass` | yes | Exact catalog value | Descriptive effect |
| `permission_class` | `PermissionClass` | yes | Exact catalog value | Required future policy |
| `privacy_class` | `PrivacyClass` | yes | Exact catalog value | Local classification |
| `expected_effects` | `tuple[CapabilityExpectedEffect, ...]` | yes | Exact catalog tuple, 1–16 | Material effects |
| `issued_at` | `datetime` | yes | Canonical UTC | Proposal metadata |
| `expires_at` | `datetime` | yes | Exactly `issued_at + timedelta(minutes=10)` | Required future expiry |
| `reuse_policy` | `ReusePolicy` | yes | Exactly `ONE_TIME` | Required future reuse policy |

The proposal lifetime is exactly ten minutes. Future validation MUST treat
`execution_at >= expires_at` as expired. F does not validate or consume a
proposal after returning it.

### 18.4 `ProposeCapabilityResult`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `operation_id` | `str` | yes | `assistantop` format | Correlation only |
| `proposal` | `CapabilityProposal` | yes | Complete immutable proposal | Non-authorizing metadata only |

## 19. A Proposal Is Not Authorization

**A PROPOSAL IS NOT AUTHORIZATION.** All of the following are permanent F
rules:

- proposal existence grants no permission;
- a proposal ID grants no permission;
- a target or parameter digest grants no permission;
- an assistant recommendation grants no permission;
- capability availability grants no permission;
- `READ_ONLY` on `propose_capability` grants no permission to execute its target;
- UI visibility, selection, or state grants no permission;
- a previous approval grants no permission for a different digest, capability
  version, target, proposal, system, or expiry;
- model or provider output can never authorize;
- an operation ID can never authorize; and
- CyberWatchtower cannot self-authorize or infer authorization.

Actual authorization decision, issuance, audit, persistence, validation,
consumption, and capability execution are DEFERRED beyond F.

## 20. Capability Catalog Result

### 20.1 `ListCapabilitiesRequest`

This is a frozen, slotted, zero-field dataclass.

### 20.2 `CapabilityCatalogResult`

| Field | Type | Required | Validation and bound | Authority |
|---|---|---:|---|---|
| `operation_id` | `str` | yes | `assistantop` format | Correlation only |
| `capabilities` | `tuple[CapabilityMetadata, ...]` | yes | 0–64; canonical order; unique ID/version | Static application policy metadata |
| `returned_count` | `int` | yes | Non-boolean 0–64; exactly tuple length | Result metadata |

There is no pagination, cursor, `has_more`, filesystem read, report read, Memory
read, platform access, provider access, or runtime availability probe. If the
internal catalog exceeds 64, contains a duplicate, unknown closed value, invalid
order, executable field, or invalid metadata, the operation fails atomically
with `INTEGRITY_FAILURE`.

Ordering is `capability_id` ASC by ASCII code point, then numeric
`capability_version` ASC using arbitrary-precision decimal comparison. Lexical
version ordering is prohibited.

## 21. `propose_capability` Behavior

The operation consumes only the immutable request and the static application
catalog. It MAY read the standard-library UTC clock and UUID4 entropy for
required metadata. It MUST NOT open reports or Memory, collect system state,
execute a capability, persist a proposal, issue or validate approval, or contact
a provider.

Processing order is exact:

1. Generate `operation_id`.
2. Validate the public request graph.
3. Resolve exact `(capability_id, capability_version)` in the static catalog.
4. Reject `PROHIBITED` permission/effect/availability.
5. Reject `UNAVAILABLE` availability.
6. Validate exact target kind/cardinality and system equality.
7. Validate the parameter schema, materialize defaults, and reject secret or
   unsafe values before digest input.
8. Canonicalize target and parameters and compute both digests.
9. Generate `proposal_id` from UUID4.
10. Read canonical UTC `issued_at`, set exact ten-minute `expires_at`, and return
    the immutable result.

Unknown capability or version, including a stale version, fails closed with
`AUTHORIZATION_DENIED`. A prohibited capability fails with
`AUTHORIZATION_DENIED`. An unavailable capability fails with
`COMPONENT_UNAVAILABLE`. No fallback version or closest capability is selected.

## 22. Resource Bounds and Failure on Overflow

F freezes these ceilings:

| Resource | Maximum |
|---|---:|
| Question | 4,096 Unicode code points |
| Capability catalog | 64 entries |
| Response sections | 16 |
| Claims per response | 64 |
| Evidence refs per claim | 16 |
| Evidence refs per response | 128 |
| Total claim text per response | 65,536 Unicode code points |
| Claim text | 2,048 Unicode code points |
| Section title | 128 Unicode code points |
| Section identifier | 128 ASCII characters |
| Capability ID | 128 ASCII characters |
| Capability version | 20 ASCII digits |
| Capability title | 128 Unicode code points |
| Capability summary | 1,024 Unicode code points |
| Expected effects per capability | 16 |
| Expected-effect ID | 128 ASCII characters |
| Expected-effect text | 512 Unicode code points |
| Parameter specs per capability | 32 |
| Proposal parameters | 32 |
| Parameter key | 64 ASCII characters |
| Parameter textual value | 1,024 Unicode code points |
| New target textual stable ID | 512 Unicode code points |
| Existing finding ID | 512 Unicode code points |
| Existing system ID | 4,096 Unicode code points |
| Report reads per assistant operation | 2 |
| Report candidate scan/read bounds | Existing WS1-D 4,096 candidates and 10 MiB per report |

There are no retries, subprocesses, provider calls, network calls, database
queries, background tasks, or pagination in F.

F performs no semantic truncation. The fixed top-five priorities and top-three
next steps are explicit purpose-bounded selections with `omitted_item_count`;
they are not silent truncation. If a required claim, section, evidence set,
catalog, identifier, or safe text cannot fit its public bound without changing
security meaning, the operation fails closed. Necessary evidence MUST NOT be
dropped. A claim requiring more than 16 references MAY be split only when each
resulting claim remains independently true and fully grounded; otherwise it is
`INTEGRITY_FAILURE`.

## 23. Deterministic Ordering

Every collection has an exact order:

- capabilities: capability ID ASC, then numeric version ASC;
- expected effects: effect ID ASC;
- target kinds: enum declaration order;
- parameter specs and proposal parameters: key ASC;
- report IDs in comparison targets/evidence: `(previous, current)` chronology;
- sections: Section 8 precedence;
- briefing priorities and actions: existing deterministic Advisor priority;
- comparison claims: category precedence then finding ID ASC;
- coverage claims: category then `ScanDomain.value` ASC;
- other claims: contract-defined category then stable claim ID ASC;
- evidence: Section 9 canonical order.

Duplicate values are rejected unless a field explicitly models multiplicity.
No F ordering may depend on dictionary insertion, set iteration, filesystem
enumeration, hash randomization, locale, platform collation, provider/model
output, or wall-clock timing.

## 24. Error Contract and Translation

F reuses the existing closed `ApplicationErrorCode`, `ApplicationComponent`,
`ApplicationFailure`, and `CyberWatchtowerApplicationError` contracts. It adds
no error code or component.

| Condition | Code | Component | Retryable |
|---|---|---|---:|
| Wrong request type; malformed field; invalid chronology; invalid target/parameter shape | `INVALID_REQUEST` | `APPLICATION` | false |
| Unknown selected report or explicitly addressed current finding; cross-system report hidden from requested scope | `NOT_FOUND` | `STORAGE` | false |
| Unknown/stale capability version or prohibited capability | `AUTHORIZATION_DENIED` | `AUTHORIZATION` | false |
| Known capability marked unavailable | `COMPONENT_UNAVAILABLE` | `APPLICATION` | false |
| Report-root or report-file permission failure | Existing WS1-D safe mapping, including `PERMISSION_DENIED` | `STORAGE` | false |
| Other safe report storage failure | Existing WS1-D `STORAGE_FAILURE` mapping | `STORAGE` | false |
| Privacy projection impossible; secret/path/command proposal input | `PRIVACY_POLICY_BLOCKED` | `PRIVACY` | false |
| Incomplete snapshot; grounding contradiction; missing mandatory evidence; duplicate semantic identity; invalid internal catalog | `INTEGRITY_FAILURE` | `PROJECTION` for grounding, otherwise owning existing component | false |
| Unsupported frozen report/data shape | `COMPATIBILITY_FAILURE` | `PROJECTION` | false |
| Unexpected internal failure | `INTERNAL_FAILURE` | `APPLICATION` | false |

Unknown report and cross-system report failures MUST NOT reveal whether the
report exists outside the requested system. F MUST preserve any stricter safe
WS1-D storage mapping.

No raw OS, filesystem, SQLite, parser, Advisor, UUID, clock, provider, or Python
exception may escape or be retained in a public failure. Messages are fixed,
bounded, privacy-safe, and MUST NOT include the question, path, raw identifier
when sensitive, report content, command, SQL, traceback, secret, or exception
text.

## 25. Concurrency, Time, and Lifecycle

All four operations are synchronous and operation-owned. No thread-safety
promise is added to the facade. Concurrent invocation remains outside the F
contract.

Report-grounded operations use one WS1-D catalog snapshot per operation and
read at most two trusted reports through it. They are not database transactions
and do not access SQLite. Catalog and proposal operations are pure apart from
required UUID/time metadata. No lock, retry, timeout, cancellation token, job,
worker, event loop, or recovery record is introduced.

Report-grounded processing order is exact: generate the operation ID; validate
the request DTO; acquire and revalidate the one complete snapshot and selected
report(s); validate system binding and chronology; then build the briefing or
classify and answer the question. Thus an unsupported question does not bypass
report/system validation, and no question classification can authorize a read
outside the explicit scope.

## 26. Platform, Provider, and Legacy Boundaries

F is platform-neutral. It performs no platform detection, adapter selection,
collector call, native command, privilege request, or subprocess. Windows 11
x64, current Ubuntu LTS x86_64, and current Debian stable x86_64 remain official
1.0 platforms; Kali Rolling x86_64 remains an advanced/developer validation
target. Darwin MUST NOT route to Linux. Unknown platforms fail closed under the
existing assessment boundary.

No `ModelGateway`, provider SDK, provider network path, or provider DTO is used.
F local DTOs MUST NOT be labeled provider-safe. Provider/privacy-firewall work
remains WS8.

Public F operations MUST NOT expose or invoke:

- `IntelligenceOrchestrator.handle()`;
- legacy executable `CapabilityRegistry` handlers;
- direct SecurityMemory/database access;
- raw report loaders;
- provider gateways; or
- platform/native collectors.

Existing deterministic Advisor algorithms and core grounding compatibility
rules MAY be reused only through private application-owned bounded adapters that
consume trusted application projections and preserve this contract. Legacy
permission values MAY be privately translated but are not authoritative.

## 27. Security and Privacy Invariants

F MUST preserve all of the following:

- deterministic reports and reasoning remain authoritative;
- canonical reports are never rewritten by F;
- SecurityMemory remains derived and untouched by F;
- assistant text, capability metadata, and proposals are non-authoritative;
- no AI/model/provider creates a fact or authorization;
- no finding, score, coverage, assurance, firewall, reachability, or identity
  value is strengthened or reinterpreted;
- no raw filesystem path, username outside an already approved application
  field, command line, argv, stdout/stderr, SQL, native JSON, secret, token,
  credential, raw report fragment, or exception crosses the new boundary;
- local application privacy does not imply provider safety;
- system/report/finding references never cross exact system scope;
- unsupported/unknown closed values and contradictions fail closed.

F's additional sensitive/path/command scans are rejection-only defenses. A
string passing them is not thereby safe for a provider, log, notification, or
unrelated purpose.

Every new assistant section title, claim text, and evidence source identifier
MUST pass the existing sensitive-marker rejection plus the Section 16.2
path/command/shell rejection before entering a public result. If a required
authoritative identity or deterministic text fails, F MUST return
`PRIVACY_POLICY_BLOCKED`; it MUST NOT redact, replace, hash, or synthesize a new
identity. Optional presentation text MAY be omitted only when its omission is
explicitly counted and does not alter a claim or its necessary evidence.

## 28. Version, Schema, Construction, and Dependency Rules

`CyberWatchtowerApplication()` remains zero-argument and I/O-free at
construction. No public dependency injection is added. A private static catalog,
clock, UUID source, report seam, or deterministic adapter MAY exist for tests,
but production construction MUST remain zero-I/O and MUST expose none of them.

F introduces source-level Python DTOs only. It adds no wire schema, numeric
application API version, persistence schema, migration, dependency, package
metadata, CI change, configuration key, environment-variable contract, or
native guard. Report schema remains 1.7, Memory schema remains 8, and scoring
remains v2.

## 29. Acceptance Test Matrix

An F implementation is acceptable only when tests prove every item below.

| ID | Required proof |
|---|---|
| F-A | Exact four public method signatures and no aliases |
| F-B | Each operation ID is generated before request validation |
| F-C | `assistantop` syntax and UUID4 family |
| F-D | Every DTO is frozen, slotted, and deeply immutable |
| F-E | Zero-argument facade construction remains I/O-free |
| F-F | Exact `EffectClass` vocabulary |
| F-G | Exact application-owned `PermissionClass` vocabulary |
| F-H | Exact four-operation effect/permission mappings |
| F-I | Capability ID grammar and version syntax |
| F-J | Catalog deterministic numeric-version order |
| F-K | Duplicate capability ID/version is rejected |
| F-L | Catalog cannot exceed 64 entries |
| F-M | Metadata contains no executable handler/object |
| F-N | Proposal is immutable, ephemeral, and non-authorizing |
| F-O | Proposal ID grants no authority |
| F-P | Proposal expiry is exactly ten minutes |
| F-Q | Reuse policy is exactly `ONE_TIME` |
| F-R | Parameter canonical bytes and digest match independent fixtures |
| F-S | Input parameter order cannot change normalized tuple or digest |
| F-T | Secret/secret-looking values are rejected before digesting |
| F-U | Request and target system IDs bind exactly |
| F-V | No hostname fallback exists |
| F-W | Canonical report authority is preserved |
| F-X | No F operation reads SecurityMemory |
| F-Y | No F operation writes SecurityMemory |
| F-Z | No F operation writes a canonical report |
| F-AA | No provider or network path is invoked |
| F-AB | No subprocess or command path is invoked |
| F-AC | No platform detection is performed |
| F-AD | No background work is started |
| F-AE | Question limit is 4,096 code points |
| F-AF | Question remains ephemeral |
| F-AG | Question is absent from public failures/results/logging |
| F-AH | Supported intent vocabulary and cues are exact |
| F-AI | Ambiguous/unsupported questions do not guess |
| F-AJ | Claim epistemic states are exact |
| F-AK | `POSSIBLE` cannot be promoted |
| F-AL | `UNKNOWN` cannot be promoted |
| F-AM | Every claim has required compatible evidence |
| F-AN | Duplicate evidence ID/semantic identity is rejected |
| F-AO | Evidence order is deterministic |
| F-AP | Raw path forms are rejected and never exposed |
| F-AQ | Raw command/argv/shell forms are rejected and never exposed |
| F-AR | Raw exceptions are translated and suppressed |
| F-AS | Response section bound is enforced |
| F-AT | Claim count and total text bounds are enforced |
| F-AU | Per-claim and per-response evidence bounds are enforced |
| F-AV | Every text/identifier bound is enforced |
| F-AW | Section and claim ordering is deterministic |
| F-AX | Scores are preserved, never recalculated |
| F-AY | Firewall and reachability are never reinterpreted |
| F-AZ | Finding identity is unchanged |
| F-BA | Frozen WS1-E comparison semantics are reused |
| F-BB | Coverage uncertainty and uncertain disappearance remain explicit |
| F-BC | Malformed requests map to `INVALID_REQUEST` |
| F-BD | Unknown/stale capability maps to `AUTHORIZATION_DENIED` |
| F-BE | Prohibited capability maps to `AUTHORIZATION_DENIED` |
| F-BF | Unavailable capability maps to `COMPONENT_UNAVAILABLE` |
| F-BG | Grounding/catalog integrity failures map safely |
| F-BH | Unsupported frozen shape maps to `COMPATIBILITY_FAILURE` |
| F-BI | Privacy failure maps to `PRIVACY_POLICY_BLOCKED` |
| F-BJ | Unexpected failures map to private `INTERNAL_FAILURE` |
| F-BK | Report/Memory schemas and migrations are unchanged |
| F-BL | Dependencies and package metadata are unchanged |
| F-BM | CI configuration is unchanged by F implementation slices unless separately authorized |
| F-BN | All frozen A-E regression suites remain green |
| F-BO | Full portable suite is green |
| F-BP | Python 3.11, 3.12, and 3.13 CI is green before remote freeze |
| F-BQ | Windows secure persistence remains `OPEN / FAIL-CLOSED` |
| F-BR | Native guards are not required for portable F freeze |
| F-BS | WS1-G is not started |
| F-BT | Same snapshot reads no more than two explicitly selected reports |
| F-BU | Report/finding cross-system access fails without existence disclosure |
| F-BV | Target canonical bytes/digest match independent fixtures |
| F-BW | Changed target, version, or parameters changes the applicable binding |
| F-BX | Default materialization produces one canonical parameter digest |
| F-BY | Evidence omitted by bounded selection is counted, never silently dropped |

Focused tests MUST use private deterministic seams and MUST NOT run native
collection, real provider/network I/O, privileged work, or arbitrary commands.

## 30. Security Abuse Cases

| Abuse case | Required fail-closed behavior |
|---|---|
| Forged/unknown report ID in briefing/question | `NOT_FOUND`; no fallback or existence detail |
| Report from another system | `NOT_FOUND` within requested scope; no cross-system data |
| Finding from another report/system in `WHY_FINDING` | `NOT_FOUND`; only current selected report is searched |
| Opaque forged report/finding target in a pure proposal | Proposal remains inert and non-authorizing; future authorization/execution MUST revalidate and reject it; F MUST NOT claim existence |
| Duplicate evidence ID or semantic tuple | `INTEGRITY_FAILURE` |
| Missing mandatory evidence | `INTEGRITY_FAILURE`; no ungrounded claim |
| Malformed/unknown epistemic state | Construction failure or `COMPATIBILITY_FAILURE`; never defaulted upward |
| Oversized or control-bearing question | `INVALID_REQUEST`; raw text absent from failure |
| Secret-looking proposal value | `PRIVACY_POLICY_BLOCKED` before digesting |
| Unknown capability | `AUTHORIZATION_DENIED` |
| Stale/unknown capability version | `AUTHORIZATION_DENIED`; no fallback version |
| Prohibited capability | `AUTHORIZATION_DENIED` regardless of caller intent |
| Unavailable capability | `COMPONENT_UNAVAILABLE` |
| Altered proposal parameter order | Normalizes to the same sorted tuple/digest only when key/kind/value semantics are identical |
| Changed parameter value | Different digest; previous proposal cannot bind it |
| Changed target after proposal | Different target/digest; previous proposal cannot bind it |
| Changed capability version | Different required binding; previous proposal cannot bind it |
| Proposal expiry | At or after expiry, future validation MUST deny; F itself executes nothing |
| Attempted proposal reuse | Future execution MUST enforce `ONE_TIME`; F stores/consumes nothing |
| Proposal treated as approval | Deny; proposal and proposal ID grant no authority |
| Executable handler smuggled into metadata | DTO rejection or catalog `INTEGRITY_FAILURE` |
| Raw path injection | `PRIVACY_POLICY_BLOCKED`; never opened or exposed |
| Raw command/argv/shell injection | `PRIVACY_POLICY_BLOCKED`; never executed or exposed |
| Provider/network attempt | Boundary test failure; production F has no such dependency/path |
| Malformed legacy report shape | Existing safe `COMPATIBILITY_FAILURE`/WS1-D mapping; no guessed result |
| Incomplete report snapshot | `INTEGRITY_FAILURE`; no partial briefing/answer |
| Score-version change | Comparison states incomparability; no numeric trend claim |
| Incomplete coverage on disappearance | `POSSIBLE`/uncertain disappearance; never resolved |
| Raw exception contains a secret/path/question | Fixed safe application failure only |

## 31. Open Qualification Items

The following remain open release/platform qualifications and do not authorize
weakening F:

1. **Windows secure report persistence:** `OPEN / FAIL-CLOSED`. It does not
   block documentation-only F.2 or portable F implementation, but report-backed
   F operations cannot be fully qualified for Windows release until the secure
   persistence boundary is qualified.
2. **Linux source-referenced native validation guard:** later release
   requirement if still open. It does not block F.2 or portable F.
3. **Native Windows, Linux, and Kali qualification:** later platform/release
   work. F introduces no native behavior and does not run it now.

## 32. Explicitly Deferred Work

The following are DEFERRED and MUST NOT enter WS1-F implementation:

- WS1-G CLI migration;
- WS2 inventory/platform maturity;
- WS4 telemetry and detections;
- WS5 jobs, schedules, monitoring, alerts, notifications, retries, and
  cancellation;
- WS6 graph and the full Confidence Engine;
- WS7 baseline, Time Machine expansion, and investigations;
- WS8 provider integration, production model path, AI Privacy Firewall, and
  external-purpose DTOs;
- WS9 voice;
- WS10 GUI;
- broader WS11 configuration, secrets, logging, or diagnostics;
- WS12 packaging, signing, updates, or dependency changes;
- WS13 native/release qualification;
- authorization issuance/validation/persistence and capability execution;
- remediation, arbitrary commands, and privileged brokers;
- conversation/proposal persistence and automatic Memory context.

## 33. F.3 Public-Contracts-Only Allowlist

After owner review and freeze, the recommended initial F.3 implementation
allowlist is:

### Production files allowed to change

- `src/cyberwatchtower/application/contracts.py`
- `src/cyberwatchtower/application/__init__.py`

### Test files allowed to change/create

- `tests/test_application_contracts.py`
- new `tests/test_application_assistant_contracts.py`

`src/cyberwatchtower/application/errors.py` is omitted because this contract
adds no error code or component. It MUST NOT be touched in F.3 unless a newly
discovered frozen-contract contradiction receives separate owner resolution.

F.3 is public contracts only. It MUST NOT add facade methods, I/O,
orchestration, report reads, Advisor adapters, catalogs with runtime behavior,
proposal generation, provider code, production tests outside the allowlist, or
WS1-G behavior.

## 34. Contract Consistency Findings

This contract preserves the frozen parent boundaries:

- Current-system assessment remains `READ_ONLY` permission policy while its
  effect is accurately described as `SYSTEM_OBSERVATION`.
- Canonical saved reports remain authoritative, are read only through WS1-D,
  and are never written by F.
- SecurityMemory remains derived state and is neither read nor written by F.
- Provider integration and provider-safe classification remain deferred to WS8.
- Proposals and assistant output cannot authorize; CyberWatchtower cannot
  self-authorize.
- The question and local security data receive local classifications only.
- Windows persistence remains open/fail-closed; no platform assumption is
  weakened.
- `assistantop` IDs remain correlation-only and distinct from assessment,
  report, history, report identity, proposal, and authorization IDs.
- Report 1.7, Memory 8, scoring v2, finding identity, comparison, firewall,
  reachability, coverage, and assurance semantics remain unchanged.
- No Darwin-to-Linux path, new platform detection, schema, migration,
  dependency, package, CI, native behavior, or background work is introduced.

No parent-authority change is required by this contract.

## 35. Decisions Frozen by This Contract

This document freezes:

1. Exactly four synchronous F operations and the `assistantop` ID family.
2. Application-owned effect, permission, privacy, availability, target,
   parameter, epistemic, evidence, intent, outcome, and reuse vocabularies.
3. Exact F operation effect/permission mappings.
4. Explicit same-system report selection with at most two reports from one
   complete/revalidated snapshot.
5. No F Memory use, persistence, provider, native, subprocess, job, or
   authorization behavior.
6. Eleven non-executable version-1 capability metadata entries describing the
   frozen A-E application surface.
7. A fully bounded immutable proposal parameter and target representation.
8. Byte-exact parameter and target canonicalization and SHA-256 digests.
9. Ten-minute proposal lifetime and `ONE_TIME` future reuse policy.
10. The permanent rule that a proposal is not authorization.
11. Five deterministic assistant intents and non-guessing outcomes.
12. Four epistemic states without synthetic numeric confidence.
13. Bounded evidence references with source/role compatibility.
14. Exact resource ceilings, ordering, errors, abuse behavior, and acceptance
    tests.
15. A contracts-only F.3 allowlist.

## 36. Freeze Recommendation

**A. WS1-F.2 CONTRACT DRAFT COMPLETE — READY FOR OWNER REVIEW AND FREEZE**

This recommendation authorizes no implementation, staging, commit, push,
native validation, F.3 work, or WS1-G work.
