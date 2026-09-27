# ForensiTrace: An NTFS Forensic Timestomping Detector and Timeline Reconstructor

> **DOCUMENT STATUS: DRAFT — NOT FOR SUBMISSION YET**
>
> This is a working draft. Several sections below are incomplete and are marked
> `[TO COMPLETE]`. Results are currently from synthetic test data only and must
> not be submitted as forensic validation. See
> [Section 6: Limitations](#6-limitations) and the checklist in
> [Section 10: Before Submission](#10-before-submission).
>
> Convert to PDF only after the outstanding items are resolved.

---

| | |
|---|---|
| **Project title** | ForensiTrace — NTFS Forensic Timestomping Detector & Timeline Reconstructor |
| **Module** | Capstone project |
| **Team** | Five members (Person 1 – Person 5) |
| **Document version** | Draft 0.2 |
| **Last updated** | 2026-09-27 |
| **Status** | Incomplete — pending dataset, API layer, and validation |

---

## Abstract

Attackers who operate on a compromised Windows system have a simple way to
mislead a subsequent investigation: rewrite the timestamps that the operating
system displays for a file. This technique, known as *timestomping*, can make a
malicious file appear years older than it really is, defeating the first
chronological check almost every analyst performs. Traditional forensic
workflows struggle to detect it because they generally read the file system
metadata that has been altered, and the change leaves no obvious trace in the
place the analyst looked.

This project presents **ForensiTrace**, a tool that detects timestomping by
correlating three independent NTFS forensic artifacts — the Master File Table
(`$MFT`), the Change Journal (`$UsnJrnl`), and the Transaction Log (`$LogFile`)
— against one another rather than trusting any single one. The central
observation is that NTFS records the same logical facts in several places, and
that an attacker who edits one of them rarely edits all of them. By comparing
the `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp pairs stored inside each
MFT record, cross-referencing journal entries against committed metadata
changes, and using the transaction log to independently corroborate metadata
writes, the tool can surface tampering that a conventional timeline would miss.

The system is implemented in Python 3.11+ on top of the `dfir_ntfs` parsing
library, and is organised as a pipeline: artifact extraction, source-specific
parsing, metadata normalization, rule-based detection, additive risk scoring,
timeline reconstruction, and a FastAPI presentation layer. Five detection rules
are defined, four of which contribute to a per-file risk score.

**At the time of writing, the analysis core is complete and the input and
output layers are not.** The `$UsnJrnl` and `$LogFile` parsers, the
normalization layer, all five detection rules, the risk scoring model, and the
timeline reconstructor are implemented and execute correctly against synthetic
test data. The `$MFT` parser, the API and dashboard, and the report generator
are not yet implemented, and no scenario has yet been run against a real disk
image. Consequently, the results reported in Section 5 demonstrate internal
consistency and correct behaviour on constructed inputs, and **do not
constitute validation of forensic detection capability.** This limitation is
stated plainly rather than deferred, and the work required to lift it is
specified in Section 9.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background and Related Work](#2-background-and-related-work)
3. [Objectives](#3-objectives)
4. [System Design](#4-system-design)
5. [Implementation and Results](#5-implementation-and-results)
6. [Limitations](#6-limitations)
7. [Discussion](#7-discussion)
8. [Conclusion and Future Work](#8-conclusion-and-future-work)
9. `[TO COMPLETE]` Outstanding Work Plan
10. [Before Submission](#10-before-submission)
11. [References](#11-references)
12. [Appendices](#12-appendices)

---

## 1. Introduction

### 1.1 Problem statement

When a file is created or modified on a Windows system, NTFS records four
timestamps for it: when it was created, when its contents were last written,
when its MFT entry was last changed, and when it was last accessed. These are
stored in the `$STANDARD_INFORMATION` (`$SI`) attribute of the file's MFT
record, and they are the values Windows Explorer displays.

An attacker with write access to a file can overwrite these values directly.
The result is a file whose displayed age is false. In practice this is used to
make a malicious payload look like a legitimate system file, to push a
compromised file's timestamp outside the incident window, or to frustrate
timeline-based triage.

The difficulty is that the alteration is invisible from the altered field
alone. An analyst who reads `$SI` sees a perfectly well-formed 2019 timestamp
and has no reason to doubt it. Detection requires an *independent* source of
truth.

### 1.2 Why NTFS makes this detectable

NTFS is unusual among file systems in recording the same facts in several
independent places, and it was designed for crash consistency rather than
forensic clarity. Three artifacts matter here:

| Artifact | What it is | Why it helps |
|---|---|---|
| `$MFT` | The Master File Table — one record per file, holding `$SI` and `$FN` attributes | `$SI` and `$FN` hold *two* copies of the same four timestamps. They are written at different times, so they drift apart naturally, and a timestomper typically updates only one. |
| `$UsnJrnl:$J` | The USN Change Journal — an append-only log NTFS writes *before* committing a change | Records that a metadata change happened, including `BASIC_INFO_CHANGE` for timestamp writes. Cannot be edited retroactively without leaving further gaps. |
| `$LogFile` | The NTFS transaction log — redo/undo records used for crash recovery | Contains the *actual bytes* of metadata writes, including the timestamps NTFS itself wrote. Independent confirmation that does not depend on the current on-disk state. |

The `$SI`/`$FN` divergence is the single most useful signal. Because the two
attributes are updated at different moments, a file that has been renamed
naturally shows different `created` and `mft_modified` values in each. This
produces false positives, which is why a naive inequality test is not
sufficient on its own — a point we return to in Section 4.3.

### 1.3 Project scope

The project deliberately builds a **small, verified** tool rather than a broad
one. A hand-built dataset of a handful of known scenarios is planned, so that
every detection claim can be checked against a recorded ground truth.

Explicitly **out of scope**, and not built: recovery of deleted-file metadata,
machine-learning-based detection, analysis of unconstrained full-volume images,
and statistical signature sampling. These appeared in earlier project
discussion and were consciously excluded to keep the deliverable finishable and
defensible.

---

## 2. Background and Related Work

### 2.1 NTFS internals

NTFS organises a volume into *clusters*, managed through the Master File Table.
Each MFT record (typically 1 KB) describes one file system object and contains
numbered *attributes* holding the object's metadata. Two are central to this
project:

- **`$STANDARD_INFORMATION` (`$SI`)** — fixed-size, holding the four timestamps
  (creation, last write, last MFT change, last access) plus DOS-mode
  attributes.
- **`$FILE_NAME` (`$FN`)** — variable-length, holding the file name and parent
  reference, with its *own* set of the same four timestamps.

Because a rename updates the `$FN` but not the `$SI`, the two attributes
routinely disagree on a legitimate file. Timestomping tools that rewrite `$SI`
alone therefore create a divergence that is *structurally identical* to normal
operation. Distinguishing the two is the core analytical problem, and it is
why ForensiTrace uses corroborating sources rather than relying on `$SI`/`$FN`
comparison by itself.

Timestamps are stored as 64-bit Windows `FILETIME` values — 100-nanosecond
intervals since 1 January 1601. Many timestomping utilities write
round/aligned values, which is the basis of Rule 3.

### 2.2 Prior work and tool landscape

Commercial and open-source timestomping tools are widely documented, including
`timestomp`, `SetFileTime`, and PowerShell's `System.IO.File` timestamp
setters. Their common weakness is that they operate on one API and therefore
update `$SI` without updating the `$FN` copy or the journal.

On the defensive side, existing forensic tooling tends to fall into two
categories. Timeline tools (Plaso/`log2timeline`, Timesketch) reconstruct
sequences from multiple event sources and are excellent at ordering events, but
they generally trust the timestamps they are given and do not cross-validate
NTFS attributes against one another. Disk-imaging and analysis suites
(FTK Imager, Sleuth Kit) provide excellent extraction and MFT decoding, but
present `$SI` and `$FN` as data to be read rather than as a consistency
problem to be tested.

The gap ForensiTrace addresses is narrow and specific: **there is no widely
available tool whose primary job is to treat NTFS timestamp redundancy as an
integrity signal and to score the inconsistency.** Most related work treats
these artifacts as sources of events to be merged, not as mutually
cross-validating claims about the same fact.

### 2.3 The `dfir_ntfs` library

Rather than implement NTFS binary formats from scratch, the project uses
`dfir_ntfs` (version 1.1.18), an open-source Python library that decodes `$MFT`
records, the USN change journal, and — significantly for this project — the
`$LogFile` transaction log. Its `$LogFile` support was confirmed to exist
during development, which resolved an early project risk: the transaction log
had been flagged as a possible custom-implementation task, and it turned out
to be available off the shelf. This is a favourable outcome for the schedule
and is discussed further in Section 7.

---

## 3. Objectives

The project set out to:

1. Parse `$MFT`, `$UsnJrnl`, and `$LogFile` artifacts from a Windows NTFS
   volume into structured records.
2. Normalise all three sources into a single common record format, so that
   cross-source reasoning is possible.
3. Implement and justify a set of detection rules for timestamp tampering.
4. Produce a per-file risk score from the triggered detections.
5. Reconstruct a single chronological timeline merging all three sources.
6. Expose results through an API and dashboard, and generate an exportable
   investigation report.
7. Validate every rule against a hand-built dataset with recorded ground truth.

Objectives 1–5 and 7 are partially met; objective 6 is not started. The
status of each is summarised in Section 5.

---

## 4. System Design

### 4.1 Pipeline architecture

ForensiTrace is structured as a linear pipeline with a frozen contract at its
centre:

```text
Windows evidence image
        │
        ▼
  Artifact extraction          $MFT | $UsnJrnl:$J | $LogFile
        │
        ▼
  Source-specific parsers      usnjrnl_parser │ logfile_parser │ mft_parser
        │
        ▼
  Normalization                normalizer.py  ──►  list[ParsedRecord]
        │
        ▼
  Analysis                     rules.py  (Rules 1–5)
                               scoring.py (risk model)
                               timeline.py (merge & sort)
        │
        ▼
  Presentation                 FastAPI API │ Jinja2 dashboard │ report
```

The central design decision is the **frozen schema**. `backend/models/schemas.py`
defines the record and result types once, and every module imports them. No
layer redefines a type locally. This was adopted specifically to allow five
people to work in parallel without integration failure, and it worked: no
module in the project redefines a shared model.

A consequence worth noting is that the project is **decoupled at the data
boundary rather than the code boundary**. Layers do not call each other; they
exchange lists of schema objects. This made parallel development possible, and
it also means the pipeline can be run stage by stage from a notebook or script,
which is how the results in Section 5 were produced.

### 4.2 The shared record format

All three sources normalise into a single `ParsedRecord` carrying a
`file_reference` in `"segment:sequence"` form (e.g. `"1234:5"`), which is the
key that allows records from different artifacts to be joined. Source-specific
detail is preserved in optional fields — `usn_reason` and `usn_timestamp` for
the journal, `logfile_operation` and `logfile_timestamp` for the transaction
log — and every record additionally retains a `raw` dictionary of the original
parser fields.

Retaining `raw` is not incidental. Rule 3 depends on the original 100-nanosecond
integer values, which are lost once a timestamp is formatted as a readable
ISO-8601 string. Preserving the raw values is what makes that rule possible at
all, and it also means any detection can be traced back to the bytes that
produced it.

### 4.3 Detection rules

Five rules were defined. Full conditions are in `docs/detection-rules.md`; the
rationale is summarised here.

**Rule 1 — `$SI`/`$FN` mismatch (+30).** Compares each of the four timestamps
in `$SI` against the corresponding timestamp in `$FN`. Any single divergence
triggers. This is the highest-weighted rule because it is the most direct
evidence of timestomping: the file system holds two copies of the same fact
and they disagree.

The honest weakness of this rule is that a divergence is *also* the normal
signature of a legitimate rename. We use exact inequality with no tolerance
window, so the rule will produce false positives on renamed files. This is
accepted for the current version, on the reasoning that `$LogFile` and USN
corroboration (Rules 2 and 5) are the intended defence, and a conservative
rule that over-reports combined with corroboration is preferable to an
aggressive rule that under-reports. Validating the threshold against ground
truth remains outstanding work.

**Rule 2 — USN `BASIC_INFO_CHANGE` correlated with an MFT change (+25).** The
journal is written before a change is committed, so a `BASIC_INFO_CHANGE`
entry is NTFS's own testimony that a metadata write occurred. The rule
requires both the journal entry *and* a visible change in the corresponding
MFT record, which prevents the rule firing on journal entries whose effect was
never committed. This is the strongest single rule in principle, because both
halves are written by the operating system rather than by the attacker.

**Rule 3 — Second-boundary timestamp alignment (+20).** Tests retained raw
100-nanosecond values for divisibility by 10,000,000 — that is, whether the
timestamp lands exactly on a second boundary. Naive timestomping scripts
frequently write round values, so this catches a common tooling pattern.

The rule's name is misleading and we record this as a known defect: the
identifier `RULE_3_TIMESTAMP_ZEROING` suggests it detects *zeroed* timestamps,
but the test detects second-boundary alignment generally, which is a broader
and different condition. The identifier is fixed by the frozen schema and
cannot be renamed without breaking every other module, so the behaviour is
documented rather than the name changed. Ideally the rule would test for
values near zero or near the epoch, and the naming should be revisited if the
schema is ever unfrozen.

**Rule 4 — Suspicious event sequence (0).** Looks for the ordered sequence
`create → modify → timestamp_change → rename → delete` on a single file. The
premise is that no individual operation is suspicious, but anti-forensic
tooling tends to run a characteristic sequence. It carries **no score weight**
in the current version, so it cannot by itself affect risk.

This rule is the least mature. It requires all five events in exactly that
order with no gaps, which is unlikely to hold on genuine evidence, and several
of its events can be synthesised from a single record's fallback timestamps
rather than from real observations. It is reported as implemented but
unvalidated.

**Rule 5 — `$LogFile` corroboration (+15).** When a file already has a
triggered Rule 1, 2, or 3 finding, this rule looks for an independent
`$LogFile` record for the same file reference. If found, it attaches
corroboration metadata to the original finding and adds a bonus score.

This is the only rule that uses all three artifacts simultaneously, and it is
the clearest expression of the project's central thesis. It is deliberately
incapable of establishing a finding on its own — a `$LogFile` record with no
matching Rule 1–3 finding produces nothing — because the transaction log
records many operations that have nothing to do with timestamps, and treating
any of them as evidence of tampering would be unsound.

### 4.4 Risk scoring

Scores are additive per file. Weights are Rule 1 +30, Rule 2 +25, Rule 3 +20,
Rule 5 +15, Rule 4 +0. Buckets are `LOW` for 0–24, `MEDIUM` for 25–54, and
`HIGH` for 55 and above.

A structural consequence of these weights is worth stating, because it affects
how results should be read: **a single Rule 1 detection is categorised
`MEDIUM` and can never reach `HIGH` on its own.** Reaching `HIGH` requires at
least three independent rules to fire on the same file. This is defensible —
`HIGH` should mean corroborated, not merely suspected — but it means the
`HIGH` category will be rare until cross-source correlation is working on real
data.

These weights are the original design placeholders. They have not been
calibrated against ground truth and must not be presented as empirically
derived. Calibration is listed as outstanding work.

### 4.5 Timeline reconstruction

Records from all three sources are expanded into individual `TimelineEvent`
objects and merged into one chronologically sorted list. Event types are
normalised to a small controlled vocabulary — `create`, `modify`,
`timestamp_change`, `rename`, `delete` — with an alias table so that the
various spellings NTFS uses (`BASIC_INFO_CHANGE`, `RENAME_NEW_NAME`,
`UpdateResidentValue`, and so on) collapse onto it. The sort raises an error on
an unparseable timestamp rather than silently dropping or misordering an
event, on the principle that a forensic timeline with a silently wrong ordering
is worse than one that fails loudly.

---

## 5. Implementation and Results

### 5.1 What has been implemented

| Component | Module | Lines | State |
|---|---|---:|---|
| Shared schemas | `models/schemas.py` | 74 | Complete |
| `$UsnJrnl` parser | `parsers/usnjrnl_parser.py` | 103 | Complete, tested |
| `$LogFile` parser | `parsers/logfile_parser.py` | 175 | Complete, tested |
| Normalization | `normalization/normalizer.py` | 177 | Complete, tested |
| Rules 1–5 | `analysis/rules.py` | 429 | Complete, untested |
| Risk scoring | `analysis/scoring.py` | 89 | Complete, untested |
| Timeline | `analysis/timeline.py` | 155 | Complete, untested |
| `$MFT` parser | `parsers/mft_parser.py` | 0 | **Not implemented** |
| API application | `main.py`, `api/routes.py` | 0 | **Not implemented** |
| Report generator | `services/report_service.py` | 0 | **Not implemented** |
| Dashboard | `dashboard/` | — | **Does not exist** |
| Dataset | `dataset/` | — | **Does not exist** |

### 5.2 The `$LogFile` recovery path

One implementation detail deserves specific mention, because it represents the
most substantial technical work in the project.

Recovering a usable timestamp from `$LogFile` is not a matter of iterating log
records. A log record contains a *reference to an index* in the Open Attribute
Table, not the file it refers to, and the only structure in the log that maps
that index to both a file reference and an attribute type code is the periodic
`OpenAttributeTableDump` snapshot. The parser therefore resolves each record's
target in two stages: first against the incrementally-built open-attribute
dictionary, then against the most recent table dump. Only the second path
yields an attribute type code, and therefore only the second path can identify
a `$STANDARD_INFORMATION` update.

Timestamps are then recovered from a narrow condition: the redo operation must
be `UpdateResidentValue` or `UpdateNonresidentValue`, the target must be
`$STANDARD_INFORMATION` (type code `0x10`), and the redo data must begin at
offset 0 — where `$STANDARD_INFORMATION` stores its four `FILETIME` values in a
fixed order, unpacked directly as four little-endian 64-bit integers.

The consequence is that **the majority of `$LogFile` records do not resolve to
a file reference and are discarded during normalization.** This is a real
limitation, not an implementation shortcut: the transaction log records many
operations that carry no recoverable timestamp. It does mean Rule 5's evidence
base is much smaller than the raw log, and this is stated in the documentation
rather than glossed over.

### 5.3 Verification performed

**Automated tests.** The test suite was executed on 2026-09-27 in a clean
virtual environment:

```text
17 passed in 0.15s
```

These cover the `$UsnJrnl` parser's reason-flag decoding, file-reference
packing and timestamp formatting; the `$LogFile` parser's attribute-name
resolution and `$STANDARD_INFORMATION` field decoding, including the
short-buffer case; and the normalizer's three-source merge, USN field
propagation, skipping of unresolved `$LogFile` records, and — importantly — a
**schema-drift guard** that validates every fixture record against
`ParsedRecord`, so that any silent divergence between the frozen schema and the
fixtures fails the build.

**End-to-end run on fixtures.** The full analysis chain
(`run_rules` → `calculate_risk_scores` → `build_timeline`) was executed over
the synthetic fixture set:

| File | Rule triggered | Score | Risk level |
|---|---|---:|---|
| `timestomped.exe` | Rule 1 | 30 | MEDIUM |
| `zeroed.dll` | Rule 3 | 20 | LOW |
| `clean_file.txt` | none | 0 | LOW |
| `renamed_file.txt` | none | 0 | LOW |

This produced 10 findings, 4 risk scores, and a 4-event timeline sorted
correctly across the `MFT` and `UsnJrnl` sources. The computed scores match
the independently hand-written `sample_risk_scores.json` fixture exactly.

### 5.4 What the results do and do not show

This subsection is deliberately explicit, because the distinction is easy to
lose in a report and would be easy to overstate in a submission.

**What the results demonstrate.** The pipeline is correctly wired end to end.
Rules fire on the records they are designed to fire on. The two negative
controls remain silent, which is the minimum evidence that the rules are
discriminating rather than flagging everything. Risk aggregation behaves as
specified. The timeline merges and orders events from multiple sources
correctly. The implementation is internally consistent.

**What the results do not demonstrate.** They do not demonstrate that
ForensiTrace detects timestomping. The two positive results are the code
agreeing with input that was hand-written specifically to make it agree. There
is no attacker in this loop, no real volume, and no ground truth. A system
tested this way could be entirely wrong about real NTFS behaviour and still
pass every check reported here.

**Coverage of the rules by these results is partial:**

| Rule | Exercised? | Notes |
|---|---|---|
| Rule 1 | Yes | Triggers correctly on the constructed mismatch; silent on the control |
| Rule 2 | **No** | No fixture contains a `BASIC_INFO_CHANGE` record; rule produced no output |
| Rule 3 | Yes | Triggers on the constructed aligned value |
| Rule 4 | **No** | No fixture contains the full five-event sequence; never triggered |
| Rule 5 | **No** | No `LogFile`-sourced fixture records exist; rule produced no output |

Four of the five rules — including Rule 5, which is the project's central
thesis — have never been observed to fire. This is the most important single
statement in this report regarding the current state of the work.

### 5.5 Screenshots and report output

`[TO COMPLETE — dashboard screenshots and a sample generated investigation
report will be inserted here once the API layer and report generator are
implemented. Neither exists at present, so no screenshots can be included.]`

---

## 6. Limitations

The following limitations bound every claim in this report. They are listed
individually because each one independently limits what the project can
conclude.

1. **No `$MFT` parser.** `backend/parsers/mft_parser.py` is an empty file. Rule
   1 operates only on `MFT`-sourced records, so the project's central
   detection rule has never been executed against a real Master File Table.
   This is the single most consequential gap in the project.

2. **No ground-truth dataset.** No scenario has been performed on a real NTFS
   volume. There are no artifact extracts and no recorded expected results, so
   no rule can be said to be validated.

3. **Synthetic test data only.** All verification to date uses four
   hand-written fixture records, authored by the same team that wrote the
   detection code. This is a self-consistency check, not independent
   validation, and the two are easy to confuse when reporting results.

4. **Rules 2, 4 and 5 unexercised.** As set out in Section 5.4, three of the
   five rules have produced no output on any available data.

5. **Scoring is uncalibrated.** The weights and risk buckets are design
   placeholders. They have not been validated against ground truth, and the
   resulting risk levels should not be interpreted as empirically grounded.

6. **No automated tests for the analysis layer.** All 17 tests cover parsing
   and normalization. The detection rules, scoring model, and timeline
   reconstructor — the parts that produce the project's actual conclusions —
   have no test coverage at all.

7. **Rule 1 will produce false positives.** The `$SI`/`$FN` comparison uses
   exact inequality with no tolerance, and a legitimate rename produces a
   divergence structurally identical to timestomping. The intended mitigation
   is corroboration via Rules 2 and 5, which is precisely the part not yet
   validated.

8. **Second-level timestamp precision.** Parsers format timestamps as
   `%Y-%m-%dT%H:%M:%SZ`, discarding sub-second precision. A timestomper
   shifting a timestamp by a few hundred milliseconds would be invisible to
   Rule 1's string comparison. Comparing raw 100-nanosecond integers would fix
   this and is listed as future work.

9. **Incomplete path resolution.** `UsnJrnl` and `LogFile` records cannot
   produce a real `full_path`; the normalizer falls back to the bare file name
   or the file reference. This is marked `TODO-INTEGRATION` in the code.
   Consequently `full_path` is unreliable for two of the three sources,
   including in Rule 5, whose representative record is always
   `LogFile`-sourced.

10. **Narrow `$LogFile` recovery.** Only `UpdateResidentValue` and
    `UpdateNonresidentValue` redo operations targeting `$STANDARD_INFORMATION`
    at redo offset 0 yield timestamps. Most log records resolve to no file
    reference and are discarded, so Rule 5's evidence base is substantially
    smaller than the raw transaction log.

11. **Corroboration is presence-based.** Rule 5 treats the existence of a
    `$LogFile` record for a file reference as corroboration without verifying
    that the logged operation is timestamp-relevant. A log entry for an
    unrelated attribute update on the same file would currently count.

12. **No API, dashboard, or report generator.** `main.py`, `routes.py`, and
    `report_service.py` are empty and the `dashboard/` directory does not
    exist. The tool is not currently servable, and the project cannot be
    demonstrated end to end.

13. **Not adversarially tested.** No attempt has been made to determine
    whether an attacker aware of these five rules could timestomp without
    triggering them. In particular, updating `$SI` and `$FN` together and
    clearing the journal would defeat Rules 1 and 2 respectively. Whether
    `$LogFile` would still catch such an attempt is untested and is the most
    interesting open question about the tool.

14. **Scale is untested.** The dataset is intended to be small by design, but
    no performance measurement has been made, and the per-file cross-source
    joins in Rules 2, 4, and 5 are implemented as linear scans that would not
    scale to a full volume.

---

## 7. Discussion

### 7.1 What worked

**Freezing the schema first was the right call.** The single most effective
decision was publishing the shared Pydantic models and fixture files on day one
and requiring every module to import rather than redefine them. Five people
working concurrently on parsers, detection logic, and a web layer is a
combination that normally produces integration failure, and it did not. One
test in the suite exists purely to catch schema drift, which suggests the team
treated the contract as genuinely binding.

**Building against fixtures before real data existed was also correct, and it
is what made progress possible at all.** With no Windows volume available to
everyone at once, the fixture-first approach let every module be developed and
independently tested. The cost is the weakness this report spends Section 6
discussing: the fixtures are self-authored, so passing them proves very little.

**Using `dfir_ntfs` throughout was a schedule decision that paid off.** The
`$LogFile` parser had been flagged as the project's highest schedule risk on
the grounds that it might require a custom implementation following published
carving research. Confirming library support removed that risk entirely and
freed the team to spend its time on detection logic, which is where the
project's value actually lies. This was the right order of investigation: a
two-hour check removed a risk that had been carrying a contingency plan.

### 7.2 What did not work

**The `$MFT` parser was left to the end and is now the critical path.** It was
the natural candidate to defer, since the schema, fixtures, and two of three
parsers could proceed without it. But because Rule 1 — the rule the whole
project is premised on — operates exclusively on `MFT`-sourced records, deferring
the parser deferred the project's central validation. A parallel development
strategy that keeps the most important component off the critical path will
eventually put it *on* the critical path.

**Validation was sequenced too late.** The plan called for Rules 1–3 to be
validated against real ground truth at the project's midpoint, as a go/no-go
checkpoint. Because the `$MFT` parser and the dataset both slipped, that
checkpoint has not happened, and the project is now carrying three unexercised
rules into its final phase. A checkpoint that can slip without stopping work is
not a checkpoint.

### 7.3 Honest assessment

The project has a **complete and tested input-processing layer, a complete but
untested analysis layer, and no output layer.** Describing it as "a working
timestomping detector" would overstate it. The accurate description is that the
analytical core of such a detector is built, that it behaves correctly on
constructed inputs, and that its central claim — that cross-correlating three
NTFS artifacts reveals tampering a single artifact hides — remains
**plausible but unproven.**

The design decisions that matter most to that claim are sound and, in the case
of the `$SI`/`$FN` redundancy and the `$LogFile` recovery path, reflect genuine
forensic reasoning. What is missing is evidence.

---

## 8. Conclusion and Future Work

ForensiTrace implements a cross-artifact approach to NTFS timestomping
detection. Its design rests on a defensible premise: NTFS stores redundant
copies of the same timestamp facts in the `$SI` and `$FN` attributes, records
metadata changes in an append-only journal before committing them, and writes
its own transaction log — and an attacker who falsifies one of these rarely
falsifies all three. Five detection rules, an additive risk model, and a merged
three-source timeline are built on that premise and execute correctly on
synthetic inputs.

The project is not yet a validated forensic tool, and the gap between "works on
constructed data" and "works on real evidence" is currently bridged by nothing
at all. The immediate priority is closing it.

**Immediate work, in order:**

1. Implement `mft_parser.py` and validate Rule 1 against a real `$MFT`. This
   is the project's critical path and its core proof of concept.
2. Build the hand-built dataset with recorded ground truth, including
   negative controls, and validate Rules 1–3 against it.
3. Add automated tests for the analysis layer, which currently has none.
4. Construct a scenario that requires `$LogFile` evidence, and validate Rule 5
   end to end.
5. Implement the API, dashboard, and report generator; re-point them from
   fixtures to real pipeline output.

**Longer-term work:**

6. Replace Rule 1's string comparison with raw 100-nanosecond integer
   comparison, to remove the sub-second blind spot.
7. Add a tolerance window to Rule 1 and calibrate it against ground truth, to
   control false positives from legitimate renames.
8. Make Rule 5 verify that the logged operation is timestamp-relevant, rather
   than accepting any log record for the file reference.
9. Resolve full paths for `UsnJrnl` and `LogFile` records by walking
   `parent_file_reference` against the MFT record set.
10. Revisit Rule 4's strict sequence matching, and rename Rule 3 if the schema
    is ever unfrozen.
11. Adversarial evaluation: attempt timestomping that evades all five rules,
    and document what is missed.
12. Calibrate the scoring weights against ground truth.

---

## 9. Outstanding Work Plan

`[TO COMPLETE — to be filled in once the deadline and grading rubric are
confirmed. Neither was specified in the project material available at the time
of writing, which is itself a project risk: the team cannot confirm that the
remaining work fits the available window.]`

---

## 10. Before Submission

`[TO COMPLETE — checklist. This document must not be converted to PDF and
submitted until every item below is resolved.]`

- [ ] `$MFT` parser implemented and Rule 1 validated against a real `$MFT`
- [ ] Ground-truth dataset built, with negative controls, and all rules
      validated against it
- [ ] Automated tests added for the analysis layer
- [ ] Rules 2, 4 and 5 each observed to fire on at least one real scenario
- [ ] API, dashboard and report generator implemented and serving real pipeline
      output
- [ ] Section 5.4 and Section 6 rewritten to reflect the real validation
      results, removing the "synthetic data only" framing
- [ ] Section 5.5 populated with dashboard screenshots and a sample report
- [ ] Scoring weights calibrated against ground truth, or explicitly presented
      as uncalibrated design choices
- [ ] Section 9 completed with the real deadline and grading rubric
- [ ] Full reference list verified — no citation may be included that has not
      been checked against the actual source
- [ ] Proofread end to end
- [ ] Confirm `pytest` passes from a clean checkout
- [ ] Confirm the documented setup instructions work on a clean clone

---

## 11. References

`[TO COMPLETE — full reference list. Entries below are working notes and must
each be verified against the actual source before submission. Do not submit an
unverified citation.]`

1. Microsoft. *Windows Internals, Part 1: System architecture, processes, threads,
   memory management, and more.* 7th ed. Microsoft Press.
   — Standard reference for NTFS `$STANDARD_INFORMATION` and `$FILE_NAME`
   attribute structure and `FILETIME` semantics.

2. Carrier, B. *File System Forensic Analysis: Theory, Investigation, and
   Recovery.* Addison-Wesley Professional, 2005.
   — Foundational treatment of file system metadata forensics.

3. `dfir_ntfs` library, version 1.1.18. `github.com/msuhanov/dfir_ntfs`
   — The parsing library used throughout. Provides `$MFT`, `$UsnJrnl`, and
   `$LogFile` decoding.

4. "$LogFile" recovery via carving research, cited in our project plan as
   *"Forensic Recovery of File System Metadata"* (2022).
   **`[TO COMPLETE — the project plan recorded only a partial citation. The
   full author list, publication venue and title must be obtained from the
   project team before this entry can be used. It was consulted to scope the
   `$LogFile` work, although the final implementation relies on `dfir_ntfs`
   rather than on custom carving.]`**

5. SANS Institute white papers on NTFS artifact analysis and timestomping.
   **`[TO COMPLETE — specific papers to be cited once identified.]`**

---

## 12. Appendices

### Appendix A — Project structure

```text
backend/
  main.py                      [EMPTY]      ASGI entrypoint
  api/routes.py                [EMPTY]      API endpoints
  models/schemas.py            74 lines     Frozen shared contract
  parsers/mft_parser.py        [EMPTY]      $MFT parser
  parsers/usnjrnl_parser.py    103 lines    $UsnJrnl parser
  parsers/logfile_parser.py    175 lines    $LogFile parser
  normalization/normalizer.py  177 lines    Three-source merge
  analysis/rules.py            429 lines    Rules 1-5
  analysis/scoring.py          89 lines     Risk model
  analysis/timeline.py         155 lines    Timeline reconstruction
  services/report_service.py   [EMPTY]      Report generation
config/settings.py             [EMPTY]      Configuration
docs/                          Documentation
fixtures/                      4 synthetic JSON files
tests/                         3 test files, 17 tests
dataset/                       [ABSENT]     Ground-truth scenarios
dashboard/                     [ABSENT]     Jinja2 templates
```

### Appendix B — Detection rule summary

| Rule | ID | Weight | Status |
|---|---|---:|---|
| `$SI`/`$FN` mismatch | `RULE_1_SI_FN_MISMATCH` | +30 | Implemented, exercised on synthetic data only |
| USN basic-info change | `RULE_2_USN_BASIC_INFO_CHANGE` | +25 | Implemented, **not exercised** |
| Second-boundary alignment | `RULE_3_TIMESTAMP_ZEROING` | +20 | Implemented, exercised on synthetic data only |
| Suspicious sequence | `RULE_4_SUSPICIOUS_SEQUENCE` | 0 | Implemented, **never triggered** |
| `$LogFile` corroboration | `RULE_5_LOGFILE_CORROBORATION` | +15 | Implemented, **not exercised** |

Risk buckets: `LOW` 0–24, `MEDIUM` 25–54, `HIGH` 55+. Uncalibrated.

### Appendix C — Verification commands

```bash
# Environment
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Test suite — expect 17 passed
pytest

# Analysis core on fixtures
python -c "
import json
from backend.models.schemas import ParsedRecord
from backend.analysis.rules import run_rules
from backend.analysis.scoring import calculate_risk_scores
from backend.analysis.timeline import build_timeline
records = [ParsedRecord(**r) for r in json.load(open('fixtures/sample_parsed_records.json'))]
findings = run_rules(records, 'SCEN-001')
for s in calculate_risk_scores(findings):
    print(s.full_path, s.total_score, s.risk_level, s.triggered_rules)
"
```

Verified 2026-09-27 on Python 3.14.7, Linux, `dfir_ntfs` 1.1.18, Pydantic 2.13.5.
