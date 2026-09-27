# Detection Rules

_Verified against commit `0529dcc` on 2026-09-27._

## Current implementation state

All five rules are **implemented and executable**. Rules 1–5 live in `backend/analysis/rules.py` and are driven by `run_rules(records, scenario_id)`, which returns a flat `list[DetectionResult]` in rule order.

What is *not* true of this page:

- No rule has been validated against real forensic evidence. The `$MFT` parser is still an empty file, so Rule 1 — the project's central check — has never run on a real `$MFT`.
- There is no ground-truth dataset to score the rules against.
- The analysis layer has no automated tests. The 17 passing tests cover parsing and normalization only.

Every rule emits one `DetectionResult` per candidate record, with `triggered` set to `True` or `False`. A rule that has nothing to say about a record emits nothing at all, so an absent result is not the same as a `triggered=False` result.

## Rules

### Rule 1 — `$SI`/`$FN` timestamp mismatch

**ID:** `RULE_1_SI_FN_MISMATCH` · **Weight:** +30

**What it does:** For every `MFT`-sourced record that has a `$FN` (`file_name_times`) attribute, compares each of the four timestamps in `$SI` (`std_info_times`) against the matching timestamp in `$FN`. If any single pair differs, the rule triggers.

```python
for field in ("created", "modified", "mft_modified", "accessed"):
    if record.std_info_times.<field> != record.file_name_times.<field>:
        mismatches[field] = {"si": ..., "fn": ...}
```

**Why it matters:** NTFS stores timestamps twice — once in `$STANDARD_INFORMATION` and once in `$FILE_NAME`. Timestomping tools typically rewrite only one of the two. A file whose displayed timestamp says 2019 but whose `$SI` says 2026 is direct evidence of manipulation.

**Threshold:** exact string inequality on ISO-8601 values. There is no tolerance window. A one-second difference triggers the rule.

**Evidence emitted:** `{"mismatches": {field: {"si": ..., "fn": ...}}}`

**Known weakness:** the comparison is on *formatted* ISO-8601 strings truncated to whole seconds by the parser (`%Y-%m-%dT%H:%M:%SZ`). Sub-second differences are invisible, so a tool that shifts a timestamp by a few hundred milliseconds would be missed. A stricter implementation would compare the raw 100-ns integers.

### Rule 2 — USN basic-information change correlated with an MFT change

**ID:** `RULE_2_USN_BASIC_INFO_CHANGE` · **Weight:** +25

**What it does:** For every `UsnJrnl`-sourced record whose `usn_reason` list contains `BASIC_INFO_CHANGE`, looks up the `MFT`-sourced record with the same `file_reference`. The rule triggers only if that MFT record is found *and* shows evidence of a timestamp change.

A record counts as "changed" if either:

- `std_info_times.modified != std_info_times.mft_modified`, or
- `raw` contains a truthy `timestamp_changed`, `mft_timestamp_changed`, or `timestamp_change` key.

**Why it matters:** the USN journal is an append-only log NTFS writes *before* the change is committed. A `BASIC_INFO_CHANGE` entry means NTFS itself recorded a metadata write. Correlating it with a visible MFT change ties the journal to the on-disk result.

**Evidence emitted:**

```json
{
  "usn_reason": ["BASIC_INFO_CHANGE"],
  "mft_record_found": true,
  "mft_timestamp_changed": true,
  "mft_record_id": "mft_1234_5_0"
}
```

**Known weakness:** correlation is by exact `file_reference` string. If the two parsers disagree on reference formatting for the same file, the lookup silently fails and the rule cannot trigger. Because `mft_parser.py` is empty, this join has never been exercised against real data.

### Rule 3 — Timestamp zeroing / second-boundary alignment

**ID:** `RULE_3_TIMESTAMP_ZEROING` · **Weight:** +20

**What it does:** Recursively walks `record.raw` looking for any key named `raw_100ns_value` (at any nesting depth, inside dicts or lists) and tests each integer against:

```text
raw_100ns_value % 10_000_000 == 0
```

**Important naming caveat:** despite the rule ID, this does **not** detect zeroed or nulled timestamps. A zeroed timestamp would be `0`, and `0 % 10_000_000 == 0`, so zero *is* caught — but so is *every* legitimate timestamp that happens to land on an exact second boundary. The modulus test detects second-alignment, not erasure. The rule ID is fixed by the frozen schema and cannot be renamed, so this page documents the actual behaviour rather than the name.

**Why it matters:** a tool that overwrites a timestamp with a fabricated round value frequently produces second-aligned timestamps, because that is what naive timestomping scripts write.

**Evidence emitted:** `{"raw_100ns_values": [<matching integers>]}`

**Known weakness:** depends entirely on the parser retaining raw 100-ns integers in `raw`. The `$MFT` parser is empty, so no real raw values are currently available to test against. The fixture run shows it working on synthetic values only.

### Rule 4 — Suspicious event sequence

**ID:** `RULE_4_SUSPICIOUS_SEQUENCE` · **Weight:** +0 (contributes no score)

**What it does:** Groups all records by `file_reference`, extracts candidate events from each record, sorts them chronologically, then walks the sorted list looking for the exact ordered sequence:

```text
create → modify → timestamp_change → rename → delete
```

Events are harvested from four places: an explicit `raw["events"]` list, an explicit `raw["event_type"]`, each entry in `usn_reason` (mapped via an alias table), and `logfile_operation`. Reason strings are normalized — lowercased, `-` and spaces folded to `_` — and run through an alias map, so `BASIC_INFO_CHANGE`, `TIMESTAMPCANGE`, and `basic-info-change` all resolve to `timestamp_change`.

**Why it matters:** no single operation is malicious. The *combination* and *order* is the signal — this is the rule meant to catch tools that anti-forensic suites run as a fixed sequence.

**Evidence emitted:** `expected_sequence`, `observed_sequence`, and the matched `events` list.

**Status: implemented but unproven.** It scored 0 on all four fixture records. It is also the one rule the project plan designated a stretch goal.

**Known weakness, and it is significant:** the matcher is a strict greedy left-to-right scan. It requires all five events, in that exact order, with no gaps and no repeats. Real file histories are not that regular, so this will very likely under-trigger on genuine evidence. It is also fragile in a second way — `_event_timestamp` falls back to `$SI` timestamps when a record carries no explicit timestamp, which means several synthetic events can be manufactured from a single record and ordered by fallback rather than by real evidence. Both of these are design issues for the rule's owner to address, not documentation fixes.

### Rule 5 — `$LogFile` corroboration

**ID:** `RULE_5_LOGFILE_CORROBORATION` · **Weight:** +15

**What it does:** Collects `LogFile`-sourced records that have a non-empty `logfile_operation` or `logfile_timestamp`, indexed by `file_reference`. For every file that already has a *triggered* Rule 1, 2, or 3 finding, if a `$LogFile` record exists for that same reference, it:

1. Sets `logfile_corroboration` on each corroborated Rule 1–3 `DetectionResult`, and
2. Emits a new `RULE_5_LOGFILE_CORROBORATION` result carrying the +15.

```json
{
  "corroborated": true,
  "details": "$LogFile record(s) for 1234:5 corroborate RULE_1_SI_FN_MISMATCH."
}
```

**Why it matters:** this is the only rule that uses all three artifacts together. Rules 1–3 establish that something is wrong; Rule 5 shows that NTFS's own transaction log independently recorded the write. It is designed as a bonus for existing evidence and deliberately cannot establish a finding on its own — a `LogFile` record with no matching Rule 1–3 finding produces nothing.

**Evidence emitted:** `corroborated_rule_ids`, `logfile_record_ids`, `logfile_operations`, `logfile_timestamps`.

**Status: implemented but unexercised.** The fixture set contains no `LogFile`-sourced records, so this rule produced zero output in the verified run.

**Known weakness:** corroboration is decided purely on the presence of a `$LogFile` record for the same `file_reference`. It does not check that the log operation is timestamp-relevant — a `LogFile` record for an unrelated attribute update on the same file would count as corroboration. The `_RESIDENT_UPDATE_OP_NAMES` filter is applied in the parser, but by the time records reach Rule 5 that filtering is not re-verified against what the rule is claiming to corroborate.

## Scoring

`backend/analysis/scoring.py` aggregates findings into one `RiskScore` per `(scenario_id, file_reference)` pair. Only findings with `triggered=True` contribute.

| Rule | Weight |
|---|---:|
| `RULE_1_SI_FN_MISMATCH` | +30 |
| `RULE_2_USN_BASIC_INFO_CHANGE` | +25 |
| `RULE_3_TIMESTAMP_ZEROING` | +20 |
| `RULE_5_LOGFILE_CORROBORATION` | +15 |
| `RULE_4_SUSPICIOUS_SEQUENCE` | 0 (excluded) |

| Total score | Risk level |
|---|---|
| 0–24 | `LOW` |
| 25–54 | `MEDIUM` |
| 55+ | `HIGH` |

Any triggered rule with no defined weight is logged as a warning and excluded from the total, but its ID is still recorded in `triggered_rules`. `RULE_4_SUSPICIOUS_SEQUENCE` is handled explicitly this way.

**These weights are the original placeholders from the project plan. They have not been calibrated against ground truth and are not empirically derived.** A file can only reach `HIGH` by accumulating at least three findings, and Rule 1 alone tops out at `MEDIUM`.

## Timeline reconstruction

`build_timeline(records)` in `backend/analysis/timeline.py` converts records from all three sources into a chronologically sorted `list[TimelineEvent]`.

Events are derived from explicit `raw["events"]` lists first, then an explicit `raw["event_type"]`, then `usn_reason` entries, then `logfile_operation`. Timestamps resolve in priority order: an explicit raw timestamp, then `usn_timestamp` for `UsnJrnl` records, then `logfile_timestamp` for `LogFile` records, and finally the relevant `$SI` field.

A record that yields no explicit events falls back to a single inferred event: `timestamp_change` if `$SI.modified != $SI.mft_modified` or a `raw_100ns_value` is present, otherwise `create` for `MFT` records. Non-MFT records with no explicit events yield nothing.

Sorting raises `ValueError` on an unparseable timestamp rather than silently dropping or misordering the event.

## Verified fixture run

Running `run_rules` → `calculate_risk_scores` → `build_timeline` over `fixtures/sample_parsed_records.json` on 2026-09-27 produced 10 findings, 4 risk scores, and 4 timeline events:

| File | Rule | Triggered | Score | Risk |
|---|---|---|---:|---|
| `timestomped.exe` | Rule 1 | yes | 30 | MEDIUM |
| `zeroed.dll` | Rule 3 | yes | 20 | LOW |
| `clean_file.txt` | Rule 1 | no | 0 | LOW |
| `renamed_file.txt` | — | — | 0 | LOW |

The 4-event timeline sorted correctly across the `MFT` and `UsnJrnl` sources.

This run confirms the pipeline is internally consistent and correctly ordered. It does **not** demonstrate forensic detection, because the inputs are hand-written fixtures designed to match the schema. The two positive results are the pipeline agreeing with data that was authored to trigger it.
