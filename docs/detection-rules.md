# Detection Rules

_Last verified: 2026-09-25_

## Current implementation state

The rule identifiers and shared result models exist in `backend/models/schemas.py`, but `backend/analysis/rules.py`, `scoring.py`, and `timeline.py` are empty placeholders. The rules below describe the intended design; they are not currently executable or validated against real evidence.

## Rules

### Rule 1 — `$SI`/`$FN` mismatch

**ID:** `RULE_1_SI_FN_MISMATCH`

Compares timestamps from the MFT `$SI` (standard information) attribute with timestamps from the `$FN` (file name) attribute. A meaningful mismatch can indicate that displayed file timestamps were rewritten or that the attributes no longer describe the same history.

The mismatch threshold is still to be validated against ground truth.

### Rule 2 — USN basic-information change

**ID:** `RULE_2_USN_BASIC_INFO_CHANGE`

Looks for a USN `BASIC_INFO_CHANGE` reason and correlates it with a corresponding MFT timestamp change for the same file reference. The correlation is intended to connect journal activity with a change visible in the MFT.

### Rule 3 — Timestamp zeroing

**ID:** `RULE_3_TIMESTAMP_ZEROING`

Checks relevant raw NTFS 100-nanosecond timestamp values for values satisfying:

```text
raw_100ns_value % 10_000_000 == 0
```

This targets timestamps landing on exact second boundaries. The raw values must be retained by the parser for this check to be meaningful.

### Rule 4 — Suspicious event sequence

**ID:** `RULE_4_SUSPICIOUS_SEQUENCE`

Stretch goal. Looks for an unusual sequence such as:

```text
create -> modify -> timestamp change -> rename -> delete
```

This rule is optional and should only be attempted after Rules 1–3 are working and validated.

### Rule 5 — `$LogFile` corroboration

**ID:** `RULE_5_LOGFILE_CORROBORATION`

Checks whether `$LogFile` evidence supports an already-triggered Rule 1, 2, or 3 finding for the same file. It is intended to strengthen evidence rather than independently establish a finding.

## Planned scoring defaults

The team plan proposes additive weights:

| Rule | Weight |
|---|---:|
| Rule 1 | +30 |
| Rule 2 | +25 |
| Rule 3 | +20 |
| Rule 5 | +15 when it corroborates another finding |

Proposed buckets are `0–24 = LOW`, `25–54 = MEDIUM`, and `55+ = HIGH`. These values are placeholders and must be validated and approved before being presented as final.

## Important limitation

The JSON fixture `sample_detection_results.json` demonstrates expected result shapes, but it does not prove that any rule implementation works. Real parser output and ground-truth validation are still required.
