# Dataset and Fixtures

_Verified against commit `0529dcc` on 2026-09-27._

## The honest headline

**There is no real dataset.** The `dataset/` directory does not exist. No scenario has been run on a real NTFS volume, there are no raw artifact extracts, and there is no ground-truth JSON anywhere in this repository.

Everything currently verifiable rests on four hand-written synthetic files in `fixtures/`. Those files exist to make the JSON schema concrete while development was happening in parallel. They are not forensic evidence, they were authored by the same team that wrote the code, and they must never be presented as validated attack results or as evidence that timestomping detection works.

## Available fixtures

| Fixture | Records | Contents |
|---|---:|---|
| `sample_parsed_records.json` | 4 | Clean file (MFT), clean rename (UsnJrnl), timestomped creation (MFT), zeroed timestamps (MFT) |
| `sample_detection_results.json` | 3 | Rule 1 on the timestomped file, Rule 3 on the zeroed file, a non-triggered Rule 1 on the clean file |
| `sample_risk_scores.json` | 3 | MEDIUM for the timestomped file, LOW for the zeroed and clean files |
| `sample_timeline_events.json` | 4 | `create`, `rename`, and two `timestamp_change` events |

All use synthetic paths under `C:/Users/test/` and synthetic file references. They cover four independent cases, not one coherent scenario, so they cannot demonstrate cross-source correlation on a single file.

## What running the pipeline on the fixtures proves

The analysis core was run over `sample_parsed_records.json` on 2026-09-27, producing 10 findings, 4 risk scores, and a correctly sorted 4-event timeline.

| File | Triggered | Score | Risk |
|---|---|---:|---|
| `timestomped.exe` | Rule 1 | 30 | MEDIUM |
| `zeroed.dll` | Rule 3 | 20 | LOW |
| `clean_file.txt` | nothing | 0 | LOW |
| `renamed_file.txt` | nothing | 0 | LOW |

The implementation's output matches `sample_risk_scores.json` exactly, which is a useful consistency check on the scoring path.

**What this establishes:** the pipeline is wired end to end, the rules fire on the records they should, the negative controls stay silent, and the timeline sorts correctly across two sources.

**What this does not establish:** that any of it works on a real disk. The two positive results are the code agreeing with input that was written to trigger it. This is a self-consistency check, and it is the only validation the project currently has.

## Coverage gaps in the fixtures

- **No `LogFile`-sourced records exist**, so Rule 5 is completely unexercised. It produced zero output.
- **No USN record carries `BASIC_INFO_CHANGE`**, so Rule 2 is unexercised. The only UsnJrnl record is a `RENAME_NEW_NAME`.
- **No record contains the full `create → modify → timestamp_change → rename → delete` sequence**, so Rule 4 never triggered.
- **No file appears in more than one source**, so no cross-source correlation is demonstrated at all.
- **No `raw_100ns_value` exists in a real parser's output**, because no parser is producing real output.

Four of the five rules therefore have never been observed to fire.

## Planned real scenarios

The project plan calls for a hand-built Windows VM dataset. The minimum planned set:

| Scenario | Purpose | Control? |
|---|---|---|
| Clean file | Untouched file must produce no findings | Negative control |
| Clean rename | Legitimate rename must not look like tampering | Negative control |
| Timestomped creation | Produce a `$SI`/`$FN` mismatch | Rule 1 target |
| Zeroed timestamps | Produce second-aligned raw timestamps | Rule 3 target |
| `$LogFile`-dependent case | A finding only `$LogFile` can explain | Rule 5 target |

The two negative controls matter as much as the positives. A detector that flags everything is worthless, so the clean cases are what make the positive results meaningful — and right now the only negative-control evidence is two synthetic records.

The fifth scenario does not yet have a concrete design. It depends on knowing what `$LogFile` evidence actually looks like in practice, which needs a real parser run.

## Ground-truth format

Not implemented and not designed. The dataset and ground-truth owner defines it. Whatever it becomes, each scenario record should capture at minimum:

- Scenario ID and a plain-language description
- VM preparation steps
- Files touched and actions performed
- Locations of the extracted `$MFT`, `$UsnJrnl:$J`, `$LogFile`
- Expected normalized records
- Expected triggered **and non-triggered** rules
- Expected timeline events
- Expected risk scores
- Known limitations or unverified fields

Recording the non-triggered rules matters. Without expected negatives in the ground truth, there is no way to detect a detector that flags everything.

## Handling evidence

Do not commit raw disk images, VM snapshots, credentials, or sensitive forensic data. `.gitignore` already excludes `dataset/scenarios/*.raw` and `my/`. Keep bulk evidence outside Git and commit only the extracts and metadata needed to reproduce findings.
