# Dataset and Fixtures

_Last verified: 2026-09-25_

## Current contents

There is currently no real `dataset/` directory, raw artifact extract, or ground-truth file in the repository. The available data is four synthetic fixture files under `fixtures/`.

Fixtures are intended to make the shared JSON shapes concrete while implementation proceeds. They are not forensic evidence and must not be described as validated attack results.

## Available fixtures

| Fixture | Contents |
|---|---|
| `sample_parsed_records.json` | Clean file, clean rename, timestomped creation, and zeroed timestamp examples |
| `sample_detection_results.json` | Example Rule 1 and Rule 3 results plus a clean-file negative result |
| `sample_risk_scores.json` | Example LOW/MEDIUM risk scores |
| `sample_timeline_events.json` | Example create, rename, and timestamp-change events |

The examples use synthetic paths such as `C:/Users/test/` and synthetic file references. They do not represent a complete end-to-end scenario dataset.

## Planned real scenarios

The project plan calls for a small hand-built Windows VM dataset with raw artifact extracts and ground-truth JSON. The minimum planned cases are:

- Clean file — negative control
- Clean rename — negative control
- Timestomped creation — Rule 1 target
- Zeroed timestamps — Rule 3 target
- At least one case where `$LogFile` evidence is needed to explain the finding

Each completed scenario should record:

- Scenario ID and description
- VM preparation steps
- Files and actions performed
- Extracted `$MFT`, `$UsnJrnl`, and `$LogFile` locations
- Expected normalized records
- Expected triggered and non-triggered rules
- Expected timeline events
- Risk-score expectations, if used
- Known limitations or unverified fields

## Ground-truth format

The final format is not yet implemented. Person 1 owns the dataset and ground-truth design; this page should be updated from the actual files after they are added. Do not invent expected results before the scenarios are run and reviewed.

## Handling evidence

Do not commit raw disk images, credentials, or sensitive forensic data. Store large evidence outside Git and document only safe extracts and metadata needed for reproduction.
