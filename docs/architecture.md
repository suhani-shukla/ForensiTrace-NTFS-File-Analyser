# Architecture

_Verified against commit `0529dcc` on 2026-09-27._

## Implementation state in one line

The **analysis core is built** (parsers, normalization, rules, scoring, timeline) and the **I/O ends are not** (no `$MFT` parser, no API, no dashboard, no report, no dataset).

## Data flow

```text
Windows evidence image
        |
        v
  Artifact extraction
  $MFT | $UsnJrnl:$J | $LogFile
        |
        v
  Source-specific parsers
  usnjrnl_parser.py    [implemented]
  logfile_parser.py    [implemented]
  mft_parser.py        [EMPTY]
        |
        v
  Normalization  ->  list[ParsedRecord]
  normalizer.py         [implemented]
        |
        v
  Analysis
  rules.py     Rules 1-5   [implemented]
  scoring.py   risk model  [implemented]
  timeline.py  merge/sort  [implemented]
        |
        v
  Presentation
  main.py / routes.py / report_service.py / dashboard/   [ALL EMPTY]
```

## Module status

| Module | Lines | Owner | State |
|---|---:|---|---|
| `backend/models/schemas.py` | 74 | P1 | Frozen contract |
| `backend/parsers/mft_parser.py` | 0 | P1 | **Empty** |
| `backend/parsers/usnjrnl_parser.py` | 103 | P2 | Working, tested |
| `backend/parsers/logfile_parser.py` | 175 | P2 | Working, tested |
| `backend/normalization/normalizer.py` | 177 | P2 | Working, tested |
| `backend/analysis/rules.py` | 429 | P3 | Working, untested |
| `backend/analysis/scoring.py` | 89 | P3 | Working, untested |
| `backend/analysis/timeline.py` | 155 | P3 | Working, untested |
| `backend/main.py` | 0 | P4 | **Empty** |
| `backend/api/routes.py` | 0 | P4 | **Empty** |
| `backend/services/report_service.py` | 0 | P4 | **Empty** |
| `config/settings.py` | 0 | P1 | **Empty** |

## Shared contract

`backend/models/schemas.py` defines five Pydantic models and is the single interface between layers. It is frozen — no module may redefine these locally.

- `ParsedRecord` — one normalized record from one artifact source
- `DetectionResult` — one rule's verdict on one record
- `RiskScore` — aggregated score for one file in one scenario
- `TimelineEvent` — one entry in the merged chronological view
- `TimestampSet` — the four-timestamp group, reused for both `$SI` and `$FN`
- `LogfileCorroboration` — the corroboration sub-object on `DetectionResult`
- `RuleID` / `RiskLevel` — enumerations of the frozen string values

Controlled vocabulary: `source` is `MFT`, `UsnJrnl`, or `LogFile`. `risk_level` is `LOW`, `MEDIUM`, or `HIGH`.

Each model keeps a `raw` dictionary of original parser fields for traceability, so a detection can always be traced back to the bytes it came from.

## Layer responsibilities

### Artifact extraction

Obtain `$MFT`, `$UsnJrnl:$J`, and `$LogFile` from a Windows NTFS volume. No extraction tooling is in this repository, and no raw images are committed.

### Parsers

Each parser converts one binary artifact into plain dictionaries, using `dfir_ntfs` 1.1.18. Parsers do not build `ParsedRecord` objects — that is normalization's job — which keeps the raw layer inspectable and the schema layer single-sourced.

Both working parsers share the same conventions:

- File references are decoded from packed 64-bit NTFS values into `"segment:sequence"` strings, e.g. `"1234:5"`.
- Timestamps are formatted as `%Y-%m-%dT%H:%M:%SZ` — **whole seconds only**, sub-second precision is discarded at this stage.
- The `USN_REASON_` prefix is stripped from reason names so they match the fixture convention (`RENAME_NEW_NAME`, not `USN_REASON_RENAME_NEW_NAME`).
- `raw` retains version, security, and redo metadata for traceability.

The `$LogFile` parser does real work beyond decoding. It resolves a log record's target file by checking the incrementally-built open-attribute table, then falling back to the periodic `OpenAttributeTableDump` snapshot — the second path being the only one that carries an attribute type code, and therefore the only one that can resolve `$STANDARD_INFORMATION` updates. When a redo operation is `UpdateResidentValue` or `UpdateNonresidentValue`, targets `$STANDARD_INFORMATION`, and starts at redo offset 0, it unpacks the four leading 8-byte FILETIME fields to recover real timestamps. **This is the only route by which a genuine timestamp can be recovered from `$LogFile`**, and it covers a narrow minority of log records.

### Normalization

`normalize(mft_raw, usnjrnl_raw, logfile_raw)` merges all three sources into one `list[ParsedRecord]`. Order is not chronological — that is the timeline's job.

The three source branches differ in what they can honestly populate:

- **MFT** is the only source that can supply real `$SI`/`$FN` timestamp pairs, a real `full_path`, and a correct `is_directory`. It is the only source Rule 1 can use.
- **UsnJrnl** carries reason codes and a timestamp but no path and no attribute timestamps. All four `TimestampSet` fields are set to the single USN timestamp, and `file_name_times` is `None`.
- **LogFile** carries an operation name, an LSN, a transaction ID, and — only on the narrow path above — recovered timestamps. `parent_file_reference` is always `None` and `is_directory` is always `False`.

Two records with no resolved `file_reference` are skipped rather than emitted with a null reference, since `file_reference` is required by the schema.

**Unresolved limitation, marked `TODO-INTEGRATION` in the code:** `UsnJrnl` and `LogFile` records cannot produce a real `full_path`. Both branches fall back to the bare file name or the file reference string. Resolving true paths means walking `parent_file_reference` links against the MFT-derived record set, which requires a function that can see the full record set at once. Until that exists, `full_path` is unreliable for two of the three sources — including in Rule 5, whose `representative` record is always LogFile-sourced.

### Analysis

Three independent modules over the same `list[ParsedRecord]`:

- `rules.run_rules()` returns a flat `list[DetectionResult]` covering Rules 1–5. Rule 5 additionally mutates the Rule 1–3 results it corroborates, attaching `logfile_corroboration` to each.
- `scoring.calculate_risk_scores()` folds findings into one `RiskScore` per file per scenario, summing weights for triggered rules only.
- `timeline.build_timeline()` expands records into `TimelineEvent` objects and sorts them chronologically, raising on an unparseable timestamp rather than silently misordering.

Full rule conditions and known weaknesses are in [detection-rules.md](detection-rules.md).

### Presentation

Intended as a single FastAPI application serving JSON endpoints, Jinja2 HTML templates, and downloadable reports. **Entirely unimplemented** — all four presentation files are empty or absent, so the project cannot currently be served.

## Integration order

The plan this project follows puts schema freeze first so parallel work is possible, then validates against real data:

1. **Done** — schemas frozen, fixtures published, parsers and normalization built against fixtures.
2. **Blocked** — real `$MFT` output plus first ground-truth scenarios, to validate Rules 1–3. `mft_parser.py` is empty and no dataset exists, so this step has not started.
3. **Blocked on step 2** — `$LogFile` integration and Rule 5 corroboration validated end to end. The parser and rule exist in code but have never run on real data together.
4. **Not started** — full dataset, end-to-end pipeline run across all scenarios.
5. **Not started** — API, dashboard, and report switched from fixtures to real pipeline output.

## Current gaps

- `$MFT` parser is empty, so Rule 1 has never run on a real `$MFT`. This is the single highest-impact gap.
- No dataset, no raw artifact extracts, no ground-truth JSON.
- No ASGI application, routes, report generator, dashboard, or configuration loader.
- No automated tests for rules, scoring, or timeline.
- Rule 2 and Rule 5 are unexercised by any available data.
- Rule 4 has never triggered.
- Path resolution incomplete for `UsnJrnl` and `LogFile` sources.
- Scoring weights and risk buckets are untuned placeholders.
- Timestamps are truncated to whole seconds at the parser layer, which limits Rule 1's sensitivity.
