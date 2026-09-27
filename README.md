# ForensiTrace — NTFS Forensic Timestomping Detector

ForensiTrace is a capstone project for analyzing NTFS metadata and reconstructing file activity. It correlates three NTFS forensic artifacts — `$MFT`, `$UsnJrnl:$J`, and `$LogFile` — to identify files whose timestamps were rewritten (timestomping), score the risk, and reconstruct a correlated chronological timeline.

## Current status

_Verified against commit `0529dcc` on 2026-09-27._

> Docs are owned by Person 5. Each page states the commit it was verified
> against — if that SHA is behind `main`, treat the page as stale and ask for a
> refresh rather than trusting it.

The project is **partially implemented**. The analysis core works; the I/O ends of the pipeline do not exist yet.

### Implemented and verified working

| Component | File | Status |
|---|---|---|
| Shared Pydantic schemas | `backend/models/schemas.py` | Complete, frozen |
| `$UsnJrnl` parser | `backend/parsers/usnjrnl_parser.py` | Implemented, unit tested |
| `$LogFile` parser | `backend/parsers/logfile_parser.py` | Implemented, unit tested |
| Normalization | `backend/normalization/normalizer.py` | Implemented, unit tested |
| Detection Rules 1–5 | `backend/analysis/rules.py` | Implemented, **no tests, not validated against real evidence** |
| Risk scoring | `backend/analysis/scoring.py` | Implemented, **no tests, weights untuned** |
| Timeline reconstruction | `backend/analysis/timeline.py` | Implemented, **no tests** |
| Test suite | `tests/` | 17 tests, all passing |

### Not yet implemented

| Component | File | Note |
|---|---|---|
| `$MFT` parser | `backend/parsers/mft_parser.py` | **Empty file** — blocks real Rule 1 validation |
| ASGI app entrypoint | `backend/main.py` | Empty file |
| API routes | `backend/api/routes.py` | Empty file |
| Report generator | `backend/services/report_service.py` | Empty file |
| Configuration | `config/settings.py` | Empty file |
| Dashboard | `dashboard/` | Directory does not exist |
| Real dataset + ground truth | `dataset/` | Directory does not exist |

**The application cannot be run end to end**, because there is no importable ASGI application and no `$MFT` parser.

## What actually works right now

The analysis core can be exercised directly against the synthetic fixtures. Running the full chain — records → rules → scores → timeline — produces:

```text
RULE_1_SI_FN_MISMATCH   triggered=True   +30  MEDIUM  C:/Users/test/timestomped.exe
RULE_3_TIMESTAMP_ZEROING triggered=True  +20  LOW     C:/Users/test/zeroed.dll
```

with a correctly chronologically-sorted 4-event timeline spanning the `MFT` and `UsnJrnl` sources. Rule 1 correctly stays silent on the untouched control file, and Rule 3 correctly stays silent on the other three.

This is a **self-consistency check against synthetic data, not a forensic result.** The fixtures were hand-written to exercise the schema, so the agreement above shows the pipeline is wired up — it does not show that timestomping is detected on a real disk image.

Two important limits on that run:

- **Rules 2 and 5 produce no output at all.** The fixtures contain no `BASIC_INFO_CHANGE` USN record and no `LogFile`-sourced record, so neither rule is exercised by the available data. Both are implemented but unproven.
- **Rule 4 never triggers** on the available data, because no fixture contains the full `create → modify → timestamp_change → rename → delete` sequence.

## Architecture

```text
Windows evidence image
        |
        v
Artifact extraction ($MFT, $UsnJrnl, $LogFile)
        |
        v
Source-specific parsers  (usnjrnl_parser, logfile_parser, mft_parser)
        |
        v
Metadata normalization -> list[ParsedRecord]
        |
        v
Detection rules 1-5 + risk scoring + timeline
        |
        v
FastAPI API + Jinja2 dashboard + report      [not implemented]
```

See [docs/architecture.md](docs/architecture.md) for the data flow and layer responsibilities.

## Requirements

- Python 3.11 or newer (developed and verified on 3.14)
- Git
- A Windows NTFS virtual machine, to reproduce the forensic dataset (not yet built)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` pins `dfir_ntfs` from its GitHub archive at version 1.1.18, plus FastAPI, Uvicorn, Jinja2, Pydantic, pytest, and python-multipart. Installation from a clean checkout was verified working on 2026-09-27.

See [docs/setup.md](docs/setup.md) for full setup and VM notes.

## Running the tests

```bash
pytest
```

Expected result:

```text
17 passed
```

The suite covers the `$UsnJrnl` parser, `$LogFile` parser helpers, and the normalizer. It does **not** cover the detection rules, scoring, or timeline — see the limitations note below.

## Running the project

The intended command is:

```bash
uvicorn backend.main:app --reload
```

**This does not work yet.** `backend/main.py` and `backend/api/routes.py` are empty files, so there is no `app` object to serve. Do not put this command in a demo or a submission until the API owner lands it.

## Known limitations

These are stated plainly because they bound what the project can currently claim.

1. **No `$MFT` parser.** Rule 1 is the project's central proof-of-concept and it runs on `MFT`-sourced records. With `mft_parser.py` empty, Rule 1 has never been validated against a real `$MFT`.
2. **No ground-truth dataset.** All verification so far is against hand-written synthetic fixtures. No attack scenario has been run on a real NTFS volume.
3. **Scoring weights are untuned.** The 30/25/20/15 weights and the LOW/MEDIUM/HIGH buckets are the original placeholders from the project plan. They have not been calibrated against ground truth and should not be presented as empirically derived.
4. **Rules 2 and 5 are unexercised**, per the fixture run described above.
5. **The analysis layer has no automated tests.** The 17 passing tests cover parsing and normalization only.
6. **Path resolution is incomplete.** For `UsnJrnl` and `LogFile` records the normalizer cannot derive a real `full_path` and falls back to the bare file name or file reference. `full_path` is therefore unreliable for non-MFT sources.
7. **`$LogFile` recovery is narrow by design.** The parser only recovers timestamps from `UpdateResidentValue`/`UpdateNonresidentValue` redo operations that target `$STANDARD_INFORMATION` at redo offset 0. Most `$LogFile` records do not resolve to a file reference and are dropped during normalization.

## Fixtures

`fixtures/` holds four synthetic JSON files covering a clean file, a clean rename, a timestomped creation, and zeroed timestamps. They are schema-oriented development aids. They are **not forensic evidence** and must not be described as validated attack results.

See [docs/dataset.md](docs/dataset.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Setup](docs/setup.md)
- [API reference](docs/api.md) — planned, not implemented
- [Detection rules](docs/detection-rules.md)
- [Dataset and fixtures](docs/dataset.md)
- [Final report](docs/final-report.md) — draft capstone write-up

## Scope

**In scope:** NTFS artifact parsing, cross-source correlation, detection of timestamp anomalies, timeline reconstruction, risk scoring, API/dashboard reporting, and a small hand-built test dataset.

**Out of scope:** deleted-file metadata recovery, machine-learning detection, full unconstrained forensic-volume analysis, and statistical signature sampling.
