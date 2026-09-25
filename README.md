# ForensiTrace — NTFS Forensic Timestomping Detector

ForensiTrace is a capstone project for analyzing NTFS metadata and reconstructing file activity. Its intended purpose is to correlate `$MFT`, `$UsnJrnl`, and `$LogFile` artifacts, identify suspicious timestamp changes, and present the findings as a timeline and investigation report.

## Current status

This repository is currently at the foundation/scaffold stage. The following pieces are present:

- Shared Pydantic models in `backend/models/schemas.py`
- Four illustrative JSON fixture files in `fixtures/`
- Dependency declarations in `requirements.txt`
- Empty implementation placeholders for parsers, normalization, analysis, API, and reporting
- A minimal top-level description

The parsers, normalizer, detection rules, scoring, timeline, FastAPI application, dashboard, report generator, real dataset, and tests are not implemented yet. The application therefore cannot currently be run end to end. Fixture detection results are examples, not validated forensic findings.

## Target architecture

```text
Windows evidence image
        |
        v
Artifact extraction ($MFT, $UsnJrnl, $LogFile)
        |
        v
Source-specific parsers
        |
        v
Metadata normalization (ParsedRecord)
        |
        v
Detection rules + risk scoring
        |
        v
Chronological timeline
        |
        v
FastAPI API + Jinja2 dashboard + report
```

## Requirements

- Python 3.11 or newer
- A Windows NTFS test environment for creating a real forensic dataset

Install the declared dependencies:

```bash
python -m venv .venv
```

Activate the environment, then run:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

See [docs/setup.md](docs/setup.md) for Windows and VM notes.

## Running the project

The intended development command will be:

```bash
uvicorn backend.main:app --reload
```

At present, `backend/main.py` is an empty placeholder, so this command is not runnable yet. Do not present fixture output as real pipeline output until the implementation and validation are complete.

## Tests

`pytest.ini` configures pytest to look in `tests/`, but the `tests/` directory and test files are not present yet. Once tests are added, run:

```bash
pytest
```

## Fixtures

The `fixtures/` directory contains schema-oriented examples for:

- A clean file
- A clean rename
- A timestomped creation
- Zeroed timestamps

These files are useful for development, but they are synthetic examples and are not a substitute for the planned VM-generated, ground-truth dataset.

## Documentation

- [Architecture](docs/architecture.md)
- [Setup](docs/setup.md)
- [API reference](docs/api.md)
- [Detection rules](docs/detection-rules.md)
- [Dataset and fixtures](docs/dataset.md)

## Scope

In scope: NTFS artifact parsing, cross-source correlation, detection of timestamp anomalies, timeline reconstruction, risk scoring, API/dashboard reporting, and a small hand-built test dataset.

Out of scope: deleted-file metadata recovery, machine-learning detection, full unconstrained forensic-volume analysis, and statistical signature sampling.
