# Architecture

_Last verified: 2026-09-25_

## Current implementation state

The repository currently contains shared data models and synthetic fixtures. The following modules exist as empty placeholders:

- `$MFT`, `$UsnJrnl`, and `$LogFile` parsers
- Normalization
- Detection rules
- Risk scoring
- Timeline reconstruction
- FastAPI routes and application entrypoint
- Report generation

No dashboard or real dataset directory is currently present. This page describes the target architecture and clearly separates it from implemented behavior.

## Target data flow

```text
Windows disk image / extracted artifacts
              |
              v
  +---------------------------+
  | Artifact extraction       |
  | $MFT, $UsnJrnl, $LogFile |
  +---------------------------+
              |
              v
  +---------------------------+
  | Source-specific parsers   |
  +---------------------------+
              |
              v
  +---------------------------+
  | Normalization             |
  | list[ParsedRecord]        |
  +---------------------------+
              |
              v
  +---------------------------+
  | Analysis                  |
  | Rules 1-5, risk, timeline |
  +---------------------------+
              |
              v
  +---------------------------+
  | Presentation              |
  | API, dashboard, report    |
  +---------------------------+
```

## Shared contracts

`backend/models/schemas.py` currently defines the shared Pydantic models:

- `ParsedRecord`
- `DetectionResult`
- `RiskScore`
- `TimelineEvent`

These models are the intended interface between normalization, analysis, and presentation layers. Source values are intended to be `MFT`, `UsnJrnl`, or `LogFile`; risk values are `LOW`, `MEDIUM`, or `HIGH`.

## Layer responsibilities

### Artifact extraction

Obtain the relevant NTFS structures from a controlled Windows test image or prepared artifact extracts. Raw disk images are not included in this repository.

### Source-specific parsers

Each parser should convert one raw artifact format into a source-specific representation. The parser should preserve raw fields for traceability while avoiding changes to the shared schema.

### Normalization

The normalizer should combine parser output into `ParsedRecord` objects, normalize timestamps to ISO 8601, and retain source-specific fields such as USN reasons and `$LogFile` operations.

### Analysis

The analysis layer should evaluate Rules 1–3 first, add Rule 5 corroboration when `$LogFile` evidence is available, calculate additive risk scores, and merge source events into a chronological timeline. Rule 4 remains a stretch goal.

### Presentation

The intended presentation layer is a FastAPI application serving JSON endpoints, Jinja2 HTML templates, and downloadable HTML/text reports from the same application.

## Integration order

1. Freeze the shared schemas and use fixtures for parallel development.
2. Integrate real `$MFT` and `$UsnJrnl` data and validate Rules 1–3.
3. Add `$LogFile` parsing and Rule 5 corroboration.
4. Run the complete pipeline across the hand-built dataset.
5. Connect the API, dashboard, and report to real pipeline output.

## Current gaps

- Parser implementations are empty.
- Normalized records are not produced.
- Detection, scoring, and timeline logic are not implemented.
- `backend/main.py` does not yet expose an ASGI application.
- No API routes or dashboard templates exist.
- No real artifact extracts or ground-truth scenarios are present.
- No automated tests are present.
