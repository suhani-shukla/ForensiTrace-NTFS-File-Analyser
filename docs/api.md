# API Reference

_Last verified: 2026-09-25_

## Current implementation state

No API is currently available. `backend/main.py` and `backend/api/routes.py` are empty placeholders, and there is no importable ASGI application yet.

The endpoints below are the planned interface from the team plan, not verified live routes.

## Planned endpoints

| Method | Endpoint | Planned response |
|---|---|---|
| `GET` | `/scenarios` | Scenario IDs |
| `GET` | `/scenarios/{scenario_id}/records` | `list[ParsedRecord]` |
| `GET` | `/scenarios/{scenario_id}/analysis` | `list[DetectionResult]` |
| `GET` | `/scenarios/{scenario_id}/timeline` | `list[TimelineEvent]` |
| `GET` | `/scenarios/{scenario_id}/score` | `list[RiskScore]` |
| `GET` | `/scenarios/{scenario_id}/report` | HTML or text report download |

The plan refers to these as five endpoint groups, although the table lists six concrete paths because the scenarios index is separate from the five scenario-specific resources.

## Intended models

The shared response models are defined in `backend/models/schemas.py`:

- `ParsedRecord`
- `DetectionResult`
- `RiskScore`
- `TimelineEvent`

The API owner must verify actual status codes, error behavior, content types, and report filenames after implementation. This page should be updated from the running application rather than from assumptions.
