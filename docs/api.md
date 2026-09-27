# API Reference

_Verified against commit `0529dcc` on 2026-09-27._

## Current implementation state

**No API exists.** `backend/main.py` and `backend/api/routes.py` are both empty files, and there is no `dashboard/` directory. There is no importable ASGI application, so `uvicorn backend.main:app` cannot work.

Nothing on this page has been verified against a running server. It records the *planned* interface from the project plan so the API owner has a target, and nothing more.

## Planned endpoints

| Method | Endpoint | Planned response | Implemented |
|---|---|---|---|
| `GET` | `/scenarios` | Scenario IDs | No |
| `GET` | `/scenarios/{scenario_id}/records` | `list[ParsedRecord]` | No |
| `GET` | `/scenarios/{scenario_id}/analysis` | `list[DetectionResult]` | No |
| `GET` | `/scenarios/{scenario_id}/timeline` | `list[TimelineEvent]` | No |
| `GET` | `/scenarios/{scenario_id}/score` | `list[RiskScore]` | No |
| `GET` | `/scenarios/{scenario_id}/report` | HTML or text report download | No |

The plan describes these as "five endpoints" while listing six paths, because the scenario index is counted separately from the five scenario-specific resources. The six paths above are the concrete set.

## Response models

All response bodies are the shared Pydantic models from `backend/models/schemas.py`. Because these are the same models the analysis layer produces, an endpoint should be able to return its objects directly.

| Model | Used by |
|---|---|
| `ParsedRecord` | `/records` |
| `DetectionResult` | `/analysis` |
| `TimelineEvent` | `/timeline` |
| `RiskScore` | `/score` |
| `TimestampSet` | nested inside `ParsedRecord` |
| `LogfileCorroboration` | nested inside `DetectionResult` |

## Undecided, and needed before this page can be completed

These are genuinely open and belong to the API owner, not to documentation:

- **Status codes.** Nothing specifies 404 behaviour for an unknown `scenario_id`, or whether an empty scenario returns `[]` or a 404.
- **Data source.** Whether the API reads from `fixtures/` or from a live pipeline run, and how that switch happens. The plan intends fixtures first, real output later.
- **Report format and filename.** HTML, text, or both; and what `Content-Disposition` filename is served.
- **Content types.** JSON is implied for the five data endpoints; the report endpoint's type is undecided.
- **Error shape.** No error response model is defined.
- **Pagination or filtering.** Not specified, and the plan gives no guidance.

## When this page gets rewritten

Once routes exist, this page should be regenerated **from the running application** — from FastAPI's generated OpenAPI schema at `/openapi.json`, cross-checked by actually calling each endpoint. Do not fill it in from the plan.

Until then, treat this page as a placeholder with a stated purpose, not as API documentation.
