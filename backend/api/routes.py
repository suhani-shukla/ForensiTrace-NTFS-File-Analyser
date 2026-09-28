"""
routes.py
----------
All API endpoints, exactly matching the Master Context's endpoint list:

  GET  /scenarios
  GET  /scenarios/{scenario_id}/records
  GET  /scenarios/{scenario_id}/analysis
  GET  /scenarios/{scenario_id}/timeline
  GET  /scenarios/{scenario_id}/score
  GET  /scenarios/{scenario_id}/report

Every endpoint's response shape is a pydantic model from backend.models.schemas
(never redefined here), consumed by both external API clients and this
project's own dashboard pages (main.py calls the same underlying
backend.api.data_access functions directly rather than making HTTP calls to
itself).
"""
from __future__ import annotations
from typing import List

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.models.schemas import ParsedRecord, DetectionResult, RiskScore, TimelineEvent
from backend.api import data_access
from backend.services import report_service

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


def _require_scenario(scenario_id: str) -> None:
    if not data_access.scenario_exists(scenario_id):
        raise HTTPException(status_code=404, detail=f"Unknown scenario_id: {scenario_id!r}")


@router.get("", response_model=List[str])
def list_scenarios() -> List[str]:
    return data_access.list_scenario_ids()


@router.get("/{scenario_id}/records", response_model=List[ParsedRecord])
def get_records(scenario_id: str) -> List[ParsedRecord]:
    _require_scenario(scenario_id)
    return data_access.get_records(scenario_id) or []


@router.get("/{scenario_id}/analysis", response_model=List[DetectionResult])
def get_analysis(scenario_id: str) -> List[DetectionResult]:
    _require_scenario(scenario_id)
    return data_access.get_analysis(scenario_id) or []


@router.get("/{scenario_id}/timeline", response_model=List[TimelineEvent])
def get_timeline(scenario_id: str) -> List[TimelineEvent]:
    _require_scenario(scenario_id)
    return data_access.get_timeline(scenario_id) or []


@router.get("/{scenario_id}/score", response_model=List[RiskScore])
def get_score(scenario_id: str) -> List[RiskScore]:
    _require_scenario(scenario_id)
    return data_access.get_scores(scenario_id) or []


@router.get("/{scenario_id}/report")
def get_report(
    scenario_id: str,
    format: str = Query("html", pattern="^(html|text)$", description="'html' or 'text'"),
) -> Response:
    _require_scenario(scenario_id)
    records = data_access.get_records(scenario_id) or []
    detections = data_access.get_analysis(scenario_id) or []
    scores = data_access.get_scores(scenario_id) or []
    timeline = data_access.get_timeline(scenario_id) or []

    if format == "text":
        content = report_service.build_report_text(scenario_id, records, detections, scores, timeline)
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{scenario_id}_report.txt"'},
        )

    content = report_service.build_report_html(scenario_id, records, detections, scores, timeline)
    return Response(
        content=content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{scenario_id}_report.html"'},
    )
