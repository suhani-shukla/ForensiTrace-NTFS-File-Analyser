"""
main.py
--------
FastAPI app entrypoint. Two things happen here:

  1. The API router (backend/api/routes.py) is mounted under /scenarios,
     giving the five endpoints from the Master Context.
  2. The dashboard itself is served from this same app, as Jinja2-rendered
     HTML pages -- per the team's Day-1 default decision (Master Context
     Open Item #1: FastAPI + Jinja2, not a separate frontend).

Dashboard page handlers call backend.api.data_access directly (the same
functions routes.py calls) rather than making an HTTP round-trip to this
app's own API -- there's no reason to pay that cost for an in-process call,
and it keeps the dashboard rendering correct even if the API layer's
request/response cycle changes shape later.

Run with:
    uvicorn backend.main:app --reload
"""
from __future__ import annotations
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.routes import router as scenarios_router
from backend.api import data_access
from backend.services import report_service

REPO_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = REPO_ROOT / "dashboard"

app = FastAPI(
    title="ForensiTrace API",
    description="NTFS timestomping detection & timeline reconstruction — backend API and dashboard.",
    version="0.1.0",
)

app.include_router(scenarios_router)

app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(DASHBOARD_DIR / "templates"))


# ---------------------------------------------------------------------------
# Dashboard pages
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def dashboard_root():
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", include_in_schema=False)
def dashboard_index(request: Request):
    scenario_ids = data_access.list_scenario_ids()
    summaries = []
    for sid in scenario_ids:
        scores = data_access.get_scores(sid) or []
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in scores:
            risk_counts[s.risk_level] = risk_counts.get(s.risk_level, 0) + 1
        summaries.append({
            "scenario_id": sid,
            "file_count": len(scores),
            "risk_counts": risk_counts,
            "highest_risk": "HIGH" if risk_counts["HIGH"] else ("MEDIUM" if risk_counts["MEDIUM"] else "LOW"),
        })
    return templates.TemplateResponse(request, "index.html", {"scenarios": summaries})


@app.get("/dashboard/{scenario_id}", include_in_schema=False)
def dashboard_scenario(request: Request, scenario_id: str):
    if not data_access.scenario_exists(scenario_id):
        raise HTTPException(status_code=404, detail=f"Unknown scenario_id: {scenario_id!r}")

    records = data_access.get_records(scenario_id) or []
    detections = data_access.get_analysis(scenario_id) or []
    scores = data_access.get_scores(scenario_id) or []
    timeline = data_access.get_timeline(scenario_id) or []

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    scores_sorted = sorted(scores, key=lambda s: (risk_order.get(s.risk_level, 9), -s.total_score))

    findings_by_file = {}
    for d in detections:
        if d.triggered:
            findings_by_file.setdefault(d.file_reference, []).append(d)

    timeline_sorted = sorted(timeline, key=lambda e: e.timestamp)

    return templates.TemplateResponse(request, "scenario.html", {
        "scenario_id": scenario_id,
        "scores": scores_sorted,
        "findings_by_file": findings_by_file,
        "timeline": timeline_sorted,
        "record_count": len(records),
    })


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}
