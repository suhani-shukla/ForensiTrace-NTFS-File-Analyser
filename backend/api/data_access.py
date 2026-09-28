"""
data_access.py
----------------
The ONLY module that knows where API data comes from. routes.py and the
dashboard handlers in main.py call the functions below and never touch
fixture files or pipeline modules directly.

Data sources
------------
Default: the team's shared ``fixtures/*.json`` (Person 1's Day-1 fixtures).
Those files are flat lists shared by every scenario. ``DetectionResult`` and
``RiskScore`` carry ``scenario_id`` so they filter directly. ``ParsedRecord``
and ``TimelineEvent`` do NOT carry one, so they are attributed to a scenario
through ``file_reference``: a record/event belongs to a scenario if that
scenario has a detection or score row for the same file_reference.
(# TODO-INTEGRATION: this is a fixture-only workaround. Once
dataset/scenarios/<id>/ is parsed for real, scoping comes from the directory.)

Optional: set FORENSITRACE_DEMO_DATA=1 to read ``backend/api/demo_data/``
instead. That is a richer demo set (all of Rules 1/2/3/5 firing, scenario-keyed
dict files) useful for screenshots and demo fallback.

Switching to the real pipeline (Day 4-5)
----------------------------------------
Real signatures in this repo:
    normalize(mft_raw, usnjrnl_raw, logfile_raw) -> list[ParsedRecord]
    run_rules(records, scenario_id)              -> list[DetectionResult]
    calculate_risk_scores(findings)              -> list[RiskScore]   # no scenario_id arg
    build_timeline(records)                      -> list[TimelineEvent]  # raises ValueError on bad timestamp
Each get_* function has a # TODO-INTEGRATION block showing the replacement.
Blocked today on backend/parsers/mft_parser.py (empty) and a real
dataset/scenarios/<id>/ layout.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List, Optional, Set

from backend.models.schemas import ParsedRecord, DetectionResult, RiskScore, TimelineEvent

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = Path(__file__).resolve().parent / "demo_data"
TEAM_FIXTURES_DIR = REPO_ROOT / "fixtures"


def _fixtures_dir() -> Path:
    return DEMO_DIR if os.environ.get("FORENSITRACE_DEMO_DATA") == "1" else TEAM_FIXTURES_DIR


def _load(filename: str) -> Any:
    with open(_fixtures_dir() / filename, encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data.pop("_note", None)  # documentation-only key in the demo files
    return data


def _file_refs_for_scenario(scenario_id: str) -> Set[str]:
    """file_references that a scenario's detections/scores mention."""
    refs: Set[str] = set()
    for fname in ("sample_detection_results.json", "sample_risk_scores.json"):
        data = _load(fname)
        rows = data.get(scenario_id, []) if isinstance(data, dict) else [
            r for r in data if r.get("scenario_id") == scenario_id
        ]
        refs.update(r["file_reference"] for r in rows)
    return refs


def _scoped_by_scenario_id(fname: str, scenario_id: str) -> List[dict]:
    data = _load(fname)
    if isinstance(data, dict):
        return data.get(scenario_id, [])
    return [r for r in data if r.get("scenario_id") == scenario_id]


def _scoped_by_file_ref(fname: str, scenario_id: str) -> List[dict]:
    data = _load(fname)
    if isinstance(data, dict):  # demo data is already keyed by scenario
        return data.get(scenario_id, [])
    refs = _file_refs_for_scenario(scenario_id)
    return [r for r in data if r.get("file_reference") in refs]


def list_scenario_ids() -> List[str]:
    """
    GET /scenarios.

    # TODO-INTEGRATION (Day 5): replace with the dataset directory listing:
    #     return sorted(p.name for p in (REPO_ROOT / "dataset" / "scenarios").iterdir() if p.is_dir())
    """
    data = _load("sample_detection_results.json")
    if isinstance(data, dict):
        return sorted(data.keys())
    return sorted({r["scenario_id"] for r in data})


def scenario_exists(scenario_id: str) -> bool:
    return scenario_id in list_scenario_ids()


def get_records(scenario_id: str) -> Optional[List[ParsedRecord]]:
    """
    GET /scenarios/{id}/records.

    # TODO-INTEGRATION (needs mft_parser.py + dataset/scenarios/<id>/):
    #     from backend.parsers.mft_parser import parse_mft
    #     from backend.parsers.usnjrnl_parser import parse_usnjrnl
    #     from backend.parsers.logfile_parser import parse_logfile
    #     from backend.normalization.normalizer import normalize
    #     d = REPO_ROOT / "dataset" / "scenarios" / scenario_id
    #     return normalize(parse_mft(d / "$MFT"), parse_usnjrnl(d / "$J"), parse_logfile(d / "$LogFile"))
    """
    if not scenario_exists(scenario_id):
        return None
    return [ParsedRecord(**r) for r in _scoped_by_file_ref("sample_parsed_records.json", scenario_id)]


def get_analysis(scenario_id: str) -> Optional[List[DetectionResult]]:
    """
    GET /scenarios/{id}/analysis.

    # TODO-INTEGRATION:
    #     from backend.analysis.rules import run_rules
    #     return run_rules(get_records(scenario_id), scenario_id)
    """
    if not scenario_exists(scenario_id):
        return None
    return [DetectionResult(**r) for r in _scoped_by_scenario_id("sample_detection_results.json", scenario_id)]


def get_scores(scenario_id: str) -> Optional[List[RiskScore]]:
    """
    GET /scenarios/{id}/score.

    # TODO-INTEGRATION:
    #     from backend.analysis.scoring import calculate_risk_scores
    #     return calculate_risk_scores(get_analysis(scenario_id))
    """
    if not scenario_exists(scenario_id):
        return None
    return [RiskScore(**r) for r in _scoped_by_scenario_id("sample_risk_scores.json", scenario_id)]


def get_timeline(scenario_id: str) -> Optional[List[TimelineEvent]]:
    """
    GET /scenarios/{id}/timeline.

    # TODO-INTEGRATION (build_timeline raises ValueError on a bad timestamp):
    #     from backend.analysis.timeline import build_timeline
    #     try:
    #         return build_timeline(get_records(scenario_id))
    #     except ValueError as e:
    #         raise HTTPException(500, f"Timeline build failed: {e}")
    """
    if not scenario_exists(scenario_id):
        return None
    return [TimelineEvent(**e) for e in _scoped_by_file_ref("sample_timeline_events.json", scenario_id)]
