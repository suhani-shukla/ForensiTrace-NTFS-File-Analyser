"""
Tests for Person 4's API + dashboard (backend/main.py, routes.py, report_service.py).

Default data source is the team's shared fixtures/ directory. A second group
of tests switches to backend/api/demo_data/ via FORENSITRACE_DEMO_DATA=1.

Run with: pytest tests/test_api.py -v   (needs httpx: pip install httpx)
"""
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)

FIXTURE_SCENARIOS = {"timestomped_creation", "zeroed_timestamps", "clean_file"}


def test_list_scenarios():
    r = client.get("/scenarios")
    assert r.status_code == 200
    assert FIXTURE_SCENARIOS <= set(r.json())


def test_unknown_scenario_returns_404():
    for endpoint in ["records", "analysis", "timeline", "score", "report"]:
        r = client.get(f"/scenarios/does_not_exist/{endpoint}")
        assert r.status_code == 404, f"{endpoint} did not 404 for an unknown scenario"


def test_records_are_scoped_to_scenario():
    r = client.get("/scenarios/timestomped_creation/records")
    assert r.status_code == 200
    refs = {rec["file_reference"] for rec in r.json()}
    assert refs == {"1236:1"}


def test_analysis_endpoint():
    r = client.get("/scenarios/timestomped_creation/analysis")
    assert r.status_code == 200
    results = r.json()
    assert [d["rule_id"] for d in results] == ["RULE_1_SI_FN_MISMATCH"]
    assert results[0]["triggered"] is True


def test_score_endpoint_levels():
    scores = client.get("/scenarios/timestomped_creation/score").json()
    assert scores[0]["total_score"] == 30 and scores[0]["risk_level"] == "MEDIUM"
    scores = client.get("/scenarios/zeroed_timestamps/score").json()
    assert scores[0]["risk_level"] == "LOW"


def test_clean_file_is_low_and_untriggered():
    scores = client.get("/scenarios/clean_file/score").json()
    assert all(s["risk_level"] == "LOW" and s["total_score"] == 0 for s in scores)
    analysis = client.get("/scenarios/clean_file/analysis").json()
    assert not any(d["triggered"] for d in analysis)


def test_timeline_endpoint():
    events = client.get("/scenarios/timestomped_creation/timeline").json()
    assert events and all(e["source"] in ("MFT", "UsnJrnl", "LogFile") for e in events)


def test_report_html_download():
    r = client.get("/scenarios/timestomped_creation/report?format=html")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "attachment" in r.headers["content-disposition"]
    assert "timestomped.exe" in r.text
    assert "RULE_1_SI_FN_MISMATCH" in r.text


def test_report_text_download():
    r = client.get("/scenarios/timestomped_creation/report?format=text")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "DIGITAL FORENSIC INVESTIGATION REPORT" in r.text


def test_report_rejects_bad_format():
    assert client.get("/scenarios/clean_file/report?format=pdf").status_code == 422


def test_dashboard_pages():
    r = client.get("/dashboard")
    assert r.status_code == 200 and "FORENSITRACE" in r.text and "timestomped_creation" in r.text
    r = client.get("/dashboard/timestomped_creation")
    assert r.status_code == 200 and "timestomped.exe" in r.text and "RULE_1_SI_FN_MISMATCH" in r.text
    assert client.get("/dashboard/does_not_exist").status_code == 404


def test_root_redirects_to_dashboard():
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/dashboard"


# --- optional richer demo data (FORENSITRACE_DEMO_DATA=1) -------------------

@pytest.fixture
def demo_data(monkeypatch):
    monkeypatch.setenv("FORENSITRACE_DEMO_DATA", "1")


def test_demo_timestomp_is_high_risk(demo_data):
    scores = client.get("/scenarios/timestomp_demo/score").json()
    assert len(scores) == 1
    assert scores[0]["risk_level"] == "HIGH" and scores[0]["total_score"] == 70


def test_demo_records_and_timeline(demo_data):
    assert len(client.get("/scenarios/timestomp_demo/records").json()) == 5
    assert len(client.get("/scenarios/timestomp_demo/timeline").json()) == 4
    ids = client.get("/scenarios").json()
    assert "clean_baseline" in ids and "timestomp_demo" in ids
