"""
report_service.py
-------------------
Generates a per-scenario investigation report in HTML or plain text,
summarizing triggered rules, risk scores, and the reconstructed timeline.
Used by:
  - GET /scenarios/{scenario_id}/report (routes.py)
  - the dashboard's "Download Report" button (dashboard/templates/scenario.html
    just links straight to that same endpoint, so the report a person
    downloads always matches what the dashboard displays)
"""
from __future__ import annotations
import datetime
from typing import List

from backend.models.schemas import ParsedRecord, DetectionResult, RiskScore, TimelineEvent

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _sorted_scores(scores: List[RiskScore]) -> List[RiskScore]:
    return sorted(scores, key=lambda s: (RISK_ORDER.get(s.risk_level, 9), -s.total_score))


def _findings_for_file(detections: List[DetectionResult], file_reference: str) -> List[DetectionResult]:
    return [d for d in detections if d.file_reference == file_reference and d.triggered]


def build_report_text(scenario_id: str, records: List[ParsedRecord], detections: List[DetectionResult],
                       scores: List[RiskScore], timeline: List[TimelineEvent]) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("DIGITAL FORENSIC INVESTIGATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Scenario ID: {scenario_id}")
    lines.append(f"Generated:   {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    lines.append(f"Files analyzed: {len(scores)}   Records parsed: {len(records)}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("RISK SUMMARY")
    lines.append("-" * 70)
    sorted_scores = _sorted_scores(scores)
    for s in sorted_scores:
        lines.append(f"{s.risk_level:>7}  {s.total_score:>3}/100  {s.full_path}")
        if s.triggered_rules:
            lines.append(f"          triggered: {', '.join(s.triggered_rules)}")
    if not sorted_scores:
        lines.append("No files scored in this scenario.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("DETAILED FINDINGS")
    lines.append("-" * 70)
    any_findings = False
    for s in sorted_scores:
        findings = _findings_for_file(detections, s.file_reference)
        if not findings:
            continue
        any_findings = True
        lines.append(f"\n{s.full_path}  ({s.risk_level}, {s.total_score}/100)")
        for f in findings:
            lines.append(f"  [{f.rule_id}] +{f.score_contribution}")
            if f.evidence:
                for k, v in f.evidence.items():
                    lines.append(f"      {k}: {v}")
            if f.logfile_corroboration:
                lines.append(f"      $LogFile corroboration: {f.logfile_corroboration.details}")
    if not any_findings:
        lines.append("No triggered findings in this scenario.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("RECONSTRUCTED TIMELINE")
    lines.append("-" * 70)
    for e in sorted(timeline, key=lambda x: x.timestamp):
        lines.append(f"{e.timestamp}  [{e.source:>7}]  {e.full_path}  -- {e.event_type}")
    if not timeline:
        lines.append("No timeline events reconstructed for this scenario.")
    lines.append("")

    lines.append("-" * 70)
    lines.append("METHODOLOGY NOTE")
    lines.append("-" * 70)
    lines.append(
        "Scores are produced by additive rule-based cross-analysis of $MFT, $UsnJrnl, "
        "and $LogFile artifacts. They are a triage aid, not a definitive determination -- "
        "legitimate software can also modify timestamps and attributes. Review findings "
        "against case context before treating them as conclusive."
    )
    return "\n".join(lines)


def build_report_html(scenario_id: str, records: List[ParsedRecord], detections: List[DetectionResult],
                       scores: List[RiskScore], timeline: List[TimelineEvent]) -> str:
    sorted_scores = _sorted_scores(scores)

    def esc(s) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    risk_rows = []
    for s in sorted_scores:
        risk_rows.append(
            f'<tr><td class="risk-{s.risk_level}">{s.risk_level}</td>'
            f'<td class="num">{s.total_score}/100</td>'
            f'<td>{esc(s.full_path)}</td>'
            f'<td>{esc(", ".join(s.triggered_rules)) or "&mdash;"}</td></tr>'
        )
    risk_table = "\n".join(risk_rows) or '<tr><td colspan="4">No files scored in this scenario.</td></tr>'

    findings_blocks = []
    for s in sorted_scores:
        findings = _findings_for_file(detections, s.file_reference)
        if not findings:
            continue
        items = []
        for f in findings:
            evidence_html = "".join(f"<li><b>{esc(k)}:</b> {esc(v)}</li>" for k, v in f.evidence.items())
            corroboration_html = (
                f'<div class="corrob">$LogFile corroboration: {esc(f.logfile_corroboration.details)}</div>'
                if f.logfile_corroboration else ""
            )
            items.append(
                f'<div class="finding"><div class="ft"><span>{esc(f.rule_id)}</span>'
                f'<span class="pts">+{f.score_contribution}</span></div>'
                f'<ul>{evidence_html}</ul>{corroboration_html}</div>'
            )
        findings_blocks.append(
            f'<h3>{esc(s.full_path)} <span class="risk-{s.risk_level}">({s.risk_level}, {s.total_score}/100)</span></h3>'
            + "".join(items)
        )
    findings_html = "\n".join(findings_blocks) or "<p>No triggered findings in this scenario.</p>"

    timeline_rows = "\n".join(
        f'<tr><td class="mono">{esc(e.timestamp)}</td><td>{esc(e.source)}</td>'
        f'<td>{esc(e.full_path)}</td><td>{esc(e.event_type)}</td></tr>'
        for e in sorted(timeline, key=lambda x: x.timestamp)
    ) or '<tr><td colspan="4">No timeline events reconstructed.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Digital Forensic Investigation Report — {esc(scenario_id)}</title>
<style>
  body {{ font-family: Georgia, 'Times New Roman', serif; max-width: 820px; margin: 44px auto;
         color: #1a1a1a; line-height: 1.6; padding: 0 20px; }}
  h1 {{ font-size: 22px; border-bottom: 3px double #1a1a1a; padding-bottom: 10px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 34px;
        border-bottom: 1px solid #999; padding-bottom: 6px; }}
  h3 {{ font-size: 14.5px; margin-top: 22px; }}
  .meta {{ font-family: 'Courier New', monospace; font-size: 13px; color: #444; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13.5px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; }}
  th {{ color: #555; font-weight: 600; }}
  .num {{ text-align: right; font-family: 'Courier New', monospace; }}
  .mono {{ font-family: 'Courier New', monospace; font-size: 12px; }}
  .risk-HIGH {{ color: #a3241d; font-weight: bold; }}
  .risk-MEDIUM {{ color: #9a6a12; font-weight: bold; }}
  .risk-LOW {{ color: #2b7a4b; font-weight: bold; }}
  .finding {{ margin: 10px 0 10px 8px; padding: 8px 0 8px 12px; border-left: 3px solid #ccc; font-size: 13.5px; }}
  .ft {{ display: flex; justify-content: space-between; font-weight: 600; }}
  .pts {{ font-family: 'Courier New', monospace; color: #555; }}
  .corrob {{ font-size: 12.5px; color: #555; margin-top: 4px; }}
  .caveat {{ font-size: 12.5px; color: #555; border-left: 3px solid #ccc; padding-left: 12px; margin-top: 30px; }}
  @media print {{ body {{ margin: 0; }} }}
</style>
</head>
<body>
  <h1>DIGITAL FORENSIC INVESTIGATION REPORT</h1>
  <div class="meta">
    Scenario ID: {esc(scenario_id)}<br>
    Report generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}<br>
    Files analyzed: {len(scores)} &nbsp;·&nbsp; Records parsed: {len(records)}
  </div>

  <h2>Risk Summary</h2>
  <table>
    <tr><th>Risk</th><th>Score</th><th>File</th><th>Triggered Rules</th></tr>
    {risk_table}
  </table>

  <h2>Detailed Findings</h2>
  {findings_html}

  <h2>Reconstructed Timeline</h2>
  <table>
    <tr><th>Timestamp</th><th>Source</th><th>File</th><th>Event</th></tr>
    {timeline_rows}
  </table>

  <div class="caveat">
    <b>Methodology note:</b> Scores are produced by additive rule-based cross-analysis of
    $MFT, $UsnJrnl, and $LogFile artifacts. They are a triage aid, not a definitive
    determination — legitimate software can also modify timestamps and attributes.
    Review findings against case context before treating them as conclusive.
  </div>
</body>
</html>
"""
