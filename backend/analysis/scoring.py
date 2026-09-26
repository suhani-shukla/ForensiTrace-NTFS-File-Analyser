"""Additive risk scoring for detection results."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable

from backend.models.schemas import DetectionResult, RiskScore


logger = logging.getLogger(__name__)

RULE_WEIGHTS = {
    "RULE_1_SI_FN_MISMATCH": 30,
    "RULE_2_USN_BASIC_INFO_CHANGE": 25,
    "RULE_3_TIMESTAMP_ZEROING": 20,
    "RULE_5_LOGFILE_CORROBORATION": 15,
}
RULE_4_SUSPICIOUS_SEQUENCE = "RULE_4_SUSPICIOUS_SEQUENCE"


def _risk_level(total_score: int) -> str:
    if total_score >= 55:
        return "HIGH"
    if total_score >= 25:
        return "MEDIUM"
    return "LOW"


def calculate_risk_scores(
    findings: Iterable[DetectionResult],
) -> list[RiskScore]:
    """Aggregate triggered findings into one risk score per file and scenario."""
    grouped: defaultdict[
        tuple[str, str], list[DetectionResult]
    ] = defaultdict(list)
    for finding in findings:
        grouped[(finding.scenario_id, finding.file_reference)].append(finding)

    scores: list[RiskScore] = []
    for (scenario_id, file_reference), file_findings in grouped.items():
        triggered_findings = [finding for finding in file_findings if finding.triggered]
        total_score = 0
        triggered_rules: list[str] = []

        for finding in triggered_findings:
            if finding.rule_id == RULE_4_SUSPICIOUS_SEQUENCE:
                logger.warning(
                    "No risk weight is defined for %s; excluding it from "
                    "scenario=%s file_reference=%s",
                    RULE_4_SUSPICIOUS_SEQUENCE,
                    scenario_id,
                    file_reference,
                )
                if finding.rule_id not in triggered_rules:
                    triggered_rules.append(finding.rule_id)
                continue

            weight = RULE_WEIGHTS.get(finding.rule_id)
            if weight is None:
                logger.warning(
                    "No risk weight is defined for rule_id=%s; excluding it from "
                    "scenario=%s file_reference=%s",
                    finding.rule_id,
                    scenario_id,
                    file_reference,
                )
                continue

            total_score += weight
            if finding.rule_id not in triggered_rules:
                triggered_rules.append(finding.rule_id)

        representative = file_findings[0]
        scores.append(
            RiskScore(
                scenario_id=scenario_id,
                file_reference=file_reference,
                full_path=representative.full_path,
                total_score=total_score,
                risk_level=_risk_level(total_score),
                triggered_rules=triggered_rules,
            )
        )

    return scores


score_findings = calculate_risk_scores