"""Detection rules for normalized NTFS forensic records."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from backend.models.schemas import DetectionResult, ParsedRecord


RULE_1_SI_FN_MISMATCH = "RULE_1_SI_FN_MISMATCH"
RULE_2_USN_BASIC_INFO_CHANGE = "RULE_2_USN_BASIC_INFO_CHANGE"
RULE_3_TIMESTAMP_ZEROING = "RULE_3_TIMESTAMP_ZEROING"

RULE_1_SCORE = 30
RULE_2_SCORE = 25
RULE_3_SCORE = 20
_ZEROING_MODULUS = 10_000_000


def _result(
    scenario_id: str,
    record: ParsedRecord,
    rule_id: str,
    triggered: bool,
    score: int,
    evidence: dict[str, Any],
) -> DetectionResult:
    return DetectionResult(
        scenario_id=scenario_id,
        file_reference=record.file_reference,
        full_path=record.full_path,
        rule_id=rule_id,
        triggered=triggered,
        score_contribution=score if triggered else 0,
        evidence=evidence,
    )


def _timestamp_mismatches(record: ParsedRecord) -> dict[str, dict[str, str]]:
    if record.source != "MFT" or record.file_name_times is None:
        return {}

    mismatches: dict[str, dict[str, str]] = {}
    for field in ("created", "modified", "mft_modified", "accessed"):
        si_value = getattr(record.std_info_times, field)
        fn_value = getattr(record.file_name_times, field)
        if si_value != fn_value:
            mismatches[field] = {"si": si_value, "fn": fn_value}
    return mismatches


def detect_rule_1(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Compare matching $SI and $FN timestamps on MFT records."""
    results: list[DetectionResult] = []
    for record in records:
        if record.source != "MFT" or record.file_name_times is None:
            continue
        mismatches = _timestamp_mismatches(record)
        results.append(
            _result(
                scenario_id,
                record,
                RULE_1_SI_FN_MISMATCH,
                bool(mismatches),
                RULE_1_SCORE,
                {"mismatches": mismatches},
            )
        )
    return results


def _mft_timestamp_changed(record: ParsedRecord) -> bool:
    """Return whether an MFT record contains evidence of a timestamp change."""
    times = record.std_info_times
    if times.modified != times.mft_modified:
        return True

    raw = record.raw
    return bool(
        raw.get("timestamp_changed")
        or raw.get("mft_timestamp_changed")
        or raw.get("timestamp_change")
    )


def detect_rule_2(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Correlate USN BASIC_INFO_CHANGE records with MFT timestamp changes."""
    record_list = list(records)
    mft_by_reference = {
        record.file_reference: record
        for record in record_list
        if record.source == "MFT"
    }
    results: list[DetectionResult] = []

    for record in record_list:
        if record.source != "UsnJrnl" or not record.usn_reason:
            continue
        if "BASIC_INFO_CHANGE" not in record.usn_reason:
            continue

        mft_record = mft_by_reference.get(record.file_reference)
        correlated = mft_record is not None and _mft_timestamp_changed(mft_record)
        evidence: dict[str, Any] = {
            "usn_reason": record.usn_reason,
            "mft_record_found": mft_record is not None,
            "mft_timestamp_changed": bool(
                mft_record is not None and _mft_timestamp_changed(mft_record)
            ),
        }
        if mft_record is not None:
            evidence["mft_record_id"] = mft_record.record_id

        results.append(
            _result(
                scenario_id,
                record,
                RULE_2_USN_BASIC_INFO_CHANGE,
                correlated,
                RULE_2_SCORE,
                evidence,
            )
        )
    return results


def _raw_100ns_values(value: Any) -> list[int]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, dict):
        values: list[int] = []
        for key, nested in value.items():
            if key == "raw_100ns_value":
                values.extend(_raw_100ns_values(nested))
            elif isinstance(nested, (dict, list, tuple)):
                values.extend(_raw_100ns_values(nested))
        return values
    if isinstance(value, (list, tuple)):
        values: list[int] = []
        for nested in value:
            values.extend(_raw_100ns_values(nested))
        return values
    return []


def detect_rule_3(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Detect retained raw NTFS timestamps aligned to an exact second."""
    results: list[DetectionResult] = []
    for record in records:
        zeroed_values = [
            value
            for value in _raw_100ns_values(record.raw)
            if value % _ZEROING_MODULUS == 0
        ]
        results.append(
            _result(
                scenario_id,
                record,
                RULE_3_TIMESTAMP_ZEROING,
                bool(zeroed_values),
                RULE_3_SCORE,
                {"raw_100ns_values": zeroed_values},
            )
        )
    return results


def run_rules(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Run Rules 1–3 and return their results in rule order."""
    record_list = list(records)
    return [
        *detect_rule_1(record_list, scenario_id),
        *detect_rule_2(record_list, scenario_id),
        *detect_rule_3(record_list, scenario_id),
    ]
