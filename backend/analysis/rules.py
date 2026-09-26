"""Detection rules for normalized NTFS forensic records."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from backend.models.schemas import DetectionResult, ParsedRecord


RULE_1_SI_FN_MISMATCH = "RULE_1_SI_FN_MISMATCH"
RULE_2_USN_BASIC_INFO_CHANGE = "RULE_2_USN_BASIC_INFO_CHANGE"
RULE_3_TIMESTAMP_ZEROING = "RULE_3_TIMESTAMP_ZEROING"
RULE_4_SUSPICIOUS_SEQUENCE = "RULE_4_SUSPICIOUS_SEQUENCE"

RULE_1_SCORE = 30
RULE_2_SCORE = 25
RULE_3_SCORE = 20
RULE_4_SCORE = 0
_ZEROING_MODULUS = 10_000_000
_SUSPICIOUS_SEQUENCE = ("create", "modify", "timestamp_change", "rename", "delete")


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


def _event_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "created": "create",
        "file_create": "create",
        "modified": "modify",
        "data_extend": "modify",
        "data_overwrite": "modify",
        "timestampchange": "timestamp_change",
        "timestamp_changed": "timestamp_change",
        "basic_info_change": "timestamp_change",
        "renamed": "rename",
        "rename_new_name": "rename",
        "rename_old_name": "rename",
        "file_delete": "delete",
        "deleted": "delete",
    }
    return aliases.get(normalized, normalized if normalized in _SUSPICIOUS_SEQUENCE else None)


def _event_timestamp(record: ParsedRecord, event_type: str, raw: dict[str, Any]) -> str:
    raw_timestamp = raw.get("timestamp") or raw.get("event_timestamp")
    if isinstance(raw_timestamp, str):
        return raw_timestamp
    if record.source == "UsnJrnl" and record.usn_timestamp:
        return record.usn_timestamp
    if record.source == "LogFile" and record.logfile_timestamp:
        return record.logfile_timestamp
    if event_type == "create":
        return record.std_info_times.created
    if event_type == "modify":
        return record.std_info_times.modified
    if event_type == "timestamp_change":
        return record.std_info_times.mft_modified
    return record.std_info_times.modified


def _record_events(record: ParsedRecord) -> list[dict[str, Any]]:
    raw = record.raw
    events: list[dict[str, Any]] = []
    raw_events = raw.get("events")
    if isinstance(raw_events, list):
        for item in raw_events:
            if not isinstance(item, dict):
                continue
            event_type = _event_type(item.get("event_type") or item.get("type"))
            if event_type:
                events.append(
                    {
                        "event_type": event_type,
                        "timestamp": _event_timestamp(record, event_type, item),
                        "record_id": record.record_id,
                    }
                )

    explicit_type = _event_type(
        raw.get("event_type") or raw.get("event") or raw.get("operation")
    )
    if explicit_type:
        events.append(
            {
                "event_type": explicit_type,
                "timestamp": _event_timestamp(record, explicit_type, raw),
                "record_id": record.record_id,
            }
        )

    for reason in record.usn_reason or []:
        event_type = _event_type(reason)
        if event_type:
            events.append(
                {
                    "event_type": event_type,
                    "timestamp": _event_timestamp(record, event_type, raw),
                    "record_id": record.record_id,
                }
            )

    logfile_event = _event_type(record.logfile_operation)
    if logfile_event:
        events.append(
            {
                "event_type": logfile_event,
                "timestamp": _event_timestamp(record, logfile_event, raw),
                "record_id": record.record_id,
            }
        )
    return events


def _event_sort_key(event: dict[str, Any]) -> tuple[int, Any]:
    timestamp = event["timestamp"]
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return (1, timestamp)
    return (0, parsed)


def detect_rule_4(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Detect create/modify/timestamp-change/rename/delete sequences per file."""
    records_by_reference: dict[str, list[ParsedRecord]] = {}
    for record in records:
        records_by_reference.setdefault(record.file_reference, []).append(record)

    results: list[DetectionResult] = []
    for file_reference, file_records in records_by_reference.items():
        events = [
            event
            for record in file_records
            for event in _record_events(record)
        ]
        events.sort(key=_event_sort_key)

        matched_events: list[dict[str, Any]] = []
        next_event = 0
        for event in events:
            if event["event_type"] == _SUSPICIOUS_SEQUENCE[next_event]:
                matched_events.append(event)
                next_event += 1
                if next_event == len(_SUSPICIOUS_SEQUENCE):
                    break

        triggered = len(matched_events) == len(_SUSPICIOUS_SEQUENCE)
        representative = file_records[0]
        evidence: dict[str, Any] = {
            "expected_sequence": list(_SUSPICIOUS_SEQUENCE),
            "observed_sequence": [event["event_type"] for event in matched_events],
            "events": matched_events,
        }
        results.append(
            _result(
                scenario_id,
                representative,
                RULE_4_SUSPICIOUS_SEQUENCE,
                triggered,
                RULE_4_SCORE,
                evidence,
            )
        )
    return results


def run_rules(
    records: Iterable[ParsedRecord], scenario_id: str
) -> list[DetectionResult]:
    """Run Rules 1–4 and return their results in rule order."""
    record_list = list(records)
    return [
        *detect_rule_1(record_list, scenario_id),
        *detect_rule_2(record_list, scenario_id),
        *detect_rule_3(record_list, scenario_id),
        *detect_rule_4(record_list, scenario_id),
    ]
