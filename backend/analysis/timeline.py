"""Chronological timeline reconstruction from normalized NTFS records."""

from __future__ import annotations

from datetime import datetime
from collections.abc import Iterable
from typing import Any

from backend.models.schemas import ParsedRecord, TimelineEvent


_REASON_EVENT_TYPES = {
    "FILE_CREATE": "create",
    "DATA_EXTEND": "modify",
    "DATA_OVERWRITE": "modify",
    "BASIC_INFO_CHANGE": "timestamp_change",
    "RENAME_NEW_NAME": "rename",
    "RENAME_OLD_NAME": "rename",
    "FILE_DELETE": "delete",
}

_OPERATION_EVENT_TYPES = {
    "create": "create",
    "file_create": "create",
    "created": "create",
    "modify": "modify",
    "modified": "modify",
    "data_extend": "modify",
    "data_overwrite": "modify",
    "timestamp_change": "timestamp_change",
    "update_timestamp": "timestamp_change",
    "updateresidentvalue": "timestamp_change",
    "updatenonresidentvalue": "timestamp_change",
    "rename": "rename",
    "renamed": "rename",
    "delete": "delete",
    "deleted": "delete",
}


def _normalize_event_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    return _OPERATION_EVENT_TYPES.get(normalized)


def _timestamp(record: ParsedRecord, event_type: str) -> str:
    if record.source == "UsnJrnl" and record.usn_timestamp:
        return record.usn_timestamp
    if record.source == "LogFile" and record.logfile_timestamp:
        return record.logfile_timestamp
    timestamps = {
        "create": record.std_info_times.created,
        "modify": record.std_info_times.modified,
        "timestamp_change": record.std_info_times.mft_modified,
        "rename": record.std_info_times.modified,
        "delete": record.std_info_times.modified,
    }
    return timestamps[event_type]


def _details(record: ParsedRecord, event_type: str) -> dict[str, Any]:
    details: dict[str, Any] = {
        "record_id": record.record_id,
        "file_name": record.file_name,
    }
    if record.parent_file_reference is not None:
        details["parent_file_reference"] = record.parent_file_reference
    if record.source == "UsnJrnl":
        details["usn_reason"] = record.usn_reason or []
    if record.source == "LogFile":
        details["logfile_operation"] = record.logfile_operation
    if event_type == "timestamp_change":
        details["std_info_times"] = record.std_info_times.model_dump()
    if record.raw:
        details["raw"] = record.raw
    return details


def _event(record: ParsedRecord, event_type: str) -> TimelineEvent:
    return TimelineEvent(
        timestamp=_timestamp(record, event_type),
        source=record.source,
        file_reference=record.file_reference,
        full_path=record.full_path,
        event_type=event_type,
        details=_details(record, event_type),
    )


def _record_events(record: ParsedRecord) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    raw = record.raw

    raw_events = raw.get("events")
    if isinstance(raw_events, list):
        for raw_event in raw_events:
            if not isinstance(raw_event, dict):
                continue
            event_type = _normalize_event_type(
                raw_event.get("event_type") or raw_event.get("type")
            )
            if event_type:
                event = _event(record, event_type)
                event.timestamp = raw_event.get("timestamp", event.timestamp)
                event.details["event"] = raw_event
                events.append(event)

    explicit_type = _normalize_event_type(
        raw.get("event_type") or raw.get("event") or raw.get("operation")
    )
    if explicit_type:
        event = _event(record, explicit_type)
        event.timestamp = raw.get("timestamp", event.timestamp)
        events.append(event)

    for reason in record.usn_reason or []:
        event_type = _REASON_EVENT_TYPES.get(reason.upper())
        if event_type:
            events.append(_event(record, event_type))

    if record.source == "LogFile" and not explicit_type:
        event_type = _normalize_event_type(record.logfile_operation)
        if event_type:
            events.append(_event(record, event_type))

    if events:
        return events

    if record.source == "MFT":
        if record.std_info_times.modified != record.std_info_times.mft_modified:
            return [_event(record, "timestamp_change")]
        if record.raw.get("raw_100ns_value") is not None:
            return [_event(record, "timestamp_change")]
        return [_event(record, "create")]
    return []


def _sort_key(event: TimelineEvent) -> datetime:
    try:
        return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Timeline event has invalid ISO8601 timestamp: {event.timestamp!r}"
        ) from exc


def build_timeline(records: Iterable[ParsedRecord]) -> list[TimelineEvent]:
    """Convert records from all artifact sources into a sorted timeline."""
    events = [event for record in records for event in _record_events(record)]
    events.sort(key=_sort_key)
    return events


reconstruct_timeline = build_timeline