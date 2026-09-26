

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.models.schemas import ParsedRecord, TimestampSet

# Shape this module assumes backend/parsers/mft_parser.py produces per raw
# MFT record. Update this comment (and _normalize_mft_record) once Person 1's
# real output is available.
MFT_RAW_RECORD_EXAMPLE: Dict[str, Any] = {
    "file_reference": "1234:5",
    "parent_file_reference": "1000:2",
    "file_name": "clean_file.txt",
    "full_path": "C:/Users/test/clean_file.txt",
    "is_directory": False,
    "standard_information": {
        "created": "2026-09-01T10:00:00Z",
        "modified": "2026-09-01T10:00:00Z",
        "mft_modified": "2026-09-01T10:00:00Z",
        "accessed": "2026-09-01T10:00:00Z",
    },
    "file_name_attribute": {  # None for records with no $FILE_NAME attribute
        "created": "2026-09-01T10:00:00Z",
        "modified": "2026-09-01T10:00:00Z",
        "mft_modified": "2026-09-01T10:00:00Z",
        "accessed": "2026-09-01T10:00:00Z",
    },
    "raw": {"note": "whatever mft_parser.py keeps for traceability"},
}


def _record_id(source: str, index: int, file_reference: str) -> str:
    return f"{source.lower()}_{file_reference.replace(':', '_')}_{index}"


def _timestamp_set(times: Optional[Dict[str, str]]) -> Optional[TimestampSet]:
    if not times:
        return None
    return TimestampSet(**times)


def _normalize_mft_record(index: int, raw: Dict[str, Any]) -> ParsedRecord:
    """Normalize one raw $MFT record (Person 1's parser output) into a ParsedRecord."""
    return ParsedRecord(
        record_id=_record_id("MFT", index, raw["file_reference"]),
        source="MFT",
        file_reference=raw["file_reference"],
        parent_file_reference=raw.get("parent_file_reference"),
        file_name=raw["file_name"],
        full_path=raw["full_path"],
        is_directory=raw["is_directory"],
        std_info_times=_timestamp_set(raw["standard_information"]),
        file_name_times=_timestamp_set(raw.get("file_name_attribute")),
        usn_reason=None,
        usn_timestamp=None,
        logfile_operation=None,
        logfile_timestamp=None,
        raw=raw.get("raw", {}),
    )


def _normalize_usnjrnl_record(index: int, raw: Dict[str, Any]) -> ParsedRecord:
    """Normalize one raw $UsnJrnl record (your usnjrnl_parser.py output)."""
    return ParsedRecord(
        record_id=_record_id("UsnJrnl", index, raw["file_reference"]),
        source="UsnJrnl",
        file_reference=raw["file_reference"],
        parent_file_reference=raw.get("parent_file_reference"),
        file_name=raw["file_name"],
        # $UsnJrnl records don't carry a full path by themselves; a real
        # implementation resolves this by walking parent_file_reference
        # links against the MFT-derived records. Until that resolver
        # exists, fall back to the file name so the field is never empty.
        # TODO-INTEGRATION: replace with real path resolution once the
        # normalizer has access to the full MFT record set for path-walking.
        full_path=raw.get("full_path", raw["file_name"]),
        is_directory=raw["is_directory"],
        std_info_times=TimestampSet(
            created=raw["timestamp"],
            modified=raw["timestamp"],
            mft_modified=raw["timestamp"],
            accessed=raw["timestamp"],
        ),
        file_name_times=None,
        usn_reason=raw["reason"],
        usn_timestamp=raw["timestamp"],
        logfile_operation=None,
        logfile_timestamp=None,
        raw=raw.get("raw", {}),
    )


def _normalize_logfile_record(index: int, raw: Dict[str, Any]) -> Optional[ParsedRecord]:
    """
    Normalize one raw $LogFile record (your logfile_parser.py output).

    Not every $LogFile record resolves to a usable ParsedRecord: many are
    low-level operations on attributes we can't (yet) tie back to a file
    (see logfile_parser.py's docstring for why). Records with no resolved
    file_reference are skipped here rather than emitted with a null
    file_reference, since file_reference is a required field on ParsedRecord.
    """
    if not raw.get("file_reference"):
        return None

    std_info_times = raw.get("std_info_times")

    return ParsedRecord(
        record_id=_record_id("LogFile", index, raw["file_reference"]),
        source="LogFile",
        file_reference=raw["file_reference"],
        parent_file_reference=None,
        # $LogFile records don't carry a file name either; same caveat as
        # the $UsnJrnl branch above applies.
        # TODO-INTEGRATION: resolve via cross-reference against MFT/UsnJrnl
        # ParsedRecords sharing the same file_reference, once this function
        # is called from a context that has that full set available.
        file_name=raw.get("file_name", raw["file_reference"]),
        full_path=raw.get("full_path", raw["file_reference"]),
        is_directory=False,
        std_info_times=_timestamp_set(std_info_times)
        or TimestampSet(
            created="1970-01-01T00:00:00Z",
            modified="1970-01-01T00:00:00Z",
            mft_modified="1970-01-01T00:00:00Z",
            accessed="1970-01-01T00:00:00Z",
        ),
        file_name_times=None,
        usn_reason=None,
        usn_timestamp=None,
        logfile_operation=raw["logfile_operation"],
        logfile_timestamp=raw.get("timestamp"),
        raw=raw.get("raw", {}),
    )


def normalize(
    mft_raw_records: List[Dict[str, Any]],
    usnjrnl_raw_records: List[Dict[str, Any]],
    logfile_raw_records: List[Dict[str, Any]],
) -> List[ParsedRecord]:
    """
    Merge raw output from all three parsers into one unified, schema-correct
    list[ParsedRecord]. Order is not guaranteed to be chronological here —
    that's backend/analysis/timeline.py's job (Person 3), which sorts by
    each ParsedRecord's relevant timestamp field.
    """
    normalized: List[ParsedRecord] = []

    for i, raw in enumerate(mft_raw_records):
        normalized.append(_normalize_mft_record(i, raw))

    for i, raw in enumerate(usnjrnl_raw_records):
        normalized.append(_normalize_usnjrnl_record(i, raw))

    for i, raw in enumerate(logfile_raw_records):
        parsed = _normalize_logfile_record(i, raw)
        if parsed is not None:
            normalized.append(parsed)

    return normalized


if __name__ == "__main__":
    # Quick manual smoke test against Person 1's Day-1 fixtures, treating the
    # fixture ParsedRecords themselves as a stand-in for "already normalized"
    # data, just to confirm every field round-trips through the schema.
    import json

    with open("fixtures/sample_parsed_records.json") as f:
        fixture_records = json.load(f)

    for record in fixture_records:
        ParsedRecord(**record)  # raises if the schema doesn't match

    print(f"{len(fixture_records)} fixture records validated against ParsedRecord OK")