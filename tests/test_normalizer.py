import json
from pathlib import Path

from backend.models.schemas import ParsedRecord
from backend.normalization.normalizer import MFT_RAW_RECORD_EXAMPLE, normalize

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def test_fixtures_validate_against_parsed_record_schema():
    """
    Confirms Person 1's actual fixture data matches the frozen ParsedRecord
    schema exactly. If this test ever fails, it means schema drift has
    happened between schemas.py and the fixtures — flag it to the team
    immediately per the team plan's Risk #2.
    """
    with open(FIXTURES_DIR / "sample_parsed_records.json") as f:
        fixture_records = json.load(f)

    for record in fixture_records:
        ParsedRecord(**record)  # raises pydantic.ValidationError on mismatch


def test_normalize_merges_all_three_sources_into_one_list():
    mft_raw = [MFT_RAW_RECORD_EXAMPLE]

    usnjrnl_raw = [
        {
            "usn": 1,
            "file_reference": "1235:3",
            "parent_file_reference": "1000:2",
            "file_name": "renamed_file.txt",
            "is_directory": False,
            "reason": ["RENAME_NEW_NAME"],
            "source_info": "None",
            "timestamp": "2026-09-02T09:05:00Z",
            "raw": {},
        }
    ]

    logfile_raw = [
        {
            "lsn": 1,
            "transaction_id": 1,
            "operation": "UpdateResidentValue",
            "file_reference": "1236:1",
            "attribute_type": "$STANDARD_INFORMATION",
            "logfile_operation": "UpdateResidentValue",
            "timestamp": "2020-01-01T09:00:00Z",
            "std_info_times": {
                "created": "2020-01-01T09:00:00Z",
                "modified": "2020-01-01T09:00:00Z",
                "mft_modified": "2026-09-03T14:00:00Z",
                "accessed": "2026-09-03T14:00:00Z",
            },
            "raw": {},
        }
    ]

    result = normalize(mft_raw, usnjrnl_raw, logfile_raw)

    assert len(result) == 3
    assert {r.source for r in result} == {"MFT", "UsnJrnl", "LogFile"}
    assert all(isinstance(r, ParsedRecord) for r in result)


def test_normalize_skips_logfile_records_with_no_resolved_file_reference():
    """
    Many $LogFile records can't be tied back to a file (see logfile_parser.py
    docstring). The normalizer must drop these rather than emit a broken
    ParsedRecord with a null file_reference.
    """
    logfile_raw = [
        {
            "lsn": 1,
            "transaction_id": 1,
            "operation": "CreateAttribute",
            "file_reference": None,
            "attribute_type": None,
            "logfile_operation": "CreateAttribute",
            "timestamp": None,
            "std_info_times": None,
            "raw": {},
        }
    ]

    assert normalize([], [], logfile_raw) == []


def test_normalize_usnjrnl_record_carries_usn_reason_and_timestamp():
    usnjrnl_raw = [
        {
            "usn": 42,
            "file_reference": "2000:1",
            "parent_file_reference": "1000:2",
            "file_name": "evidence.txt",
            "is_directory": False,
            "reason": ["BASIC_INFO_CHANGE"],
            "source_info": "None",
            "timestamp": "2026-09-05T00:00:00Z",
            "raw": {},
        }
    ]

    [record] = normalize([], usnjrnl_raw, [])

    assert record.usn_reason == ["BASIC_INFO_CHANGE"]
    assert record.usn_timestamp == "2026-09-05T00:00:00Z"
    assert record.logfile_operation is None