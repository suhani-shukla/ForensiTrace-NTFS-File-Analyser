import datetime
import struct

from backend.parsers.logfile_parser import (
    _parse_std_info_times,
    _resolve_attribute_type_name,
)


def _to_filetime(dt: datetime.datetime) -> int:
    """Inverse of dfir_ntfs's FILETIME decoding, for building test data."""
    delta = dt - datetime.datetime(1601, 1, 1)
    return int(delta.total_seconds() * 10_000_000)


def test_parse_std_info_times_decodes_all_four_fields_in_order():
    created = datetime.datetime(2020, 1, 1, 9, 0, 0)
    modified = datetime.datetime(2026, 9, 3, 14, 0, 0)
    mft_modified = datetime.datetime(2026, 9, 3, 14, 0, 1)
    accessed = datetime.datetime(2026, 9, 3, 14, 0, 2)

    # $STANDARD_INFORMATION layout: created, modified, mft_modified, accessed
    # — four consecutive 8-byte little-endian FILETIME values.
    redo_data = struct.pack(
        "<4Q",
        _to_filetime(created),
        _to_filetime(modified),
        _to_filetime(mft_modified),
        _to_filetime(accessed),
    )

    assert _parse_std_info_times(redo_data) == {
        "created": "2020-01-01T09:00:00Z",
        "modified": "2026-09-03T14:00:00Z",
        "mft_modified": "2026-09-03T14:00:01Z",
        "accessed": "2026-09-03T14:00:02Z",
    }


def test_parse_std_info_times_returns_none_when_too_short():
    # Fewer than 32 bytes means we don't have all four timestamps.
    assert _parse_std_info_times(b"\x00" * 10) is None


def test_resolve_attribute_type_name_standard_information():
    assert _resolve_attribute_type_name(0x10) == "$STANDARD_INFORMATION"


def test_resolve_attribute_type_name_file_name():
    assert _resolve_attribute_type_name(0x30) == "$FILE_NAME"


def test_resolve_attribute_type_name_none_when_no_code():
    assert _resolve_attribute_type_name(None) is None


def test_resolve_attribute_type_name_unknown_code_falls_back_to_hex():
    assert _resolve_attribute_type_name(0xFFFF) == "0xffff"