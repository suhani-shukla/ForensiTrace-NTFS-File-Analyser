import datetime

from dfir_ntfs import USN

from backend.parsers.usnjrnl_parser import (
    _decode_reasons,
    _format_file_reference,
    _format_timestamp,
)


def test_format_file_reference_packs_segment_and_sequence():
    # Packed NTFS file reference layout: low 48 bits = segment number,
    # high 16 bits = sequence number. This packs segment=1235, sequence=3.
    packed = (3 << 48) | 1235
    assert _format_file_reference(packed) == "1235:3"


def test_format_file_reference_zero_sequence():
    packed = (0 << 48) | 1000
    assert _format_file_reference(packed) == "1000:0"


def test_decode_reasons_single_flag():
    assert _decode_reasons(USN.USN_REASON_RENAME_NEW_NAME) == ["RENAME_NEW_NAME"]


def test_decode_reasons_multiple_flags_sorted_by_flag_value():
    combined = USN.USN_REASON_DATA_EXTEND | USN.USN_REASON_RENAME_NEW_NAME
    # DATA_EXTEND's flag value is numerically smaller than RENAME_NEW_NAME's,
    # so it should come first.
    assert _decode_reasons(combined) == ["DATA_EXTEND", "RENAME_NEW_NAME"]


def test_decode_reasons_no_flags_set():
    assert _decode_reasons(0) == []


def test_format_timestamp_none_passthrough():
    assert _format_timestamp(None) is None


def test_format_timestamp_formats_iso8601_with_z_suffix():
    dt = datetime.datetime(2026, 9, 2, 9, 5, 0)
    assert _format_timestamp(dt) == "2026-09-02T09:05:00Z"