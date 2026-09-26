from __future__ import annotations

import io
from typing import Any, BinaryIO, Dict, List, Union

from dfir_ntfs import USN
from dfir_ntfs.MFT import DecodeFileRecordSegmentReference

# FILE_ATTRIBUTE_DIRECTORY, per the Windows API (winnt.h).
FILE_ATTRIBUTE_DIRECTORY = 0x10

# Strip this prefix so our reason strings match the naming convention used in
# fixtures/sample_parsed_records.json (e.g. "RENAME_NEW_NAME", not
# "USN_REASON_RENAME_NEW_NAME").
_REASON_PREFIX = "USN_REASON_"


def _format_file_reference(reference_number: int) -> str:
    """Convert a packed 64-bit NTFS file reference into "segment:sequence"."""
    segment_number, sequence_number = DecodeFileRecordSegmentReference(reference_number)
    return f"{segment_number}:{sequence_number}"


def _decode_reasons(reason_bitmask: int) -> List[str]:
    """Decode a USN reason bitmask into a list of short reason names."""
    reasons = []
    for flag, name in sorted(USN.ReasonList.items()):
        if reason_bitmask & flag:
            short_name = name[len(_REASON_PREFIX):] if name.startswith(_REASON_PREFIX) else name
            reasons.append(short_name)
    return reasons


def _format_timestamp(dt) -> str | None:
    """Format a naive UTC datetime (as returned by dfir_ntfs) as ISO8601 with 'Z'."""
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_usnjrnl(source: Union[str, BinaryIO]) -> List[Dict[str, Any]]:
    """
    Parse a $UsnJrnl:$J file (path or already-open binary file object) into a
    list of raw record dicts. See module docstring for the output shape.
    """
    file_object: BinaryIO
    opened_here = False

    if isinstance(source, (str, bytes)):
        file_object = open(source, "rb")
        opened_here = True
    else:
        file_object = source

    try:
        parser = USN.ChangeJournalParser(file_object)
        records: List[Dict[str, Any]] = []

        for usn_record in parser.usn_records():
            file_attributes = usn_record.get_file_attributes()
            is_directory = bool(file_attributes & FILE_ATTRIBUTE_DIRECTORY)

            records.append(
                {
                    "usn": usn_record.get_usn(),
                    "file_reference": _format_file_reference(
                        usn_record.get_file_reference_number()
                    ),
                    "parent_file_reference": _format_file_reference(
                        usn_record.get_parent_file_reference_number()
                    ),
                    "file_name": usn_record.get_file_name(),
                    "is_directory": is_directory,
                    "reason": _decode_reasons(usn_record.get_reason()),
                    "source_info": USN.ResolveSourceCodes(usn_record.get_source_info()),
                    "timestamp": _format_timestamp(usn_record.get_timestamp()),
                    "raw": {
                        "file_attributes": file_attributes,
                        "major_version": usn_record.get_major_version(),
                        "minor_version": usn_record.get_minor_version(),
                        "security_id": usn_record.get_security_id(),
                    },
                }
            )

        return records
    finally:
        if opened_here:
            file_object.close()


if __name__ == "__main__":
    # Quick manual smoke test:
    #   python usnjrnl_parser.py path/to/extracted/$UsnJrnl_$J
    import sys
    import json

    if len(sys.argv) != 2:
        print("usage: python usnjrnl_parser.py <path-to-usnjrnl-$J-stream>")
        raise SystemExit(1)

    parsed = parse_usnjrnl(sys.argv[1])
    print(json.dumps(parsed, indent=2))
