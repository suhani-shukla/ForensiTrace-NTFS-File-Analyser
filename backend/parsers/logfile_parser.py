from __future__ import annotations

import struct
from typing import Any, BinaryIO, Dict, List, Optional, Union

from dfir_ntfs import LogFile
from dfir_ntfs.Attributes import AttributeTypes
from dfir_ntfs.MFT import DecodeFileRecordSegmentReference

_STANDARD_INFORMATION_TYPE_CODE = 0x10

# Operation codes (from LogFile.NTFSOperations) that rewrite attribute bytes
# directly and are therefore where a real timestamp can be recovered if the
# target attribute happens to be $STANDARD_INFORMATION.
_RESIDENT_UPDATE_OP_NAMES = {"UpdateResidentValue", "UpdateNonresidentValue"}


def _format_file_reference(reference_number: Optional[int]) -> Optional[str]:
    if reference_number is None:
        return None
    segment_number, sequence_number = DecodeFileRecordSegmentReference(reference_number)
    return f"{segment_number}:{sequence_number}"


def _resolve_attribute_type_name(type_code: Optional[int]) -> Optional[str]:
    if type_code is None:
        return None
    entry = AttributeTypes.get(type_code)
    return entry[0] if entry else hex(type_code)


def _resolve_target(record) -> "tuple[Optional[int], Optional[int]]":
    """
    Resolve (file_reference_number, attribute_type_code) for a log record by
    checking, in order: the incrementally-built open-attribute dict on the
    record, then the periodic OAT dump snapshot attached to the record (if
    any). Returns (None, None) if neither source can resolve the index.
    """
    index = record.get_target_attribute()

    # 1) Explicit "OpenNonresidentAttribute" events populate record.oat as
    #    {index: (file_reference, attribute_name)} — mainly useful for named
    #    (ADS) streams, and doesn't carry an attribute *type* code.
    if index in record.oat:
        file_reference, _attribute_name = record.oat[index]
        return file_reference, None

    # 2) Periodic OpenAttributeTableDump snapshots carry full OPEN_ATTRIBUTE_ENTRY
    #    structures, which include both the file reference and the attribute
    #    type code. This is the path that resolves $STANDARD_INFORMATION /
    #    $FILE_NAME updates, which is what Rule 5 actually needs.
    oat_dump = getattr(record, "oat_dump", None)
    if oat_dump is not None:
        try:
            entry_buf = oat_dump.buf[index:]
            entry = oat_dump.oat_class(entry_buf)
        except Exception:
            return None, None
        try:
            return entry.get_file_reference(), entry.get_attribute_type_code()
        except Exception:
            return entry.get_file_reference(), None

    return None, None


def _parse_std_info_times(redo_data: bytes) -> Optional[Dict[str, str]]:
    """
    $STANDARD_INFORMATION begins with four 8-byte FILETIME fields, in this
    exact order: created, modified (last write), mft_modified (last MFT
    change), accessed. If redo_data covers at least those 32 bytes from the
    start of the attribute, decode them into the same TimestampSet shape used
    by ParsedRecord.std_info_times.
    """
    if len(redo_data) < 32:
        return None

    from dfir_ntfs.USN import DecodeFiletime  # shared FILETIME decoder

    created, modified, mft_modified, accessed = struct.unpack("<4Q", redo_data[:32])

    def _fmt(filetime: int) -> Optional[str]:
        decoded = DecodeFiletime(filetime)
        return decoded.strftime("%Y-%m-%dT%H:%M:%SZ") if decoded else None

    return {
        "created": _fmt(created),
        "modified": _fmt(modified),
        "mft_modified": _fmt(mft_modified),
        "accessed": _fmt(accessed),
    }


def parse_logfile(source: Union[str, BinaryIO]) -> List[Dict[str, Any]]:
    """
    Parse a $LogFile stream (path or already-open binary file object) into a
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
        parser = LogFile.LogFileParser(file_object)
        results: List[Dict[str, Any]] = []

        for record in parser.parse_ntfs_records():
            if not isinstance(record, LogFile.NTFSLogRecord):
                continue  # skip NTFSRestartArea and any other client data type

            redo_op_code = record.get_redo_operation()
            operation_name = LogFile.ResolveNTFSOperation(redo_op_code)

            file_reference_number, attribute_type_code = _resolve_target(record)
            file_reference = _format_file_reference(file_reference_number)
            attribute_type = _resolve_attribute_type_name(attribute_type_code)

            std_info_times = None
            timestamp = None

            is_resident_update = operation_name in _RESIDENT_UPDATE_OP_NAMES
            is_std_info = attribute_type_code == _STANDARD_INFORMATION_TYPE_CODE

            if is_resident_update and is_std_info and record.get_redo_offset() == 0:
                redo_data = record.get_redo_data()
                std_info_times = _parse_std_info_times(redo_data)
                if std_info_times:
                    # Rule 5 cares about "what did this operation set the
                    # timestamps to" — use the modified time as the single
                    # representative timestamp for this LogFile event.
                    timestamp = std_info_times["modified"]

            results.append(
                {
                    "lsn": record.lsn,
                    "transaction_id": record.transaction_id,
                    "operation": operation_name,
                    "file_reference": file_reference,
                    "attribute_type": attribute_type,
                    "logfile_operation": operation_name,
                    "timestamp": timestamp,
                    "std_info_times": std_info_times,
                    "raw": {
                        "redo_offset": record.get_redo_offset(),
                        "redo_length": record.get_redo_length(),
                        "undo_operation": LogFile.ResolveNTFSOperation(
                            record.get_undo_operation()
                        ),
                    },
                }
            )

        return results
    finally:
        if opened_here:
            file_object.close()


if __name__ == "__main__":
    # Quick manual smoke test:
    #   python logfile_parser.py path/to/extracted/$LogFile
    import sys
    import json

    if len(sys.argv) != 2:
        print("usage: python logfile_parser.py <path-to-logfile>")
        raise SystemExit(1)

    parsed = parse_logfile(sys.argv[1])
    print(json.dumps(parsed, indent=2))
