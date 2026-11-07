from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any


class PEFormatError(ValueError):
    """Raised when a file is not a structurally readable PE image."""


MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

COFF_CHARACTERISTICS = {
    0x0002: "executable_image",
    0x2000: "dll",
    0x0100: "32_bit_machine",
}

SECTION_CHARACTERISTICS = {
    0x00000020: "code",
    0x00000040: "initialized_data",
    0x00000080: "uninitialized_data",
    0x02000000: "discardable",
    0x04000000: "not_cached",
    0x08000000: "not_paged",
    0x10000000: "shared",
    0x20000000: "execute",
    0x40000000: "read",
    0x80000000: "write",
}

MAX_SECTIONS = 96
MAX_IMPORT_DESCRIPTORS = 4096
MAX_TOTAL_IMPORT_THUNKS = 65536


def _require(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise PEFormatError(f"{label} extends beyond the end of the file")


def _u16(data: bytes, offset: int, label: str) -> int:
    _require(data, offset, 2, label)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int, label: str) -> int:
    _require(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0]


def _cstring(data: bytes, offset: int, label: str, max_length: int = 4096) -> str:
    _require(data, offset, 1, label)
    end = data.find(b"\0", offset, min(len(data), offset + max_length + 1))
    if end < 0:
        raise PEFormatError(f"{label} is not null-terminated within {max_length} bytes")
    return data[offset:end].decode("ascii", errors="replace")


def _entropy(data: bytes) -> float | None:
    if not data:
        return None
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return round(
        -sum((count / length) * math.log2(count / length) for count in counts if count),
        3,
    )


def _characteristic_names(value: int, mapping: dict[int, str]) -> list[str]:
    return [name for bit, name in mapping.items() if value & bit]


def analyze_pe(path: str | Path) -> dict[str, Any]:
    """Read and analyze a PE file without loading or executing it."""
    file_path = Path(path)
    data = file_path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEFormatError("missing DOS MZ signature or truncated DOS header")

    pe_offset = _u32(data, 0x3C, "PE header offset")
    _require(data, pe_offset, 24, "PE signature and COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PEFormatError("invalid PE signature")

    coff_offset = pe_offset + 4
    machine = _u16(data, coff_offset, "machine")
    section_count = _u16(data, coff_offset + 2, "section count")
    timestamp = _u32(data, coff_offset + 4, "timestamp")
    optional_size = _u16(data, coff_offset + 16, "optional header size")
    coff_flags = _u16(data, coff_offset + 18, "COFF characteristics")
    if section_count > MAX_SECTIONS:
        raise PEFormatError(f"section count exceeds safety limit ({MAX_SECTIONS})")

    optional_offset = coff_offset + 20
    _require(data, optional_offset, optional_size, "optional header")
    if optional_size < 2:
        raise PEFormatError("optional header is missing")
    magic = _u16(data, optional_offset, "optional header magic")
    if magic == 0x10B:
        bitness = 32
        image_base = _u32(data, optional_offset + 28, "image base")
        directory_count_offset = 92
        directory_offset = 96
        thunk_size = 4
        ordinal_flag = 0x80000000
    elif magic == 0x20B:
        bitness = 64
        _require(data, optional_offset + 24, 8, "image base")
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
        directory_count_offset = 108
        directory_offset = 112
        thunk_size = 8
        ordinal_flag = 0x8000000000000000
    else:
        raise PEFormatError(f"unsupported optional header magic 0x{magic:04x}")

    minimum_optional_size = directory_offset
    if optional_size < minimum_optional_size:
        raise PEFormatError("optional header is truncated")
    entry_point = _u32(data, optional_offset + 16, "entry point")
    section_alignment = _u32(data, optional_offset + 32, "section alignment")
    file_alignment = _u32(data, optional_offset + 36, "file alignment")
    size_of_image = _u32(data, optional_offset + 56, "image size")
    size_of_headers = _u32(data, optional_offset + 60, "header size")
    dll_characteristics = _u16(data, optional_offset + 70, "DLL characteristics")
    directory_count = _u32(data, optional_offset + directory_count_offset, "data directory count")
    available_directory_count = (optional_size - directory_offset) // 8
    if directory_count > available_directory_count:
        raise PEFormatError("data directory count exceeds the optional header size")

    directories: list[tuple[int, int]] = []
    for index in range(directory_count):
        directories.append(struct.unpack_from("<II", data, optional_offset + directory_offset + index * 8))

    section_table_offset = optional_offset + optional_size
    _require(data, section_table_offset, section_count * 40, "section table")
    sections: list[dict[str, Any]] = []
    section_raw: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        characteristics = _u32(data, offset + 36, "section characteristics")
        _require(data, raw_offset, raw_size, f"section {name!r} raw data")
        raw_bytes = data[raw_offset : raw_offset + raw_size]
        flags = _characteristic_names(characteristics, SECTION_CHARACTERISTICS)
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": f"0x{characteristics:08x}",
                "permissions": [name for name in ("read", "write", "execute") if name in flags],
                "flags": flags,
                "entropy": _entropy(raw_bytes),
            }
        )
        section_raw.append((virtual_address, virtual_size, raw_offset, raw_size))

    def rva_to_offset(rva: int, label: str) -> int:
        if rva < size_of_headers and rva < len(data):
            return rva
        for virtual_address, virtual_size, raw_offset, raw_size in section_raw:
            extent = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + extent:
                delta = rva - virtual_address
                if delta >= raw_size:
                    raise PEFormatError(f"{label} points to uninitialized section data")
                file_offset = raw_offset + delta
                _require(data, file_offset, 1, label)
                return file_offset
        raise PEFormatError(f"{label} RVA 0x{rva:x} is not backed by file data")

    imports: list[dict[str, Any]] = []
    total_import_thunks = 0
    if len(directories) > 1:
        import_rva, import_size = directories[1]
        if import_rva and import_size:
            import_offset = rva_to_offset(import_rva, "import directory")
            descriptor_limit = min(import_size // 20, MAX_IMPORT_DESCRIPTORS)
            terminated = False
            for index in range(descriptor_limit):
                descriptor_offset = import_offset + index * 20
                _require(data, descriptor_offset, 20, "import descriptor")
                original_thunk, import_timestamp, forwarder_chain, name_rva, first_thunk = struct.unpack_from(
                    "<IIIII", data, descriptor_offset
                )
                if not any((original_thunk, import_timestamp, forwarder_chain, name_rva, first_thunk)):
                    terminated = True
                    break
                dll_name = _cstring(data, rva_to_offset(name_rva, "import DLL name"), "import DLL name")
                thunk_rva = original_thunk or first_thunk
                symbols: list[dict[str, Any]] = []
                thunk_terminated = False
                for thunk_index in range(MAX_TOTAL_IMPORT_THUNKS - total_import_thunks):
                    total_import_thunks += 1
                    thunk_offset = rva_to_offset(thunk_rva + thunk_index * thunk_size, "import thunk")
                    _require(data, thunk_offset, thunk_size, "import thunk")
                    value = (
                        _u32(data, thunk_offset, "import thunk")
                        if thunk_size == 4
                        else struct.unpack_from("<Q", data, thunk_offset)[0]
                    )
                    if value == 0:
                        thunk_terminated = True
                        break
                    if value & ordinal_flag:
                        symbols.append({"kind": "ordinal", "ordinal": value & 0xFFFF})
                    else:
                        hint_name_offset = rva_to_offset(value, "import hint/name")
                        hint = _u16(data, hint_name_offset, "import hint")
                        symbol_name = _cstring(data, hint_name_offset + 2, "import name")
                        symbols.append({"kind": "name", "hint": hint, "name": symbol_name})
                if not thunk_terminated:
                    raise PEFormatError("import thunk tables exceed safety limit")
                imports.append({"dll": dll_name, "symbols": symbols})
            if not terminated:
                raise PEFormatError("import directory has no terminating descriptor")

    mitigations = {
        "aslr": bool(dll_characteristics & 0x0040),
        "dep": bool(dll_characteristics & 0x0100),
        "cfg": bool(dll_characteristics & 0x4000),
    }
    findings: list[dict[str, str]] = []
    for section in sections:
        permissions = section["permissions"]
        if "write" in permissions and "execute" in permissions:
            findings.append(
                {
                    "severity": "high",
                    "confidence": "high",
                    "title": f"Writable and executable section: {section['name'] or '(unnamed)'}",
                    "evidence": (
                        f"Section characteristics {section['characteristics']} grant both write and execute "
                        f"permissions to {section['name'] or '(unnamed)'}."
                    ),
                }
            )
    mitigation_labels = {
        "aslr": ("ASLR", "DYNAMIC_BASE"),
        "dep": ("DEP", "NX_COMPAT"),
        "cfg": ("CFG", "GUARD_CF"),
    }
    for key, enabled in mitigations.items():
        if not enabled:
            label, flag = mitigation_labels[key]
            findings.append(
                {
                    "severity": "medium",
                    "confidence": "high",
                    "title": f"{label} compatibility flag is not set",
                    "evidence": (
                        f"Optional-header DLL characteristics are 0x{dll_characteristics:04x}; "
                        f"the {flag} bit is clear. This indicates the image does not declare this mitigation."
                    ),
                }
            )

    return {
        "schema_version": 1,
        "file": {
            "path": str(file_path),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "headers": {
            "machine": MACHINE_NAMES.get(machine, f"unknown (0x{machine:04x})"),
            "machine_value": f"0x{machine:04x}",
            "bitness": bitness,
            "timestamp": timestamp,
            "section_count": section_count,
            "entry_point_rva": f"0x{entry_point:x}",
            "image_base": f"0x{image_base:x}",
            "section_alignment": section_alignment,
            "file_alignment": file_alignment,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "characteristics": f"0x{coff_flags:04x}",
            "characteristic_flags": _characteristic_names(coff_flags, COFF_CHARACTERISTICS),
            "dll_characteristics": f"0x{dll_characteristics:04x}",
        },
        "sections": sections,
        "imports": imports,
        "mitigations": mitigations,
        "findings": findings,
        "limitations": [
            "Static metadata only; the input was not executed or loaded.",
            "Findings describe observable file properties and do not establish exploitability or maliciousness.",
            "A cleared mitigation flag may be intentional or platform-dependent.",
        ],
    }
