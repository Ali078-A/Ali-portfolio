import struct


def minimal_pe(*, dll_characteristics=0x0140, section_characteristics=0x60000020):
    """Build a tiny valid PE32 image in memory for parser tests."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 70, dll_characteristics)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, section_characteristics)
    data[0x200:0x400] = bytes(range(256)) * 2
    return bytes(data)


def pe_with_import():
    data = bytearray(minimal_pe())
    optional = 0x98
    struct.pack_into("<II", data, optional + 96 + 8, 0x1100, 40)
    # Import descriptor at RVA 0x1100.
    struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1128, 0x1150)
    # Null descriptor follows the first one.
    data[0x314:0x328] = b"\0" * 20
    dll_name = b"KERNEL32.dll\0"
    data[0x328 : 0x328 + len(dll_name)] = dll_name
    struct.pack_into("<II", data, 0x340, 0x1160, 0)
    struct.pack_into("<H", data, 0x360, 7)
    data[0x362:0x36E] = b"ExitProcess\0"
    return bytes(data)
