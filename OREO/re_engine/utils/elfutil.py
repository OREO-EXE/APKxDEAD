"""Minimal, deterministic ELF parsing for native libraries.

Extracts machine architecture and both the defined (exported) and undefined
(imported) entries of the dynamic symbol table from an ELF ``.so`` payload
using only the standard library. No external tooling.
"""

from __future__ import annotations

import struct
from typing import List, Optional

SHT_STRTAB = 3
SHT_DYNSYM = 11
SHN_UNDEF = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_FUNC = 2
STT_OBJECT = 1
STT_TLS = 6
STT_GNU_IFUNC = 10

_ARCH_NAMES = {
    (1, 3): "EM_386 (x86)",
    (2, 62): "EM_X86_64 (x86_64)",
    (1, 40): "EM_ARM",
    (2, 183): "EM_AARCH64",
    (1, 8): "EM_MIPS",
    (2, 8): "EM_MIPS_64",
    (2, 243): "EM_RISCV",
}


def _parse(data: bytes):
    """Parse an ELF payload; return (arch, defined_syms, imported_syms)."""
    if not _is_elf(data):
        return None
    ei_class = data[4]
    endian = ">" if data[5] == 2 else "<"
    is64 = ei_class == 2

    if is64:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(
            endian + "HHH", data, 0x3A
        )
        sym_size = 24
        sh_type_off, sh_offset_off, sh_size_off, sh_link_off = 4, 24, 32, 40
        u64 = True
    else:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(
            endian + "HHH", data, 0x2E
        )
        sym_size = 16
        sh_type_off, sh_offset_off, sh_size_off, sh_link_off = 4, 16, 20, 24
        u64 = False

    if not shentsize or shoff + shentsize * shnum > len(data):
        return None

    sections = {}
    for i in range(shnum):
        base = shoff + i * shentsize
        sh_type = struct.unpack_from(endian + "I", data, base + sh_type_off)[0]
        sh_offset = struct.unpack_from(
            endian + ("Q" if u64 else "I"), data, base + sh_offset_off
        )[0]
        sh_size = struct.unpack_from(
            endian + ("Q" if u64 else "I"), data, base + sh_size_off
        )[0]
        sh_link = struct.unpack_from(endian + "I", data, base + sh_link_off)[0]
        sections[i] = {
            "type": sh_type,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
        }

    dynsym = next(
        (
            (sec["offset"], sec["size"], sec["link"])
            for sec in sections.values()
            if sec["type"] == SHT_DYNSYM
        ),
        None,
    )
    if dynsym is None:
        arch = _ARCH_NAMES.get((ei_class, struct.unpack_from(
            endian + "H", data, 18
        )[0]))
        return arch, [], []

    sym_off, sym_size_total, str_link = dynsym
    str_sec = sections.get(str_link, {})
    string_data = data[
        str_sec.get("offset", 0) : str_sec.get("offset", 0)
        + str_sec.get("size", 0)
    ]

    e_machine = struct.unpack_from(endian + "H", data, 18)[0]
    arch = _ARCH_NAMES.get((ei_class, e_machine))

    defined: List[str] = []
    imported: List[str] = []
    n = sym_size_total // sym_size
    for i in range(n):
        base = sym_off + i * sym_size
        name_off, info, _, shndx = struct.unpack_from(
            endian + "IBBH", data, base
        )[:4]
        bind = info >> 4
        sym_type = info & 0xF
        if bind not in (STB_GLOBAL, STB_WEAK):
            continue
        name = _cstr(string_data, name_off)
        if not name:
            continue
        if shndx == SHN_UNDEF:
            imported.append(name)
        elif sym_type in (STT_FUNC, STT_OBJECT, STT_TLS, STT_GNU_IFUNC):
            defined.append(name)
        if len(defined) + len(imported) >= 4000:
            break

    return arch, sorted(set(defined)), sorted(set(imported))


def elf_architecture(data: bytes) -> Optional[str]:
    if not _is_elf(data):
        return None
    ei_class = data[4]
    endian = ">" if data[5] == 2 else "<"
    e_machine = struct.unpack_from(endian + "H", data, 18)[0]
    return _ARCH_NAMES.get((ei_class, e_machine))


def elf_symbols(data: bytes, limit: int = 2000) -> List[str]:
    """Return sorted exported (global/weak, defined) dynamic symbols."""
    parsed = _parse(data)
    if parsed is None:
        return []
    _, defined, _ = parsed
    return defined[:limit]


def elf_imports(data: bytes, limit: int = 2000) -> List[str]:
    """Return sorted imported (undefined) dynamic symbols."""
    parsed = _parse(data)
    if parsed is None:
        return []
    _, _, imported = parsed
    return imported[:limit]


def elf_info(data: bytes) -> Optional[dict]:
    """Return ``{"architecture", "symbols", "imports"}`` or None."""
    if not _is_elf(data):
        return None
    parsed = _parse(data)
    if parsed is None:
        return None
    arch, defined, imported = parsed
    return {
        "architecture": arch,
        "symbols": defined,
        "imports": imported,
    }


def _is_elf(data: bytes) -> bool:
    return len(data) >= 16 and data.startswith(b"\x7fELF")


def _cstr(data: bytes, offset: int) -> str:
    if offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        return ""
    try:
        return data[offset:end].decode("utf-8", "replace")
    except Exception:
        return ""


__all__ = ["elf_architecture", "elf_symbols", "elf_imports", "elf_info"]