"""Deterministic test fixtures for triage analyzers.

Synthetic ZIPs (no androguard), a hand-built ELF payload (no external
tooling), and duck-typed fakes for the androguard APK/DEX surface so every
analyzer is unit-testable without depending on androguard being installed.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path
from types import SimpleNamespace

from re_engine.apk import ApkAccessor, ZipEntry

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def build_zip(
    entries: dict,
    path: Path,
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    """Write ``entries`` (name -> bytes) into a deterministic ZIP at ``path``."""
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, blob in sorted(entries.items()):
            archive.writestr(name, blob)
            archive.comment = b""
    return path


def build_elf(
    machine: int = 62,
    defined_symbols: list | None = None,
    imported_symbols: list | None = None,
) -> bytes:
    """Hand-build an ELF64 little-endian with .dynsym/.dynstr sections."""
    defined_symbols = list(defined_symbols or [])
    imported_symbols = list(imported_symbols or [])

    names = defined_symbols + imported_symbols
    dynstr_raw = b"".join(f"{name}\x00".encode() for name in names)
    offsets = []
    cursor = 0
    for name in names:
        offsets.append(cursor)
        cursor += len(name.encode()) + 1

    sym_entries = b""
    for index, name in enumerate(names):
        shndx = 0 if index >= len(defined_symbols) else 1
        bind = 2 if shndx == 0 else 1  # WEAK import / GLOBAL defined
        st_info = (bind << 4) | 1  # STB_GLOBAL/WEAK | STT_OBJECT
        sym_entries += struct.pack(
            "<IBBHQQ", offsets[index], st_info, 0, shndx, 0, 0
        )

    dynsym_off = 64
    dynstr_off = dynsym_off + len(sym_entries)
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    sh_name_dynsym = shstrtab.index(b".dynsym")
    sh_name_dynstr = shstrtab.index(b".dynstr")
    sh_name_shstrtab = shstrtab.index(b".shstrtab")
    shstr_off = dynstr_off + len(dynstr_raw)
    section_table_offset = shstr_off + len(shstrtab)

    def shdr(name_off, sh_type, offset, size, link, entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off,
            sh_type,
            0,
            0,
            offset,
            size,
            link,
            0,
            1,
            entsize,
        )

    null_shdr = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    dynsym_shdr = shdr(sh_name_dynsym, 11, dynsym_off, len(sym_entries), 2, 24)
    dynstr_shdr = shdr(sh_name_dynstr, 3, dynstr_off, len(dynstr_raw), 0, 1)
    shstr_shdr = shdr(sh_name_shstrtab, 3, shstr_off, len(shstrtab), 0, 1)

    blob = bytearray(64)  # ELF64 header
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # EI_CLASS 64
    blob[5] = 1  # little endian
    blob[6] = 1  # EV_CURRENT
    struct.pack_into("<HHI", blob, 16, 2, machine, 1)  # ET_DYN, e_machine
    struct.pack_into("<Q", blob, 0x28, section_table_offset)  # e_shoff
    struct.pack_into("<HHH", blob, 0x3A, 64, 4, 3)  # shentsize, shnum, shstrndx

    return (
        bytes(blob)
        + sym_entries
        + dynstr_raw
        + shstrtab
        + null_shdr
        + dynsym_shdr
        + dynstr_shdr
        + shstr_shdr
    )


class FakeDex:
    """Duck-typed androguard DEX object holding FakeDexClass instances."""

    def __init__(self, classes):
        self._classes = list(classes)

    def get_classes(self):
        return list(self._classes)


class FakeDexClass:
    def __init__(self, name, superclass, interfaces, fields, methods):
        self._name = name
        self._super = superclass
        self._iface = interfaces
        self._fields = [FakeField(*f) for f in fields]
        self._methods = [FakeMethod(*m) for m in methods]

    def get_name(self):
        return self._name

    def get_superclassname(self):
        return self._super

    def get_interfaces(self):
        return list(self._iface)

    def get_fields(self):
        return self._fields

    def get_methods(self):
        return self._methods


class FakeField:
    def __init__(self, name, descriptor):
        self._name = name
        self._desc = descriptor

    def get_name(self):
        return self._name

    def get_descriptor(self):
        return self._desc


class FakeMethod:
    def __init__(self, name, descriptor, access="", instructions=(), registers=2):
        self._name = name
        self._desc = descriptor
        self._access = access
        self._instructions = list(instructions)
        self._registers = registers

    def get_name(self):
        return self._name

    def get_descriptor(self):
        return self._desc

    def get_access_flags_string(self):
        return self._access

    def get_code(self):
        return FakeCode(self._instructions, self._registers)


class FakeCode:
    def __init__(self, instructions, registers=2):
        from re_engine.analyzers import dex_analyzer

        self._registers = registers
        self._bc = SimpleNamespace(get_instructions=lambda: list(instructions))

    def get_bc(self):
        return self._bc

    def get_registers_size(self):
        return self._registers


class FakeInstruction:
    def __init__(self, name, output, string=None):
        self._name = name
        self._output = output
        self._string = string

    def get_name(self):
        return self._name

    def get_output(self):
        return self._output

    def get_string(self):
        if self._string is None:
            raise AttributeError("no string constant for this instruction")
        return self._string

    def __str__(self):
        text = f"{self._name} {self._output}".rstrip()
        return text


def fake_manifest_xml(text: str):
    import xml.etree.ElementTree as ET

    return ET.fromstring(text)


class FakeCertificate:
    def __init__(
        self,
        subject="CN=Test Org",
        issuer="CN=Test Org",
        sha256="a" * 64,
        sha1="b" * 40,
        serial="12345",
        not_before=None,
        not_after=None,
        algorithm="sha256WithRSAEncryption",
    ):
        from datetime import datetime

        if not_before is None:
            not_before = datetime(2020, 1, 1)
        if not_after is None:
            not_after = datetime(2030, 1, 1)
        self.subject = SimpleNamespace(human_friendly=subject)
        self.issuer = SimpleNamespace(human_friendly=issuer)
        self.sha256 = sha256
        self.sha1 = sha1
        self.serial_number = serial
        self.not_valid_before = not_before
        self.not_valid_after = not_after
        self.hash_algo = "sha256"
        self.signature_algo = algorithm


class FakeApk:
    """Duck-typed stand-in for androguard.core.apk.APK."""

    def __init__(
        self,
        package="com.example.triage",
        app_name="TriageApp",
        version_name="1.0.0",
        version_code="1",
        min_sdk="23",
        target_sdk="30",
        activities=None,
        services=None,
        receivers=None,
        providers=None,
        main_activity="com.example.triage.MainActivity",
        permissions=None,
        certificates=None,
        manifest_xml=None,
        schemes=None,
    ):
        self._package = package
        self._app_name = app_name
        self._version_name = version_name
        self._version_code = version_code
        self._min_sdk = min_sdk
        self._target_sdk = target_sdk
        self._activities = activities or []
        self._services = services or []
        self._receivers = receivers or []
        self._providers = providers or []
        self._main = main_activity
        self._permissions = permissions or []
        self._certificates = certificates or []
        self._manifest = manifest_xml
        self._schemes = schemes or ["v1", "v2"]

    def get_package(self):
        return self._package

    def get_app_name(self):
        return self._app_name

    def get_androidversion_name(self):
        return self._version_name

    def get_androidversion_code(self):
        return self._version_code

    def get_min_sdk_version(self):
        return self._min_sdk

    def get_target_sdk_version(self):
        return self._target_sdk

    def get_activities(self):
        return self._activities

    def get_services(self):
        return self._services

    def get_receivers(self):
        return self._receivers

    def get_providers(self):
        return self._providers

    def get_main_activity(self):
        return self._main

    def get_permissions(self):
        return self._permissions

    def get_certificates(self):
        return self._certificates

    def get_android_manifest_xml(self):
        return self._manifest

    def is_signed_v1(self):
        return "v1" in self._schemes

    def is_signed_v2(self):
        return "v2" in self._schemes

    def is_signed_v3(self):
        return "v3" in self._schemes

    def is_signed_v31(self):
        return "v31" in self._schemes


def real_accessor(zip_path: Path) -> ApkAccessor:
    """A real ApkAccessor over the synthetic ZIP."""
    return ApkAccessor(zip_path)


def inject_fakes(
    accessor: ApkAccessor,
    fake_apk=None,
    fake_dex=None,
) -> ApkAccessor:
    """Replace androguard-backed surfaces with fakes for unit tests."""
    if fake_apk is not None:
        accessor._apk = fake_apk
    if fake_dex is not None:
        accessor._dex = fake_dex
    return accessor


def entry_for(accessor: ApkAccessor, name: str) -> ZipEntry:
    return next(e for e in accessor.entries() if e.name == name)