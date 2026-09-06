"""Deterministic access to an APK's raw contents.

Every triage analyzer reads the APK exclusively through :class:`ApkAccessor`.
It provides:
    - a stable, sorted view of the zip (ZIP) entries
    - raw bytes of the file and of any entry
    - lazy, cached androguard parsing when androguard is installed
    - lazy, cached DEX objects

Nothing here executes the APK or contacts the network.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from re_engine.utils.elfutil import elf_symbols


def _silence_androguard() -> None:
    """Stop androguard's loguru DEBUG spam from polluting output."""
    try:
        import loguru

        loguru.logger.disable("androguard")
    except Exception:
        pass


@dataclass
class ZipEntry:
    """Stable, deterministic view of a ZIP entry inside the APK."""

    name: str
    size: int
    compress_size: int
    method: int  # zipfile.ZIP_STORED == 0, ZIP_DEFLATED == 8

    @property
    def compression(self) -> str:
        return "stored" if self.method == zipfile.ZIP_STORED else "deflated"


class ApkAccessor:
    """Lazily-loaded, cached accessor for one APK file."""

    def __init__(self, apk_path) -> None:
        self.apk_path = Path(apk_path)
        self._zip: Optional[zipfile.ZipFile] = None
        self._entries: Optional[List[ZipEntry]] = None
        self._apk: Any = None
        self._dex: Optional[List[Any]] = None
        self._raw: Optional[bytes] = None
        self._entry_cache: Dict[str, Optional[bytes]] = {}

    # ------------------------------------------------------------------
    # ZIP access
    # ------------------------------------------------------------------
    @property
    def zip(self) -> zipfile.ZipFile:
        if self._zip is None:
            self._zip = zipfile.ZipFile(self.apk_path)
        return self._zip

    def entries(self) -> List[ZipEntry]:
        if self._entries is None:
            self._entries = sorted(
                (
                    ZipEntry(
                        info.filename,
                        info.file_size,
                        info.compress_size,
                        info.compress_type,
                    )
                    for info in self.zip.infolist()
                ),
                key=lambda entry: entry.name,
            )
        return self._entries

    def entry_names(self) -> List[str]:
        return [entry.name for entry in self.entries()]

    def read(self, name: str, cap: Optional[int] = None) -> bytes:
        if name not in self._entry_cache:
            try:
                self._entry_cache[name] = self.zip.read(name)
            except (KeyError, zipfile.BadZipFile):
                self._entry_cache[name] = None
        blob = self._entry_cache[name] or b""
        if cap is not None:
            return blob[:cap]
        return blob

    def read_head(self, name: str, size: int = 64) -> bytes:
        return self.read(name)[:size]

    def dex_bytes(self):
        """Yield (name, raw_bytes) for every ``classes*.dex`` entry."""
        for entry in self.entries():
            if not _is_dex_entry(entry.name):
                continue
            raw = self.read(entry.name)
            if _looks_like_dex(raw):
                yield entry.name, raw

    def has(self, name: str) -> bool:
        return name in {entry.name for entry in self.entries()}

    # ------------------------------------------------------------------
    # Raw file access
    # ------------------------------------------------------------------
    @property
    def raw_bytes(self) -> bytes:
        if self._raw is None:
            self._raw = self.apk_path.read_bytes()
        return self._raw

    # ------------------------------------------------------------------
    # androguard access
    # ------------------------------------------------------------------
    @property
    def androguard_apk(self) -> Any:
        """Load the androguard APK object once and cache it.

        Returns None when androguard is not installed.
        """
        if self._apk is not None:
            return self._apk
        try:
            _silence_androguard()
            from androguard.core.apk import APK

            self._apk = APK(str(self.apk_path))
        except Exception:
            self._apk = None
        return self._apk

    @property
    def dex(self) -> List[Any]:
        """Lazily parse all ``classes*.dex`` into androguard DEX objects."""
        if self._dex is not None:
            return self._dex
        self._dex = []
        try:
            _silence_androguard()
            from androguard.core.dex import DEX

            for entry in self.entries():
                if not _is_dex_entry(entry.name):
                    continue
                raw = self.read(entry.name)
                if _looks_like_dex(raw):
                    try:
                        self._dex.append(DEX(raw))
                    except Exception:
                        continue
        except Exception:
            self._dex = []
        return self._dex

    def close(self) -> None:
        if self._zip is not None:
            try:
                self._zip.close()
            finally:
                self._zip = None

    def __enter__(self) -> "ApkAccessor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _is_dex_entry(name: str) -> bool:
    base = name.split("/")[-1]
    return base.startswith("classes") and base.endswith(".dex")


def _looks_like_dex(data: bytes) -> bool:
    return data.startswith(b"dex\n") or data.startswith(b"dex\x0a")


__all__ = ["ApkAccessor", "ZipEntry"]