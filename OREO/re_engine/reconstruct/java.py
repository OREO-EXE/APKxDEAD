"""Best-effort Java reconstruction backends.

Two backends are provided behind a common interface:

    - :class:`DADJavaBackend` - androguard's built-in offline decompiler
      (DAD). It is authoritative-free (a heuristic decompiler) but fully
      offline and always preferred when androguard is importable.
    - :class:`JadxJavaBackend` - an optional external JADX CLI wrapper. It is
      only selected when ``jadx`` is discoverable on PATH.

Java reconstruction is NEVER authoritative evidence. The DEX/Smali view is the
authoritative low-level representation. Backends signal failure by raising
:class:`JavaSourceError`; callers degrade to Smali.
"""

from __future__ import annotations

import shutil
from typing import Dict, List, Optional


class JavaSourceError(Exception):
    """Raised when a Java backend cannot produce source for an input."""


class JavaBackend:
    """Common interface for Java reconstruction backends."""

    name: str = "java"

    def __init__(self) -> None:
        self._available: Optional[bool] = None

    def available(self) -> bool:
        raise NotImplementedError

    def method_source(self, dex_idx: int, method) -> str:
        raise NotImplementedError

    def class_source(self, dex_idx: int, cls) -> str:
        raise NotImplementedError

    def describe(self) -> Dict[str, object]:
        return {"backend": self.name, "available": bool(self.available())}


class DADJavaBackend(JavaBackend):
    """Offline Java reconstruction via androguard's DAD decompiler."""

    name = "androguard-dad"

    def __init__(self, dex_files) -> None:
        super().__init__()
        self._dex_files = list(dex_files or [])
        self._analyses: Dict[int, object] = {}
        self._decompilers: Dict[int, object] = {}
        self._build_error: Optional[str] = None

    def available(self) -> bool:
        if self._available is None:
            self._available = False
            try:
                import androguard  # noqa: F401

                self._available = True
            except Exception:
                self._available = False
        return self._available

    def describe(self) -> Dict[str, object]:
        info = super().describe()
        if self._build_error:
            info["error"] = self._build_error
        return info

    def _ensure(self, dex_idx: int) -> object:
        if dex_idx in self._decompilers:
            return self._decompilers[dex_idx]
        try:
            from androguard.core.analysis.analysis import Analysis
            from androguard.decompiler.decompiler import DecompilerDAD
        except Exception as exc:  # pragma: no cover - androguard missing
            raise JavaSourceError(f"androguard decompiler unavailable: {exc}")

        dex = self._dex_files[dex_idx]
        try:
            analysis = self._analyses.get(dex_idx)
            if analysis is None:
                analysis = Analysis(dex)
                self._analyses[dex_idx] = analysis
            decompiler = DecompilerDAD(dex, analysis)
            self._decompilers[dex_idx] = decompiler
            return decompiler
        except Exception as exc:
            self._build_error = str(exc)[:200]
            raise JavaSourceError(f"DAD analysis failed: {exc}")

    def method_source(self, dex_idx: int, method) -> str:
        decompiler = self._ensure(dex_idx)
        try:
            return decompiler.get_source_method(method)
        except Exception as exc:
            raise JavaSourceError(f"DAD method decompilation failed: {exc}")

    def class_source(self, dex_idx: int, cls) -> str:
        decompiler = self._ensure(dex_idx)
        try:
            return decompiler.get_source_class(cls)
        except Exception as exc:
            raise JavaSourceError(f"DAD class decompilation failed: {exc}")


class JadxJavaBackend(JavaBackend):
    """Optional external JADX CLI backend.

    Only used when a ``jadx`` executable is available on PATH. Because JADX
    decompiles whole APKs rather than single methods, per-method queries are
    not supported; the backend stays unavailable unless byte-exact class dumps
    are requested.
    """

    name = "jadx"

    def __init__(self, jadx_path: Optional[str] = None) -> None:
        super().__init__()
        self._path = jadx_path or shutil.which("jadx")

    def available(self) -> bool:
        if self._available is None:
            self._available = bool(self._path)
        return self._available

    def method_source(self, dex_idx: int, method) -> str:
        raise JavaSourceError(
            "jadx backend does not provide per-method source; use the "
            "androguard-dad backend or render Smali"
        )

    def class_source(self, dex_idx: int, cls) -> str:
        raise JavaSourceError(
            "jadx CLI integration is not configured (jadx not on PATH)"
        )


def build_backend(
    dex_files,
    prefer: str = "dad",
    jadx_path: Optional[str] = None,
) -> Optional[JavaBackend]:
    """Build the preferred available backend (``None`` when none can run)."""
    if prefer == "dad" or prefer in ("auto", "any"):
        backend = DADJavaBackend(dex_files)
        if backend.available():
            return backend
    if prefer in ("jadx", "auto", "any"):
        backend = JadxJavaBackend(jadx_path=jadx_path)
        if backend.available():
            return backend
    return None