"""Code reconstruction subsystem.

Converts raw DEX bytecode into a normalized, evidence-backed representation:

    - Smali rendering rebuilt directly from DEX instructions (authoritative)
    - Java reconstruction through pluggable offline backends (androguard DAD,
      optional external JADX) marked as best-effort
    - per-method reference extraction (called methods, strings, class and
      field references) and bounded caller analysis
    - class / method / package lookups over one or more DEX files

Nothing here executes APK code or contacts the network.
"""

from re_engine.reconstruct.index import (
    ClassEntry,
    CodeIndex,
    MethodEntry,
    normalize_class_name,
)
from re_engine.reconstruct.java import (
    DADJavaBackend,
    JadxJavaBackend,
    JavaBackend,
    JavaSourceError,
    build_backend,
)
from re_engine.reconstruct.models import (
    ARTIFACT_CLASS,
    ARTIFACT_METHOD,
    LANGUAGE_JAVA,
    LANGUAGE_SMALI,
    CodeArtifact,
    ReconstructionResult,
    artifact_id,
)
from re_engine.reconstruct.reconstructor import CodeReconstructor

__all__ = [
    "ARTIFACT_CLASS",
    "ARTIFACT_METHOD",
    "LANGUAGE_JAVA",
    "LANGUAGE_SMALI",
    "ClassEntry",
    "CodeArtifact",
    "CodeIndex",
    "CodeReconstructor",
    "DADJavaBackend",
    "JadxJavaBackend",
    "JavaBackend",
    "JavaSourceError",
    "MethodEntry",
    "ReconstructionResult",
    "artifact_id",
    "build_backend",
    "normalize_class_name",
]