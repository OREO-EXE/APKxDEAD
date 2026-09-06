"""Reconstruction orchestrator.

:class:`CodeReconstructor` ties the code index, the Smali renderer and the
Java backends together for one APK. It produces a bounded, deterministic set
of :class:`CodeArtifact` records for:

    - methods anchored by existing findings (``class_name`` + ``method_name``)
    - methods of manifest-declared executable components
    - a deterministic fallback sample when the above resolve to nothing

Every artifact records the references that were directly observed in its own
bytecode (``evidence_refs``) and keeps the reconstruction honest: Java views
are marked as best-effort, Smali stays authoritative.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from re_engine.models.context import AnalysisContext
from re_engine.reconstruct.index import (
    ClassEntry,
    CodeIndex,
    MethodEntry,
)
from re_engine.reconstruct.java import build_backend
from re_engine.reconstruct.models import (
    ARTIFACT_CLASS,
    ARTIFACT_METHOD,
    DEFAULT_CALLER_SCAN_CAP,
    DEFAULT_CLASS_ARTIFACTS,
    DEFAULT_COMPONENT_CLASS_CAP,
    DEFAULT_COMPONENT_METHODS_PER_CLASS,
    DEFAULT_FALLBACK_METHOD_CAP,
    DEFAULT_FINDING_TARGET_CAP,
    DEFAULT_JAVA_CLASSES,
    DEFAULT_JAVA_METHODS,
    DEFAULT_METHOD_ARTIFACTS,
    DEFAULT_REF_CAP,
    DEFAULT_SOURCE_CAP,
    LANGUAGE_JAVA,
    LANGUAGE_SMALI,
    CodeArtifact,
    ReconstructionResult,
    artifact_id,
)

_TRUNC_MARK = "\n... [truncated]"


class CodeReconstructor:
    """Produces bounded CodeArtifact reconstructions for one APK."""

    def __init__(
        self,
        context: Optional[AnalysisContext] = None,
        dex_files=None,
        options: Optional[Dict[str, object]] = None,
    ) -> None:
        self.context = context
        self.options = {**self._default_options(), **(options or {})}

        if dex_files is None and context is not None:
            artifacts = getattr(context, "artifacts", None)
            dex_files = getattr(artifacts, "dex", None) or []
        self.index = CodeIndex(
            dex_files,
            caller_scan_cap=int(self.options.get("caller_scan_cap")),
        )
        self._backend = None

    @staticmethod
    def _default_options() -> Dict[str, object]:
        """Standard bounded-reconstruction options (keys may be overridden)."""
        return {
            "method_artifacts": DEFAULT_METHOD_ARTIFACTS,
            "class_artifacts": DEFAULT_CLASS_ARTIFACTS,
            "java_methods": DEFAULT_JAVA_METHODS,
            "java_classes": DEFAULT_JAVA_CLASSES,
            "source_cap": DEFAULT_SOURCE_CAP,
            "ref_cap": DEFAULT_REF_CAP,
            "caller_scan_cap": DEFAULT_CALLER_SCAN_CAP,
            "finding_target_cap": DEFAULT_FINDING_TARGET_CAP,
            "component_class_cap": DEFAULT_COMPONENT_CLASS_CAP,
            "component_methods_per_class": DEFAULT_COMPONENT_METHODS_PER_CLASS,
            "fallback_method_cap": DEFAULT_FALLBACK_METHOD_CAP,
            "build_java": False,
        }

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def run(self, targets: Optional[List[str]] = None) -> ReconstructionResult:
        """Run reconstruction and return a bounded, deterministic result."""
        result = ReconstructionResult()
        self.index._ensure_index()
        result.stats.update(self.index.stats)

        if targets:
            method_targets = self._resolve_targets(targets, result)
            class_targets, _ = self._component_classes(result, cap=None)
        else:
            method_targets = self._default_method_targets(result)
            class_targets, _ = self._component_classes(result, cap=None)

        method_targets = self._dedupe_methods(method_targets)
        class_descriptors = self._dedupe_classes(
            [entry.class_descriptor for entry in method_targets]
            + [entry.descriptor for entry in class_targets]
        )

        method_cap = int(self.options["method_artifacts"])
        class_cap = int(self.options["class_artifacts"])
        java_method_cap = int(self.options["java_methods"])
        java_class_cap = int(self.options["java_classes"])

        smali_count = 0
        java_count = 0

        for entry in method_targets[:method_cap]:
            artifact = self._method_smali_artifact(entry, result)
            if artifact is None:
                continue
            result.artifacts.append(artifact)
            smali_count += 1
            reaching = self._reaching_components(entry)
            if reaching:
                result.reaching_components[entry.mid] = sorted(reaching)

        if self._java_enabled():
            java_method_entries = [
                e for e in method_targets[:method_cap] if e.mid
            ][:java_method_cap]
            for entry in java_method_entries:
                artifact = self._method_java_artifact(entry, result)
                if artifact is None:
                    continue
                result.artifacts.append(artifact)
                java_count += 1

        for descriptor in class_descriptors[:class_cap]:
            class_entry = self.index.find_class(descriptor)
            if class_entry is None:
                continue
            component_meta = self._component_metadata(class_entry)
            artifact = self._class_smali_artifact(
                class_entry, result, component_meta
            )
            if artifact is None:
                continue
            result.artifacts.append(artifact)
            smali_count += 1

        if self._java_enabled():
            java_class_entries = [
                self.index.find_class(d)
                for d in class_descriptors[:class_cap]
                if self.index.find_class(d) is not None
            ][:java_class_cap]
            for class_entry in java_class_entries:
                artifact = self._class_java_artifact(class_entry, result)
                if artifact is None:
                    continue
                result.artifacts.append(artifact)
                java_count += 1

        result.stats["artifacts_total"] = len(result.artifacts)
        result.stats["smali_artifacts"] = smali_count
        result.stats["java_artifacts"] = java_count
        backend = self._backend_describe()
        itemized = " and ".join(
            part for part in [f"smali={smali_count}", f"java={java_count}"] if part
        )
        classes = result.stats.get("classes_indexed", 0)
        dex_count = result.stats.get("dex_count", 0)
        if smali_count + java_count == 0:
            result.summary = (
                f"no code reconstructed from {classes} classes across "
                f"{dex_count} dex file(s)"
            )
        else:
            result.summary = (
                f"reconstructed {itemized} from {classes} classes across "
                f"{dex_count} dex file(s)"
            )
        result.backend = backend.get("backend") if backend else None
        return result

    def reconstruct_method(self, mid: str) -> Optional[CodeArtifact]:
        """Reconstruct a single method as an authoritative Smali artifact."""
        result = ReconstructionResult()
        entry = self.index.get_method(mid)
        if entry is None:
            result.errors.append(f"method not found: {mid}")
            return None
        return self._method_smali_artifact(entry, result)

    def caller_analysis(
        self, mid: str, cap: Optional[int] = None
    ) -> Dict[str, List[str]]:
        return self.index.caller_analysis(mid, cap=cap)

    # ------------------------------------------------------------------
    # Targeting
    # ------------------------------------------------------------------
    def _default_method_targets(self, result: ReconstructionResult) -> List[MethodEntry]:
        entries: List[MethodEntry] = []
        seen: set = set()

        for finding in self._context_findings():
            class_name = getattr(finding, "class_name", None)
            method_name = getattr(finding, "method_name", None)
            if not class_name or not method_name:
                continue
            entry = self.index.find_method(class_name, method_name)
            if entry is not None and entry.mid not in seen:
                seen.add(entry.mid)
                entries.append(entry)
            if len(entries) >= int(self.options["finding_target_cap"]):
                break

        component_classes, _ = self._component_classes(result, cap=None)
        per_class = int(self.options["component_methods_per_class"])
        for class_entry in component_classes:
            for method in class_entry.methods():
                if method.mid and method.mid not in seen:
                    seen.add(method.mid)
                    entries.append(method)
                if len(entries) >= int(self.options["finding_target_cap"]) + (
                    int(self.options["component_class_cap"]) * per_class
                ):
                    break

        if not entries:
            fallback_cap = int(self.options["fallback_method_cap"])
            for class_entry in self._fallback_classes():
                for method in class_entry.methods():
                    if method.mid and method.mid not in seen:
                        seen.add(method.mid)
                        entries.append(method)
                    if len(entries) >= fallback_cap:
                        break
                if len(entries) >= fallback_cap:
                    break

        return self._dedupe_methods(entries)

    def _resolve_targets(
        self, targets: List[str], result: ReconstructionResult
    ) -> List[MethodEntry]:
        entries: List[MethodEntry] = []
        seen: set = set()
        for target in targets:
            entry = self.index.get_method(target)
            if entry is None:
                result.errors.append(f"unresolved target: {target}")
                continue
            if entry.mid not in seen:
                seen.add(entry.mid)
                entries.append(entry)
        self._dedupe_methods(entries)
        return entries

    def _fallback_classes(self) -> List[ClassEntry]:
        entries = []
        for descriptor in sorted(
            self.index.descriptors_matching(""), key=str.lower
        ):
            entry = self.index.find_class(descriptor)
            if entry is not None:
                entries.append(entry)
        return entries

    def _component_classes(
        self, result: ReconstructionResult, cap: Optional[int] = None
    ):
        component_classes: List[ClassEntry] = []
        seen: set = set()
        for component in self._context_components():
            name = getattr(component, "name", None)
            if not name:
                continue
            entry = self.index.find_class(name)
            if entry is None:
                continue
            if entry.descriptor not in seen:
                seen.add(entry.descriptor)
                component_classes.append(entry)
            if cap is not None and len(component_classes) >= cap:
                break
        return component_classes, seen

    def _component_metadata(self, class_entry: ClassEntry) -> Optional[Dict[str, str]]:
        for component in self._context_components():
            name = getattr(component, "name", None)
            if not name:
                continue
            entry = self.index.find_class(name)
            if entry is None:
                continue
            if entry.descriptor == class_entry.descriptor:
                return {
                    "name": str(name),
                    "kind": getattr(component, "kind", None) or "component",
                }
        return None

    def _reaching_components(self, method_entry: MethodEntry) -> List[str]:
        reached = []
        refs = method_entry.references().get("classes", [])
        own_descriptor = method_entry.class_descriptor
        for component in self._context_components():
            name = getattr(component, "name", None)
            if not name:
                continue
            entry = self.index.find_class(name)
            if entry is None:
                continue
            if entry.descriptor == own_descriptor:
                reached.append(str(name))
                continue
            if entry.descriptor in refs:
                reached.append(str(name))
        return reached

    # ------------------------------------------------------------------
    # Artifact builders
    # ------------------------------------------------------------------
    def _method_smali_artifact(
        self, entry: MethodEntry, result: ReconstructionResult
    ) -> Optional[CodeArtifact]:
        try:
            source = entry.smali()
            rendered = self._truncate(source, int(self.options["source_cap"]))
        except Exception as exc:
            result.errors.append(f"smali render failed for {entry.mid}: {exc}")
            return None
        refs = entry.references(ref_cap=int(self.options["ref_cap"]))
        evidence_refs = self._evidence_refs(refs)
        package = self._package_of(entry.class_dotted)
        metadata: Dict[str, object] = {
            "access_flags": entry.access_flags,
            "descriptor": entry.signature,
            "package": package,
            "dex": entry.class_entry.dex_label,
            "instruction_count": entry.instruction_count,
            "api_usage": list(refs["calls"]),
        }
        registers = self._registers(entry)
        if registers is not None:
            metadata["registers"] = registers
        return CodeArtifact(
            artifact_id=artifact_id(
                ARTIFACT_METHOD,
                entry.class_descriptor,
                entry.name,
                entry.signature,
                LANGUAGE_SMALI,
                rendered,
            ),
            type=ARTIFACT_METHOD,
            class_name=entry.class_dotted,
            method_name=entry.name,
            signature=entry.signature,
            source=rendered,
            language=LANGUAGE_SMALI,
            source_location=(
                f"{entry.class_entry.dex_label}:{entry.class_descriptor}->"
                f"{entry.name}{entry.signature}"
            ),
            evidence_refs=evidence_refs,
            provenance={"backend": "dex-instructions", "authoritative": True},
            metadata=metadata,
        )

    def _method_java_artifact(
        self, entry: MethodEntry, result: ReconstructionResult
    ) -> Optional[CodeArtifact]:
        backend = self._get_backend(result)
        if backend is None:
            return None
        try:
            source = backend.method_source(entry.class_entry._dex_idx, entry.method)
            rendered = self._truncate(source, int(self.options["source_cap"]))
        except Exception as exc:
            result.errors.append(f"java decompile failed for {entry.mid}: {exc}")
            return None
        if not rendered:
            result.errors.append(f"java decompile empty for {entry.mid}")
            return None
        return CodeArtifact(
            artifact_id=artifact_id(
                ARTIFACT_METHOD,
                entry.class_descriptor,
                entry.name,
                entry.signature,
                LANGUAGE_JAVA,
                rendered,
            ),
            type=ARTIFACT_METHOD,
            class_name=entry.class_dotted,
            method_name=entry.name,
            signature=entry.signature,
            source=rendered,
            language=LANGUAGE_JAVA,
            source_location=(
                f"{entry.class_entry.dex_label}:{entry.class_descriptor}->"
                f"{entry.name}{entry.signature}"
            ),
            evidence_refs=self._evidence_refs(
                entry.references(ref_cap=int(self.options["ref_cap"]))
            ),
            provenance={"backend": backend.name, "authoritative": False},
            metadata={"descriptor": entry.signature},
        )

    def _class_smali_artifact(
        self,
        class_entry: ClassEntry,
        result: ReconstructionResult,
        component_meta: Optional[Dict[str, str]] = None,
    ) -> Optional[CodeArtifact]:
        try:
            source = self._class_smali(class_entry)
            rendered = self._truncate(source, int(self.options["source_cap"]))
        except Exception as exc:
            result.errors.append(f"class smali render failed: {exc}")
            return None
        metadata: Dict[str, object] = {
            "package": self._package_of(class_entry.dotted),
            "superclass": class_entry.superclass(),
            "interfaces": class_entry.interfaces(),
            "fields": class_entry.fields(),
            "descriptor": class_entry.descriptor,
            "dex": class_entry.dex_label,
        }
        evidence_refs: List[Dict[str, str]] = []
        for iface in class_entry.interfaces():
            if str(iface).startswith("L"):
                evidence_refs.append({"kind": "interface", "ref": str(iface)})
        if component_meta:
            metadata["component"] = component_meta
            evidence_refs.append(
                {
                    "kind": "component",
                    "ref": f"{component_meta['kind']}:{component_meta['name']}",
                }
            )
        return CodeArtifact(
            artifact_id=artifact_id(
                ARTIFACT_CLASS,
                class_entry.descriptor,
                None,
                class_entry.descriptor,
                LANGUAGE_SMALI,
                rendered,
            ),
            type=ARTIFACT_CLASS,
            class_name=class_entry.dotted,
            method_name=None,
            signature=class_entry.descriptor,
            source=rendered,
            language=LANGUAGE_SMALI,
            source_location=f"{class_entry.dex_label}:{class_entry.descriptor}",
            evidence_refs=evidence_refs,
            provenance={"backend": "dex-class", "authoritative": True},
            metadata=metadata,
        )

    def _class_java_artifact(
        self, class_entry: ClassEntry, result: ReconstructionResult
    ) -> Optional[CodeArtifact]:
        backend = self._get_backend(result)
        if backend is None:
            return None
        try:
            source = backend.class_source(class_entry._dex_idx, class_entry.cls)
            rendered = self._truncate(source, int(self.options["source_cap"]))
        except Exception as exc:
            result.errors.append(
                f"java class decompile failed for {class_entry.descriptor}: {exc}"
            )
            return None
        if not rendered:
            result.errors.append(f"java class decompile empty for {class_entry.descriptor}")
            return None
        return CodeArtifact(
            artifact_id=artifact_id(
                ARTIFACT_CLASS,
                class_entry.descriptor,
                None,
                class_entry.descriptor,
                LANGUAGE_JAVA,
                rendered,
            ),
            type=ARTIFACT_CLASS,
            class_name=class_entry.dotted,
            method_name=None,
            signature=class_entry.descriptor,
            source=rendered,
            language=LANGUAGE_JAVA,
            source_location=f"{class_entry.dex_label}:{class_entry.descriptor}",
            evidence_refs=[],
            provenance={"backend": backend.name, "authoritative": False},
            metadata={"descriptor": class_entry.descriptor},
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _class_smali(self, class_entry: ClassEntry) -> str:
        from re_engine.reconstruct.smali import render_class_smali

        return render_class_smali(class_entry.cls)

    def _truncate(self, source: str, cap: int) -> str:
        if source is None:
            return ""
        if len(source) <= cap:
            return source
        return source[:cap] + _TRUNC_MARK

    def _evidence_refs(self, refs: Dict[str, List[str]]) -> List[Dict[str, str]]:
        evidence: List[Dict[str, str]] = []
        for kind in ("calls", "strings", "classes", "fields"):
            for ref in refs.get(kind, []):
                evidence.append({"kind": kind, "ref": ref})
        evidence.sort(key=lambda item: (item["kind"], item["ref"]))
        return evidence[: int(self.options["ref_cap"]) * 4]

    def _dedupe_methods(self, entries: List[MethodEntry]) -> List[MethodEntry]:
        seen: set = set()
        deduped = []
        for entry in entries:
            if not entry.mid:
                continue
            if entry.mid in seen:
                continue
            seen.add(entry.mid)
            deduped.append(entry)
        deduped.sort(
            key=lambda e: (
                e.class_dotted.lower(),
                e.name.lower(),
                e.signature,
            )
        )
        return deduped

    def _dedupe_classes(self, descriptors: List[str]) -> List[str]:
        return sorted(set(d for d in descriptors if d), key=str.lower)

    def _registers(self, entry: MethodEntry) -> Optional[int]:
        try:
            code = getattr(entry.method, "get_code", lambda: None)()
            if code is None:
                return None
            return code.get_registers_size()
        except Exception:
            return None

    def _java_enabled(self) -> bool:
        return bool(self.options.get("build_java"))

    def _get_backend(self, result: ReconstructionResult):
        if self._backend is None and self._java_enabled():
            self._backend = build_backend(self.index._dex_files)
            if self._backend is None:
                result.errors.append("java reconstruction requested but no backend available")
        return self._backend

    def _backend_describe(self) -> Optional[Dict[str, object]]:
        if self._backend is None:
            return None
        return self._backend.describe()

    def _context_findings(self) -> List[object]:
        if self.context is None:
            return []
        return list(getattr(self.context, "findings", []) or [])

    def _context_components(self) -> List[object]:
        if self.context is None:
            return []
        return list(getattr(self.context, "components", []) or [])

    @staticmethod
    def _package_of(dotted: str) -> str:
        parts = dotted.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:2])
        return dotted