"""Manifest triage analyzer.

Reuses the repository's ``ManifestExtractor`` for basic component lists and
adds a deterministic detail pass over the decoded manifest XML: exported
status, intent filters, process names, foreground services, boot receivers,
accessibility and device-admin components, and application-level flags.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from re_engine.analyzers.base import BaseAnalyzer
from re_engine.models.context import AnalysisContext, Component
from re_engine.models.finding import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    Severity,
)

try:
    from ai.feature_extraction.manifest_extractor import ManifestExtractor
except Exception:  # pragma: no cover - repo layout unchanged
    ManifestExtractor = None  # type: ignore[assignment]

_BOOT = "android.intent.action.BOOT_COMPLETED"
_ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService"
_DEVICE_ADMIN_ACTION = "android.app.action.DEVICE_ADMIN_ENABLED"
_BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"


class ManifestAnalyzer(BaseAnalyzer):
    """Extract and triage manifest-declared components and flags."""

    name = "manifest"
    version = "0.1.0"
    description = "Manifest components, exported status, intent filters, flags"

    def run(self, context: AnalysisContext) -> None:
        accessor = context.artifacts
        apk = accessor.androguard_apk if accessor else None
        manifest = _get_manifest_xml(apk)

        declared = self._declared_component_names(apk)
        elements = {
            "activity": _collect(manifest, "activity") + _collect(manifest, "activity-alias"),
            "service": _collect(manifest, "service"),
            "receiver": _collect(manifest, "receiver"),
            "provider": _collect(manifest, "provider"),
        }

        # Qualify: prefer XML detail; else the apk.get_* list.
        qualified: List[Tuple[str, str]] = []
        seen = set()
        for kind in ("activity", "service", "receiver", "provider"):
            for elem in elements[kind]:
                name = _attr(elem, "name")
                if not name:
                    name = _default_package(context) + "." + _class_base(elem, kind)
                key = (kind, name)
                if key in seen:
                    continue
                seen.add(key)
                qualified.append((name, kind))
            for name in declared.get(kind, []):
                key = (kind, name)
                if key not in seen:
                    seen.add(key)
                    qualified.append((name, kind))

        context.components = []
        target_sdk = _to_int(context.target_sdk)
        for name, kind in qualified:
            elem = next(
                (e for e in elements[kind] if _attr(e, "name") == name), None
            )
            context.components.append(
                Component(
                    name=name,
                    kind=kind,
                    exported=_effective_exported(elem, target_sdk),
                    intent_filters=_intent_filter_actions(elem),
                    process=_attr(elem, "process"),
                )
            )
            if context.components[-1].exported:
                context.exported_components.append(name)

        context.intent_filters = {
            name: c.intent_filters
            for c in context.components
            if c.intent_filters
        }
        context.main_activity = (
            self._main_activity(apk, elements) or declared_launcher(elements)
        )

        self._flag_components(context, elements)

        # Privileged / security-relevant components
        self._triage_special_components(context, elements)

        self._capture_permissions(context, manifest)
        self._capture_application_flags(context, manifest, elements)

        self.emit(
            context,
            Finding(
                category=FindingCategory.MANIFEST,
                title="Manifest parsed",
                description=(
                    f"components={len(context.components)} "
                    f"exported={len(context.exported_components)} "
                    f"main_activity={context.main_activity or 'N/A'}"
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence_type=EvidenceType.MANIFEST,
                source_file="AndroidManifest.xml",
            ),
        )

    # ------------------------------------------------------------------
    def _declared_component_names(self, apk) -> Dict[str, List[str]]:
        if apk is None:
            return {}
        try:
            return {
                "activity": list(apk.get_activities()),
                "service": list(apk.get_services()),
                "receiver": list(apk.get_receivers()),
                "provider": list(apk.get_providers()),
            }
        except Exception:
            return {}

    def _main_activity(self, apk, elements) -> Optional[str]:
        if apk is not None:
            try:
                return apk.get_main_activity()
            except Exception:
                pass
        actions = _intent_filter_actions(elements["activity"][0]) \
            if elements["activity"] else []
        return None

    def _flag_components(
        self, context: AnalysisContext, elements: Dict[str, list]
    ) -> None:
        for component in context.components:
            if not component.exported:
                continue
            self.emit(
                context,
                Finding(
                    category=FindingCategory.COMPONENT,
                    title="Exported component",
                    description=(
                        f"Component '{component.name}' is exported"
                        f"{' with intent filters: ' + ', '.join(component.intent_filters) if component.intent_filters else ' (no intent filter)'}."
                    ),
                    severity=(
                        Severity.MEDIUM
                        if component.kind != "activity"
                        else Severity.LOW
                    ),
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.MANIFEST,
                    source_file="AndroidManifest.xml",
                    class_name=component.name,
                    metadata={"kind": component.kind,
                               "exported_inferred": self._was_inferred(
                                   elements, component
                               )},
                ),
            )

    def _was_inferred(self, elements, component) -> bool:
        elem = _find_element(elements[component.kind], component.name)
        return elem is None or _attr(elem, "exported") is None

    def _triage_special_components(
        self, context: AnalysisContext, elements: Dict[str, list]
    ) -> None:
        boot = []
        foreground = []
        accessibility = []
        device_admin = []

        for kind, elem, name in _all_elements_with(elements):
            if kind == "receiver":
                if _BOOT in _intent_filter_actions(elem):
                    boot.append(name)
                if _DEVICE_ADMIN_ACTION in _intent_filter_actions(elem):
                    device_admin.append(name)
            if kind == "service":
                if _attr(elem, "foregroundServiceType"):
                    foreground.append(name)
                if (
                    _ACCESSIBILITY_ACTION in _intent_filter_actions(elem)
                    or _accessibility_permission(elem)
                    or "AccessibilityService" in (name or "")
                ):
                    accessibility.append(name)

        context.boot_receivers = boot
        context.foreground_services = foreground
        context.accessibility_components = accessibility
        context.device_admin_components = device_admin

        for receiver in boot:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.COMPONENT,
                    title="Boot receiver present",
                    description=f"Receiver '{receiver}' listens for BOOT_COMPLETED.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.MANIFEST,
                    source_file="AndroidManifest.xml",
                    class_name=receiver,
                    supporting_string=_observed_string(
                        context, "android.intent.action.BOOT_COMPLETED"
                    ),
                    metadata={"action": _BOOT},
                ),
            )
        for service in accessibility:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.COMPONENT,
                    title="Accessibility service present",
                    description=(
                        f"Service '{service}' declares accessibility-service "
                        "capabilities."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.MANIFEST,
                    source_file="AndroidManifest.xml",
                    class_name=service,
                    metadata={"action": _ACCESSIBILITY_ACTION},
                ),
            )
        for receiver in device_admin:
            self.emit(
                context,
                Finding(
                    category=FindingCategory.COMPONENT,
                    title="Device-admin receiver present",
                    description=(
                        f"Receiver '{receiver}' can become a device owner/admin."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.MANIFEST,
                    source_file="AndroidManifest.xml",
                    class_name=receiver,
                    metadata={"action": _DEVICE_ADMIN_ACTION},
                ),
            )

    def _capture_permissions(
        self, context: AnalysisContext, manifest
    ) -> None:
        if not context.permissions and manifest is not None:
            context.permissions = sorted(
                _uses_permissions(manifest) | _declared_permissions(manifest)
            )

    def _capture_application_flags(
        self, context: AnalysisContext, manifest, elements
    ) -> None:
        app = _first_tag(manifest, "application")
        flags = {
            "debuggable": _attr(app, "debuggable"),
            "allowBackup": _attr(app, "allowBackup"),
            "usesCleartextTraffic": _attr(app, "usesCleartextTraffic"),
            "networkSecurityConfig": _attr(app, "networkSecurityConfig"),
            "requestLegacyExternalStorage": _attr(
                app, "requestLegacyExternalStorage"
            ),
            "extractNativeLibs": _attr(app, "extractNativeLibs"),
        }
        context.application_flags = {
            k: v for k, v in flags.items() if v is not None
        }
        if flags["debuggable"] not in (None, "false"):
            self.emit(
                context,
                Finding(
                    category=FindingCategory.MANIFEST,
                    title="Debuggable application",
                    description="android:debuggable is set to true.",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_type=EvidenceType.MANIFEST,
                    source_file="AndroidManifest.xml",
                ),
            )


# ----------------------------------------------------------------------
# XML helpers (namespace-agnostic; work on lxml and stdlib ET elements)
# ----------------------------------------------------------------------

def _attr(elem, name: str) -> Optional[str]:
    if elem is None:
        return None
    value = elem.get(f"{{http://schemas.android.com/apk/res/android}}{name}")
    if value is None:
        value = elem.get(f"android:{name}")
    return value


def _local(tag) -> str:
    return tag.split("}")[-1]


def _collect(manifest, wanted: str):
    if manifest is None:
        return []
    return [child for child in manifest.iter() if _local(child.tag) == wanted]


def _find_element(elements, name: str):
    for elem in elements:
        if _attr(elem, "name") == name:
            return elem
    return None


def _all_elements_with(elements: Dict[str, list]):
    for kind, items in elements.items():
        for elem in items:
            yield kind, elem, _attr(elem, "name")


def _intent_filter_actions(elem) -> List[str]:
    if elem is None:
        return []
    actions = []
    for child in elem.iter():
        if _local(child.tag) != "action":
            continue
        value = _attr(child, "name")
        if value:
            actions.append(value)
    return list(dict.fromkeys(actions))


def _effective_exported(elem, target_sdk: Optional[int]) -> bool:
    if elem is None:
        return False
    declared = _attr(elem, "exported")
    if declared is not None:
        return declared == "true"
    if target_sdk is not None and target_sdk >= 31:
        return False
    return bool(_intent_filter_actions(elem))


def _first_tag(manifest, wanted):
    if manifest is None:
        return None
    for child in manifest.iter():
        if _local(child.tag) == wanted:
            return child
    return None


def _uses_permissions(manifest) -> set:
    return {
        _attr(child, "name")
        for child in manifest.iter()
        if _local(child.tag) == "uses-permission"
    } if manifest is not None else set()


def _declared_permissions(manifest) -> set:
    return {
        _attr(child, "name")
        for child in manifest.iter()
        if _local(child.tag) == "permission"
    } if manifest is not None else set()


def _accessibility_permission(elem) -> bool:
    return _attr(elem, "permission") == _BIND_ACCESSIBILITY


def _default_package(context) -> str:
    return context.package_name or "com.example.app"


def _class_base(elem, kind) -> str:
    return f"{kind}"


def declared_launcher(elements: Dict[str, list]) -> Optional[str]:
    for elem in elements["activity"]:
        if "android.intent.action.MAIN" in _intent_filter_actions(elem):
            return _attr(elem, "name")
    return None


def _to_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _get_manifest_xml(apk):
    if apk is None:
        return None
    try:
        return apk.get_android_manifest_xml()
    except Exception:
        return None


def _observed_string(context, value: str) -> Optional[str]:
    return value if value in context.strings else None