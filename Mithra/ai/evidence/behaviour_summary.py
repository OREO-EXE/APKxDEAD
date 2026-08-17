def build_behavior(raw):
    """Compatibility shim retained for older imports."""
    from .report_builder import build_report

    evidence = build_report(raw)
    return evidence.behavior.behaviors