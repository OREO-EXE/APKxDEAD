"""Behaviour catalogue shape guarantees."""

from __future__ import annotations

import re

from re_engine.behavior.specs import BEHAVIORS, BY_KEY, behaviors_in_order

KNOWN_CATEGORIES = {
    "persistence",
    "data_collection",
    "command_execution",
    "dynamic_behavior",
    "network",
    "evasion",
    "cryptography",
}

KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")


def test_catalogue_sizes_and_unique_keys():
    assert len(BEHAVIORS) == 41
    assert len({spec.key for spec in BEHAVIORS}) == len(BEHAVIORS)
    assert len(BY_KEY) == len(BEHAVIORS)
    assert len(behaviors_in_order()) == len(BEHAVIORS)
    ordered = [spec.key for spec in behaviors_in_order()]
    # stable (category, key) order
    expected = sorted(BEHAVIORS, key=lambda spec: (spec.category, spec.key))
    assert ordered == [spec.key for spec in expected]


def test_every_spec_has_identity_and_category():
    for spec in BEHAVIORS:
        assert KEY_RE.match(spec.key), spec.key
        assert spec.name
        assert spec.description
        assert spec.category in KNOWN_CATEGORIES, spec.key


def test_all_behaviors_evaluate_with_known_statuses_only():
    # Every spec must be mappable by a detector (direct or aggregate); the
    # registry/aggregate-union must exactly cover the catalogue.
    from re_engine.behavior.detectors import AGGREGATE_KEYS, DETECTORS

    catalog = {spec.key for spec in BEHAVIORS}
    assert catalog == (set(DETECTORS) | AGGREGATE_KEYS)
    assert AGGREGATE_KEYS.issubset(catalog)


def test_every_category_is_represented():
    cats = {spec.category for spec in BEHAVIORS}
    assert cats == KNOWN_CATEGORIES


def test_detectable_behaviors_have_evidence_signatures():
    for spec in BEHAVIORS:
        if spec.key in {
            "evasion.anti_analysis",
            "evasion.control_flow_obfuscation",
            "persistence.background_service",
            "dynamic.downloaded_code",
            "dynamic.encrypted_payload",
        }:
            continue  # aggregate / combinatorial detectors
        assert (
            spec.call_prefixes
            or spec.field_prefixes
            or spec.class_prefixes
            or spec.strings
            or spec.permissions
        ), spec.key