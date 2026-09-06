"""Behavior reconstruction: evidence-backed behavioral profile.

Public API:
    BehaviorEngine                  runs every behavior detector over the APK
    BehaviorResult / BehaviorFinding  output models
    BehaviorStatus / BehaviorSpec      status enum + catalogue driver
    BEHAVIORS / behaviors_in_order()   the behaviour catalogue
"""

from re_engine.behavior.engine import BEHAVIOR_VERSION, BehaviorEngine
from re_engine.behavior.models import (
    BehaviorFinding,
    BehaviorResult,
    BehaviorStatus,
)
from re_engine.behavior.specs import (
    BEHAVIORS,
    BehaviorSpec,
    behaviors_in_order,
)

__all__ = [
    "BEHAVIOR_VERSION",
    "BehaviorEngine",
    "BehaviorFinding",
    "BehaviorResult",
    "BehaviorStatus",
    "BEHAVIORS",
    "BehaviorSpec",
    "behaviors_in_order",
]