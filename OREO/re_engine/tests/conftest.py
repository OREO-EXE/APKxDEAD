"""Pytest fixtures for RE engine tests.

Insert the OREO package root (the parent of ``samples/`` and ``re_engine/``)
onto ``sys.path`` so the package imports without any environment setup.
"""

from __future__ import annotations

import sys
from pathlib import Path

OREO_ROOT = Path(__file__).resolve().parents[2]

if str(OREO_ROOT) not in sys.path:
    sys.path.insert(0, str(OREO_ROOT))