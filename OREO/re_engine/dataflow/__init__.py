"""Source-to-sink data-flow analysis for the RE engine.

Bounded, deterministic register-level taint analysis that establishes actual
data-flow paths from sensitive Android sources (SMS, contacts, call logs,
device identifiers, location, microphone, camera, clipboard, notifications,
files, credentials) to sinks (HTTP, sockets, WebSockets, files, databases,
logs, SMS send, command execution, external intents, native calls), annotating
transformations (Base64, URL encoding, encryption, compression,
serialization, JSON, string concatenation) along the way.

Every finding is evidence-backed: a flow is only emitted when the engine
traced a concrete path. Statuses distinguish confidence:

    DataFlowEngine      the analysis engine (source -> sink taint flow)
    DataFlowResult      findings + stats + limitations
    DataFlowFinding     one source-to-sink flow
    FlowStatus          CONFIRMED / PROBABLE / POSSIBLE / NOT_ESTABLISHED

Nothing in this package imports the malware-family classifier or runs an LLM.
"""

from re_engine.dataflow.engine import DATAFLOW_VERSION, DataFlowEngine
from re_engine.dataflow.models import (
    DataFlowFinding,
    DataFlowResult,
    FlowStatus,
)

__all__ = [
    "DataFlowEngine",
    "DATAFLOW_VERSION",
    "DataFlowFinding",
    "DataFlowResult",
    "FlowStatus",
]