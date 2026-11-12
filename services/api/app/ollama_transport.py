"""Deprecated compatibility import; use app.analysts.providers.ollama_transport. Retire separately."""

from app.analysts.providers.ollama_transport import (
    GatedLiveOllamaProvider as GatedLiveOllamaProvider,
    GatedOllamaTransport as GatedOllamaTransport,
    MAX_HEADER_BYTES as MAX_HEADER_BYTES,
    MAX_WIRE_BYTES as MAX_WIRE_BYTES,
    _ClosingStream as _ClosingStream,
    _destination as _destination,
    _generate_chat as _generate_chat,
    _require_operational_clearance as _require_operational_clearance,
    _validate_request as _validate_request,
    dataclass as dataclass,
    field as field,
    httpx as httpx,
    inference as inference,
    math as math,
)
