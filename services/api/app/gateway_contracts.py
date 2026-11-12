"""Deprecated compatibility import; use app.gateway.contracts. Retire separately."""

from app.gateway.contracts import (
    Annotated as Annotated,
    BaseModel as BaseModel,
    ConfigDict as ConfigDict,
    Field as Field,
    Literal as Literal,
    Parameter as Parameter,
    Parameters as Parameters,
    Text as Text,
    ToolRequest as ToolRequest,
    TrustedContext as TrustedContext,
    UUID as UUID,
    _Contract as _Contract,
    _Operation as _Operation,
    field_validator as field_validator,
    ip_address as ip_address,
)
