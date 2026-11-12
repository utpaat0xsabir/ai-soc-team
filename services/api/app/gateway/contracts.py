"""Shared TG-01 contracts; re-exported by tool_gateway for existing callers."""

from ipaddress import ip_address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


Text = Annotated[str, Field(min_length=1, max_length=64)]
Parameter = tuple[Annotated[str, Field(min_length=1, max_length=32)],
                  Annotated[str, Field(min_length=1, max_length=128)]]
Parameters = Annotated[tuple[Parameter, ...], Field(max_length=8)]


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid',
                              hide_input_in_errors=True, revalidate_instances='always')
    schema_version: Literal['1.0'] = '1.0'


class TrustedContext(_Contract):
    tenant_id: UUID
    principal_id: UUID


class _Operation(_Contract):
    tenant_id: UUID
    principal_id: UUID
    capability_id: Text
    capability_version: Text
    operation: Text
    target: Annotated[str, Field(min_length=1, max_length=45)]
    parameters: Parameters

    @field_validator('target')
    @classmethod
    def canonical_ip(cls, value, info):
        if info.data.get('capability_id') == 'wazuh.alerts.search':
            return str(UUID(value))
        if '%' in value:
            raise ValueError('invalid_target')
        return str(ip_address(value))

    @field_validator('parameters')
    @classmethod
    def canonical_parameters(cls, value):
        if len({key for key, _ in value}) != len(value):
            raise ValueError('duplicate_parameters')
        return tuple(sorted(value))


class ToolRequest(_Operation):
    request_id: UUID
