"""Deprecated compatibility import; use app.integrations.wazuh.cursor. Retire separately."""

from app.integrations.wazuh.cursor import (
    MAX_CURSOR_BYTES as MAX_CURSOR_BYTES,
    MAX_TIMESTAMP_MS as MAX_TIMESTAMP_MS,
    SortValues as SortValues,
    UUID as UUID,
    WazuhCursor as WazuhCursor,
    _integer as _integer,
    _invalid as _invalid,
    _text as _text,
    _unique_object as _unique_object,
    asdict as asdict,
    dataclass as dataclass,
    json as json,
    re as re,
    replace as replace,
    validate_sort_values as validate_sort_values,
)
