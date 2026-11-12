"""Deprecated compatibility exports; use app.database.roles. Retire separately."""

from app.database.roles import (
    APPLICATION_TABLES as APPLICATION_TABLES,
    Base as Base,
    EXPECTED_REVISION as EXPECTED_REVISION,
    RolePlan as RolePlan,
    _SafeParser as _SafeParser,
    _identifier as _identifier,
    argparse as argparse,
    bootstrap_sql as bootstrap_sql,
    dataclass as dataclass,
    main as main,
    ownership_sql as ownership_sql,
    preflight_sql as preflight_sql,
    re as re,
    render_sql as render_sql,
    runtime_grants_sql as runtime_grants_sql,
)
