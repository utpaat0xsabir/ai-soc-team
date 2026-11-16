"""Deprecated compatibility exports; use app.audit.integrity. Retire separately."""

from . import integrity as _integrity

globals().update(
    {
        name: value
        for name, value in vars(_integrity).items()
        if not name.startswith("__")
    }
)
