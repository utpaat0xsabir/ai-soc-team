"""Deprecated compatibility import; use app.analysts.providers.ollama_prompt. Retire separately."""

from app.analysts.providers.ollama_prompt import (
    ACCOUNTING_VERSION as ACCOUNTING_VERSION,
    Annotated as Annotated,
    CHAT_OVERHEAD_UNITS as CHAT_OVERHEAD_UNITS,
    Field as Field,
    Literal as Literal,
    OllamaPromptPlan as OllamaPromptPlan,
    _Contract as _Contract,
    ai as ai,
    build_chat_body as build_chat_body,
    evaluation as evaluation,
    hashlib as hashlib,
    json as json,
    model_validator as model_validator,
    optimize_prompt as optimize_prompt,
    strip_schema_titles as strip_schema_titles,
    validate_plan as validate_plan,
)
