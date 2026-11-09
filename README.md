# AI SOC Team

A local-first, evidence-driven AI Security Operations Center.

## Current phase

Phase 0: Project foundation.

## Initial components

- FastAPI application
- PostgreSQL 16
- Pydantic configuration
- SQLAlchemy database connectivity
- Automated API tests

## Security principles

- Read-only investigation by default.
- No autonomous destructive response actions.
- Evidence must have traceable provenance.
- AI interpretations must remain distinguishable from observations.
- Human approval is required for response actions.
- Secrets must not be committed to Git.

## Development setup

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Start PostgreSQL:

    sudo docker compose --env-file .env \
      -f deploy/compose/compose.yaml up -d

Start the API:

    uvicorn app.main:app --app-dir services/api --reload

Run tests:

    pytest

API documentation:

    http://127.0.0.1:8000/docs
