from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from app.db import engine

app = FastAPI(
    title="AI SOC Team API",
    description="Foundation API for a local-first AI Security Operations Center.",
    version="0.1.0",
)


@app.get("/health", tags=["System"])
def health():
    """Check whether the API process is responding."""
    return {
        "status": "ok",
        "service": "ai-soc-api",
    }


@app.get("/ready", tags=["System"])
def readiness():
    """Check whether the API can communicate with PostgreSQL."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="database_unavailable",
        ) from exc

    return {
        "status": "ready",
        "database": "available",
    }
