from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    created_at: datetime
