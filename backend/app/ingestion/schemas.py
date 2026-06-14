from datetime import date, datetime

from pydantic import BaseModel, Field


class RawVendorBulletin(BaseModel):
    vendor: str
    source_name: str
    bulletin_id: str
    bulletin_date: date | None
    bulletin_url: str | None
    cve_ids: list[str]
    fetched_at: datetime
    metadata: dict = Field(default_factory=dict)


class RawVendorRun(BaseModel):
    run_id: str
    vendor: str
    bulletins: list[RawVendorBulletin]
    errors: list[dict] = Field(default_factory=list)
