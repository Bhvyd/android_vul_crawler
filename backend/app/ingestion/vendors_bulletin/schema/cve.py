from datetime import date
from pydantic import BaseModel, Field


class CVERecord(BaseModel):
    cve_id: str

    vendor: str

    source_name: str

    bulletin_id: str | None = None

    bulletin_url: str | None = None

    bulletin_date: date | None = None

    severity: str | None = None

    vulnerability_type: str | None = None

    subcomponent: str | None = None

    reference: str | None = None

    cvss_score: float | None = None        

    cvss_vector: str | None = None   

    description: str | None = None         

    affected_versions: str | None = None   

    fixed_versions: str | None = None      

    source_credit: str | None = None       

    last_updated_date: date | None = None  

    vendor_advisory: str | None = None
    

    metadata: dict = Field(default_factory=dict)