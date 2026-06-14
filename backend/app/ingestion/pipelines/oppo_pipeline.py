from app.ingestion.bulletin.oppo_bulletin_collector import (
    OppoBulletinCollector,
)
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class OppoPipeline(BaseVendorPipeline):
    vendor = "oppo"
    source_name = OppoBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = OppoBulletinCollector()

    def fetch_bulletins(
        self,
        **kwargs,
    ) -> list[RawVendorBulletin]:
        return self._collector.fetch_bulletins(
            start_year=kwargs.get("start_year", 2022),
            end_year=kwargs.get("end_year"),
        )