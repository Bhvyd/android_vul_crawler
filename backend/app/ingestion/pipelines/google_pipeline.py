from app.ingestion.vendor_bulletin.pixel_bulletin_collector import GoogleBulletinCollector
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class GooglePipeline(BaseVendorPipeline):
    vendor = "google"
    source_name = GoogleBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = GoogleBulletinCollector.__new__(GoogleBulletinCollector)

    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        months = kwargs.get("months")
        start_year = kwargs.get("start_year", 2020)
        if months is not None:
            return self._collector.fetch_bulletins(months=months)
        return self._collector.fetch_bulletins(start_year=start_year)
