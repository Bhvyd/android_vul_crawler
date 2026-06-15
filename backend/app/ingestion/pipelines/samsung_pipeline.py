from app.ingestion.vendor_bulletin.samsung_bulletin_collector import SamsungBulletinCollector
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class SamsungPipeline(BaseVendorPipeline):
    vendor = "samsung"
    source_name = SamsungBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = SamsungBulletinCollector.__new__(SamsungBulletinCollector)

    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        years = kwargs.get("years")
        start_year = kwargs.get("start_year", 2020)
        if years is not None:
            return self._collector.fetch_bulletins(years=years)
        return self._collector.fetch_bulletins(start_year=start_year)
