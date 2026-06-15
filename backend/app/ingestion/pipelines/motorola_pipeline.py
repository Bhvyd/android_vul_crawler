from app.ingestion.vendor_bulletin.motorola_bulletin_collector import MotorolaBulletinCollector
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class MotorolaPipeline(BaseVendorPipeline):
    vendor = "motorola"
    source_name = MotorolaBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = MotorolaBulletinCollector()

    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        return self._collector.fetch_bulletins()
