from app.ingestion.vendor_bulletin.xiaomi_bulletin_collector import XiaomiBulletinCollector
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class XiaomiPipeline(BaseVendorPipeline):
    vendor = "xiaomi"
    source_name = XiaomiBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = XiaomiBulletinCollector()

    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        return self._collector.fetch_bulletins()
