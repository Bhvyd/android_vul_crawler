from app.ingestion.bulletin.vivo_bulletin_collector import VivoBulletinCollector
from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.schemas import RawVendorBulletin


class VivoPipeline(BaseVendorPipeline):
    vendor = "vivo"
    source_name = VivoBulletinCollector.SOURCE_NAME

    def __init__(self):
        self._collector = VivoBulletinCollector()

    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        max_advisories = kwargs.get("max_advisories")
        return self._collector.fetch_bulletins(max_advisories=max_advisories)
    
if __name__ == "__main__":
    pipeline = VivoPipeline()
    bulletins = pipeline.fetch_bulletins(
        max_advisories=5
    )
    print(len(bulletins))
    print(bulletins[0])
        