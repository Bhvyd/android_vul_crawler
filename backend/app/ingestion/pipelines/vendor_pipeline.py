from datetime import datetime, timezone

from app.ingestion.pipelines.collection_coordinator import collect_vendors_parallel
from app.ingestion.pipelines.json_io import RAW_VENDOR_DIR
from app.ingestion.pipelines.registry import ENABLED_VENDORS
from app.ingestion.pipelines.schemas import RawVendorRun


class VendorPipeline:
    """Batch collect: parallel fetch per vendor → raw JSON under data/raw_vendor/{run_id}/."""

    def __init__(
        self,
        vendors: list[str] | None = None,
        run_id: str | None = None,
        max_workers: int = 4,
    ):
        self.vendors = vendors or list(ENABLED_VENDORS)
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        self.max_workers = max_workers

    def collect(
        self,
        pipeline_kwargs: dict[str, dict] | None = None,
    ) -> dict[str, RawVendorRun]:
        return collect_vendors_parallel(
            run_id=self.run_id,
            vendors=self.vendors,
            max_workers=self.max_workers,
            pipeline_kwargs=pipeline_kwargs,
        )

    @property
    def output_dir(self):
        return RAW_VENDOR_DIR / self.run_id
