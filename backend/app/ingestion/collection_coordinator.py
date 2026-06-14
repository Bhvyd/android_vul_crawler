from concurrent.futures import ThreadPoolExecutor, as_completed

from app.ingestion.pipelines.base_pipeline import BaseVendorPipeline
from app.ingestion.json_io import write_raw_vendor_json
from app.ingestion.pipelines.registry import ENABLED_VENDORS, get_pipeline
from app.ingestion.schemas import RawVendorRun


def collect_vendor(
    vendor: str,
    run_id: str,
    pipeline_kwargs: dict | None = None,
) -> RawVendorRun:
    pipeline: BaseVendorPipeline = get_pipeline(vendor)
    kwargs = pipeline_kwargs or {}
    run = pipeline.collect(run_id, **kwargs)
    write_raw_vendor_json(run)
    return run


def collect_vendors_parallel(
    run_id: str,
    vendors: list[str] | None = None,
    max_workers: int = 4,
    pipeline_kwargs: dict[str, dict] | None = None,
) -> dict[str, RawVendorRun]:
    vendor_list = vendors or ENABLED_VENDORS
    pipeline_kwargs = pipeline_kwargs or {}
    results: dict[str, RawVendorRun] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                collect_vendor,
                vendor,
                run_id,
                pipeline_kwargs.get(vendor, {}),
            ): vendor
            for vendor in vendor_list
        }
        for future in as_completed(futures):
            vendor = futures[future]
            results[vendor] = future.result()

    return results

if __name__ == "__main__":
    print("Starting collection...")

    from datetime import datetime

    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    results = collect_vendors_parallel(
        run_id=run_id,
    )

    print(results.keys())
