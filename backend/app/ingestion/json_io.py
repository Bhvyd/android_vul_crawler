from pathlib import Path

from app.ingestion.schemas import RawVendorRun

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_VENDOR_DIR = BACKEND_ROOT / "data_vendor" / "raw_vendor"


def raw_vendor_path(run_id: str, vendor: str) -> Path:
    return RAW_VENDOR_DIR / run_id / f"{vendor}.json"


def write_raw_vendor_json(run: RawVendorRun) -> Path:
    path = raw_vendor_path(run.run_id, run.vendor)
    print(f"Writing raw vendor JSON to {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(run.model_dump_json(indent=2), encoding="utf-8")
    return path


def read_raw_vendor_json(run_id: str, vendor: str) -> RawVendorRun:
    path = raw_vendor_path(run_id, vendor)
    return RawVendorRun.model_validate_json(path.read_text(encoding="utf-8"))
