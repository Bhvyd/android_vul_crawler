# app/ingestion/pipelines/registry.py

from app.ingestion.pipelines.google_pipeline import GooglePipeline
from app.ingestion.pipelines.samsung_pipeline import SamsungPipeline
from app.ingestion.pipelines.vivo_pipeline import VivoPipeline
from app.ingestion.pipelines.xiaomi_pipeline import XiaomiPipeline
from app.ingestion.pipelines.oppo_pipeline import OppoPipeline
from app.ingestion.pipelines.motorola_pipeline import MotorolaPipeline


PIPELINES = {
    "google": GooglePipeline,
    "samsung": SamsungPipeline,
    "vivo": VivoPipeline,
    "xiaomi": XiaomiPipeline,
    "oppo": OppoPipeline,
    "motorola": MotorolaPipeline,
}

ENABLED_VENDORS = list(PIPELINES.keys())


def get_pipeline(vendor: str):
    if vendor not in PIPELINES:
        raise ValueError(f"Unsupported vendor: {vendor}")

    return PIPELINES[vendor]()