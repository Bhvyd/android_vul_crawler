from abc import ABC, abstractmethod
from datetime import datetime, timezone

from app.ingestion.schemas import RawVendorBulletin, RawVendorRun


class BaseVendorPipeline(ABC):
    vendor: str
    source_name: str
    not_implemented: bool = False

    @abstractmethod
    def fetch_bulletins(self, **kwargs) -> list[RawVendorBulletin]:
        raise NotImplementedError

    def collect(self, run_id: str, **kwargs) -> RawVendorRun:
        errors: list[dict] = []
        if self.not_implemented:
            errors.append(
                {
                    "vendor": self.vendor,
                    "message": f"{self.vendor} collector not implemented",
                }
            )
            return RawVendorRun(
                run_id=run_id,
                vendor=self.vendor,
                bulletins=[],
                errors=errors,
            )

        try:
            bulletins = self.fetch_bulletins(**kwargs)
        except Exception as exc:
            errors.append({"vendor": self.vendor, "message": str(exc)})
            bulletins = []

        return RawVendorRun(
            run_id=run_id,
            vendor=self.vendor,
            bulletins=bulletins,
            errors=errors,
        )

    @staticmethod
    def utc_now() -> datetime:
        return datetime.now(timezone.utc)
