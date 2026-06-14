import argparse
import sys
from datetime import datetime, timezone

from app.ingestion.pipelines.json_io import write_raw_vendor_json
from app.ingestion.pipelines.registry import ENABLED_VENDORS, get_pipeline


def _parse_years(value: str | None) -> list[int] | None:
    if not value:
        return None
    return [int(y.strip()) for y in value.split(",") if y.strip()]


def _parse_months(value: str | None) -> list[str] | None:
    if not value:
        return None
    months: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        # YYYY-MM → bulletin day URL; YYYY-MM-DD passed through
        if len(part) == 7 and part[4] == "-":
            months.append(f"{part}-01")
        else:
            months.append(part)
    return months


def _build_kwargs(args: argparse.Namespace) -> dict:
    kwargs: dict = {}
    years = _parse_years(args.years)
    months = _parse_months(args.months)
    if years is not None:
        kwargs["years"] = years
    if months is not None:
        kwargs["months"] = months
    if args.start_year is not None:
        kwargs["start_year"] = args.start_year
    return kwargs


def main() -> int:
    parser = argparse.ArgumentParser(description="Single-vendor bulletin smoke test")
    parser.add_argument("--vendor", required=True, help=f"One of: {', '.join(ENABLED_VENDORS)}")
    parser.add_argument("--years", help="Comma-separated years (Samsung)")
    parser.add_argument("--months", help="Comma-separated YYYY-MM (Google)")
    parser.add_argument("--start-year", type=int, help="Default start year for range fetch")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip HTTP; for not-implemented vendors only",
    )
    args = parser.parse_args()

    vendor = args.vendor.lower()


    try:
        pipeline = get_pipeline(vendor)
    except ValueError as exc:
        print(exc)
        return 1

    if pipeline.not_implemented:
        print(f"{vendor}: not implemented")
        return 1

    if args.dry_run:
        print(f"{vendor}: dry-run — no HTTP requests")
        return 0

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    run_id = f"smoke_{vendor}_{timestamp}"
    kwargs = _build_kwargs(args)

    run = pipeline.collect(run_id, **kwargs)

    if run.errors:
        for err in run.errors:
            print(f"ERROR: {err.get('message', err)}")
        return 1

    if not run.bulletins:
        print(f"{vendor}: no bulletins fetched")
        return 1

    path = write_raw_vendor_json(run)
    all_cves: set[str] = set()
    for bulletin in run.bulletins:
        all_cves.update(bulletin.cve_ids)

    sample = sorted(all_cves)[:10]
    print(f"vendor:       {vendor}")
    print(f"bulletins:    {len(run.bulletins)}")
    print(f"unique CVEs:  {len(all_cves)}")
    print(f"sample CVEs:  {sample}")
    print(f"output:       {path}")

    if not all_cves and vendor not in ("oneplus", "nokia", "sony"):
        print(f"{vendor}: warning — zero CVEs extracted")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
