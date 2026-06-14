

from pathlib import Path
import json

from asb.parsers.bulletin_parser import BulletinParser


def export_bulletins():

    parser = BulletinParser()

    html_dir = Path(
        "storage/raw/html"
    )

    output_dir = Path(
        "output"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = []

    for html_file in sorted(
        html_dir.glob("*.html")
    ):

        try:

            bulletin = parser.parse_file(
                html_file
            )

            bulletin["source_file"] = (
                html_file.name
            )

            results.append(
                bulletin
            )

            print(
                f"[OK] Parsed "
                f"{html_file.name}"
            )

        except Exception as exc:

            print(
                f"[FAILED] "
                f"{html_file.name}: {exc}"
            )

    output_file = (
        output_dir /
        "bulletins.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            results,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"\nSaved {len(results)} bulletins "
        f"to {output_file}"
    )


if __name__ == "__main__":

    export_bulletins()





