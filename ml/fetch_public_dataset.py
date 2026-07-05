import argparse
import csv
import json
import urllib.request
from pathlib import Path

DATASET_API_URL = (
    "https://huggingface.co/api/datasets/zefang-liu/phishing-email-dataset"
)
DATASET_CSV_URL = "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv"


def _download(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "phishguard-ai-dataset-prep/1.0"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _label(raw_label: str) -> int:
    value = raw_label.strip().lower()
    if value == "phishing email":
        return 1
    if value == "safe email":
        return 0
    raise ValueError(f"Unexpected label: {raw_label!r}")


def normalize_dataset(
    raw_csv: Path, output_csv: Path, metadata_output: Path
) -> dict[str, object]:
    csv.field_size_limit(2_147_483_647)
    with raw_csv.open(encoding="utf-8", newline="", errors="replace") as handle:
        rows = list(csv.DictReader(handle))

    normalized: dict[str, int] = {}
    skipped = 0
    for row in rows:
        text = (row.get("Email Text") or "").strip()
        label_text = (row.get("Email Type") or "").strip()
        if not text or not label_text or text.lower() == "nan":
            skipped += 1
            continue
        try:
            normalized[text] = _label(label_text)
        except ValueError:
            skipped += 1

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "label", "source"])
        writer.writeheader()
        for text, label in normalized.items():
            writer.writerow(
                {
                    "text": text,
                    "label": label,
                    "source": "zefang-liu/phishing-email-dataset",
                }
            )

    metadata = {
        "dataset_name": "zefang-liu/phishing-email-dataset",
        "dataset_url": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset",
        "raw_file": "Phishing_Email.csv",
        "license": "lgpl-3.0",
        "raw_rows": len(rows),
        "normalized_rows": len(normalized),
        "skipped_rows": skipped,
        "label_mapping": {"Safe Email": 0, "Phishing Email": 1},
        "notes": (
            "Raw corpus is downloaded locally and normalized to text,label,source. "
            "The raw dataset is not committed to the repository."
        ),
    }
    metadata_output.parent.mkdir(parents=True, exist_ok=True)
    metadata_output.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def fetch(raw_csv: Path, output_csv: Path, metadata_output: Path) -> dict[str, object]:
    api_data = json.loads(_download(DATASET_API_URL).decode("utf-8"))
    license_name = (api_data.get("cardData") or {}).get("license")
    if license_name != "lgpl-3.0":
        raise RuntimeError(
            f"Dataset license changed or could not be verified: {license_name!r}"
        )

    raw_csv.parent.mkdir(parents=True, exist_ok=True)
    raw_csv.write_bytes(_download(DATASET_CSV_URL))
    return normalize_dataset(raw_csv, output_csv, metadata_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--raw-csv", type=Path, default=Path("data/raw/Phishing_Email.csv")
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("data/processed/phishing_email_dataset.csv"),
    )
    parser.add_argument(
        "--metadata-output", type=Path, default=Path("docs/dataset-metadata.json")
    )
    args = parser.parse_args()
    print(
        json.dumps(fetch(args.raw_csv, args.output_csv, args.metadata_output), indent=2)
    )
