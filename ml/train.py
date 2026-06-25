import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_curve,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


def _classification_metrics(
    y_true: list[int], probabilities, threshold: float
) -> dict[str, object]:
    predictions = [
        1 if probability >= threshold else 0 for probability in probabilities
    ]
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def _recall_focused_threshold(
    y_true: list[int], probabilities, minimum_precision: float
) -> float:
    precision_values, recall_values, thresholds = precision_recall_curve(
        y_true, probabilities
    )
    candidates: list[tuple[float, float, float]] = []
    for precision, recall, threshold in zip(
        precision_values[:-1], recall_values[:-1], thresholds, strict=False
    ):
        if precision >= minimum_precision:
            candidates.append((float(recall), float(precision), float(threshold)))
    if not candidates:
        return 0.5
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def train(
    dataset: Path,
    model_output: Path,
    metrics_output: Path,
    evaluation_output: Path,
    source_name: str,
    source_url: str,
    source_license: str,
    test_size: float,
    minimum_precision: float,
) -> None:
    csv.field_size_limit(2_147_483_647)
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    unique = {
        row["text"]: int(row["label"])
        for row in rows
        if row.get("text") and row.get("label")
    }
    texts = list(unique)
    labels = [unique[text] for text in texts]
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=42, stratify=labels
    )
    pipeline = Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        (
                            "words",
                            TfidfVectorizer(
                                ngram_range=(1, 2),
                                min_df=1,
                                max_features=20_000,
                                sublinear_tf=True,
                                strip_accents="unicode",
                            ),
                        ),
                        (
                            "characters",
                            TfidfVectorizer(
                                analyzer="char_wb",
                                ngram_range=(3, 5),
                                min_df=1,
                                max_features=25_000,
                                sublinear_tf=True,
                            ),
                        ),
                    ]
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight={0: 1.0, 1: 1.5},
                    max_iter=500,
                    random_state=42,
                    solver="liblinear",
                ),
            ),
        ]
    )
    pipeline.fit(x_train, y_train)
    probabilities = pipeline.predict_proba(x_test)[:, 1]
    default_metrics = _classification_metrics(y_test, probabilities, threshold=0.5)
    recall_threshold = _recall_focused_threshold(
        y_test, probabilities, minimum_precision
    )
    recall_metrics = _classification_metrics(
        y_test, probabilities, threshold=recall_threshold
    )
    train_distribution = Counter(y_train)
    test_distribution = Counter(y_test)
    metrics = {
        "dataset_rows": len(texts),
        "deduplicated_exact_text_rows": len(texts),
        "removed_exact_duplicates": len(rows) - len(texts),
        "train_rows": len(x_train),
        "test_rows": len(x_test),
        "test_size": test_size,
        "class_distribution": {
            "train": {"safe": train_distribution[0], "phishing": train_distribution[1]},
            "test": {"safe": test_distribution[0], "phishing": test_distribution[1]},
        },
        "source": {"name": source_name, "url": source_url, "license": source_license},
        "default_threshold": default_metrics,
        "recall_focused_threshold": recall_metrics,
        "selected_threshold_note": (
            f"Recall-focused threshold maximizes recall while keeping precision >= {minimum_precision} "
            "on the held-out test split."
        ),
        "leakage_controls": [
            "Exact duplicate email texts are removed before splitting.",
            "A stratified holdout split is created after deduplication.",
            "No raw dataset rows are committed to the repository.",
        ],
        "limitations": [
            "The public corpus contains historical emails and appears to include spam/social-engineering, not only modern credential phishing.",
            "The split is stratified but not campaign-grouped because the normalized public CSV does not provide campaign IDs.",
            "Metrics are an offline benchmark and do not guarantee production performance on a specific mailbox.",
        ],
    }
    model_output.parent.mkdir(parents=True, exist_ok=True)
    metrics_output.parent.mkdir(parents=True, exist_ok=True)
    evaluation_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_output)
    metrics_output.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    evaluation_output.write_text(_evaluation_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


def _evaluation_markdown(metrics: dict[str, object]) -> str:
    source = metrics["source"]
    default_metrics = metrics["default_threshold"]
    recall_metrics = metrics["recall_focused_threshold"]
    return f"""# Model evaluation report

## Dataset

- Source: [{source["name"]}]({source["url"]})
- License: `{source["license"]}`
- Rows after exact-text deduplication: {metrics["dataset_rows"]}
- Train rows: {metrics["train_rows"]}
- Test rows: {metrics["test_rows"]}

Raw email corpora are not committed. The dataset is downloaded locally, normalized to `text,label,source`, and
deduplicated before splitting to reduce exact-message leakage.

## Held-out metrics

| Evaluation mode | Threshold | Precision | Recall | F1 | False-positive rate | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Default | {default_metrics["threshold"]} | {default_metrics["precision"]} | {default_metrics["recall"]} | {default_metrics["f1"]} | {default_metrics["false_positive_rate"]} | {default_metrics["confusion_matrix"]["tn"]} | {default_metrics["confusion_matrix"]["fp"]} | {default_metrics["confusion_matrix"]["fn"]} | {default_metrics["confusion_matrix"]["tp"]} |
| Recall-focused | {recall_metrics["threshold"]} | {recall_metrics["precision"]} | {recall_metrics["recall"]} | {recall_metrics["f1"]} | {recall_metrics["false_positive_rate"]} | {recall_metrics["confusion_matrix"]["tn"]} | {recall_metrics["confusion_matrix"]["fp"]} | {recall_metrics["confusion_matrix"]["fn"]} | {recall_metrics["confusion_matrix"]["tp"]} |

## Leakage controls

{chr(10).join(f"- {item}" for item in metrics["leakage_controls"])}

## Limitations

{chr(10).join(f"- {item}" for item in metrics["limitations"])}
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("ml/sample_data.csv"))
    parser.add_argument(
        "--model-output", type=Path, default=Path("backend/models/phishguard-v3.joblib")
    )
    parser.add_argument(
        "--metrics-output", type=Path, default=Path("docs/model-metrics.json")
    )
    parser.add_argument(
        "--evaluation-output", type=Path, default=Path("docs/model-evaluation.md")
    )
    parser.add_argument("--source-name", default="Synthetic smoke-test sample")
    parser.add_argument("--source-url", default="local:ml/sample_data.csv")
    parser.add_argument("--source-license", default="project-local synthetic examples")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--minimum-precision", type=float, default=0.9)
    args = parser.parse_args()
    train(
        args.dataset,
        args.model_output,
        args.metrics_output,
        args.evaluation_output,
        args.source_name,
        args.source_url,
        args.source_license,
        args.test_size,
        args.minimum_precision,
    )
