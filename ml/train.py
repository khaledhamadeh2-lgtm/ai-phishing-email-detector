import argparse
import csv
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


def train(dataset: Path, model_output: Path, metrics_output: Path) -> None:
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    unique = {row["text"]: int(row["label"]) for row in rows if row.get("text") and row.get("label")}
    texts = list(unique)
    labels = [unique[text] for text in texts]
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.33, random_state=42, stratify=labels
    )
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=30_000, sublinear_tf=True)),
            (
                "classifier",
                LogisticRegression(class_weight={0: 1.0, 1: 1.35}, max_iter=1_000, random_state=42),
            ),
        ]
    )
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    metrics = {
        "dataset_rows": len(texts),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "warning": (
            "Illustrative smoke-test metrics from the tiny synthetic dataset; "
            "not production evidence."
        ),
    }
    model_output.parent.mkdir(parents=True, exist_ok=True)
    metrics_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_output)
    metrics_output.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("ml/sample_data.csv"))
    parser.add_argument("--model-output", type=Path, default=Path("backend/models/phishguard-v1.joblib"))
    parser.add_argument("--metrics-output", type=Path, default=Path("docs/model-metrics.json"))
    args = parser.parse_args()
    train(args.dataset, args.model_output, args.metrics_output)
