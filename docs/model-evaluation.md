# Model evaluation report

## Dataset

- Source: [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
- License: `lgpl-3.0`
- Rows after exact-text deduplication: 17522
- Train rows: 13141
- Test rows: 4381

Raw email corpora are not committed. The dataset is downloaded locally, normalized to `text,label,source`, and
deduplicated before splitting to reduce exact-message leakage.

## Held-out metrics

| Evaluation mode | Threshold | Precision | Recall | F1 | False-positive rate | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Default | 0.5 | 0.9793 | 0.9841 | 0.9817 | 0.0124 | 2711 | 34 | 26 | 1610 |
| Recall-focused | 0.2175 | 0.9102 | 0.9969 | 0.9516 | 0.0587 | 2584 | 161 | 5 | 1631 |

## Leakage controls

- Exact duplicate email texts are removed before splitting.
- A stratified holdout split is created after deduplication.
- No raw dataset rows are committed to the repository.

## Limitations

- The public corpus contains historical emails and appears to include spam/social-engineering, not only modern credential phishing.
- The split is stratified but not campaign-grouped because the normalized public CSV does not provide campaign IDs.
- Metrics are an offline benchmark and do not guarantee production performance on a specific mailbox.
