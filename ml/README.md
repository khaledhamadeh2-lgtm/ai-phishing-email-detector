# Model training

The model pipeline trains a hybrid TF-IDF logistic-regression classifier for email text classification.

## Public dataset workflow

The current `phishguard-v3` artifact is trained from:

- Dataset: [`zefang-liu/phishing-email-dataset`](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
- License: `lgpl-3.0`
- Original file: `Phishing_Email.csv`
- Normalized schema: `text,label,source`

Raw email corpora are downloaded to `data/`, which is ignored by Git. Do not commit redistributed raw email data.

```bash
python ml/fetch_public_dataset.py
python ml/train.py --dataset data/processed/phishing_email_dataset.csv \
  --source-name zefang-liu/phishing-email-dataset \
  --source-url https://huggingface.co/datasets/zefang-liu/phishing-email-dataset \
  --source-license lgpl-3.0
```

`fetch_public_dataset.py` verifies the dataset license from the Hugging Face dataset API before downloading, then
normalizes `Email Text` and `Email Type` into the project schema.

## Leakage controls

- Exact duplicate email texts are removed before splitting.
- A stratified holdout split is created after deduplication.
- Raw dataset rows are not committed to the repository.

## Evaluation outputs

Training writes:

- `backend/models/phishguard-v3.joblib` - versioned model artifact
- `docs/model-metrics.json` - machine-readable metrics
- `docs/model-evaluation.md` - recruiter/reviewer-friendly evaluation report
- `docs/dataset-metadata.json` - dataset source, license, row counts, and label mapping

## Limitations

The benchmark is much more realistic than the original synthetic smoke test, but it is still not a production claim.
The public corpus is historical, appears to include spam/social-engineering examples beyond credential phishing, and
does not provide campaign IDs for campaign-grouped splitting. Future work should add campaign-aware evaluation,
time-based validation, and organization-specific false-positive analysis.

The committed `sample_data.csv` remains only as a tiny offline fallback for pipeline smoke tests.
