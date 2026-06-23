# Model training

`train.py` accepts a CSV containing `text` and binary `label` columns. It deduplicates messages before a
stratified split, preventing exact-message leakage, then trains a TF-IDF logistic-regression pipeline.

The committed `sample_data.csv` is synthetic and intentionally small; it exists only to make the pipeline
reproducible and the application demonstrable. Its metrics are not a claim of real-world accuracy.

For a meaningful experiment, download datasets from their original sources and confirm their current terms:

- [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) for legitimate and spam mail.
- [Nazario phishing corpus](https://monkey.org/~jose/phishing/) for historical phishing messages.

Do not commit redistributed email corpora. Normalize them into the two-column schema locally, preserve source
metadata for group-aware splitting, and review personal information before processing.
