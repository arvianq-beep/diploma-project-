# ML Pipeline

This folder contains the Python ML workflow for the diploma prototype.

## Expected datasets

- `CIC-IDS2017`
- `CIC-UNSW-NB15 (Augmented)`

Datasets are not committed to the repository because of size. Place them locally and train the model with:

```bash
cd backend
python -m ml.train_model --cic /path/to/CIC-IDS2017 --unsw /path/to/CIC-UNSW-NB15-AUGMENTED
```

Artifacts are saved to:

- `backend/ml/artifacts/rf_ids_model.joblib`
- `backend/ml/artifacts/evaluation_metrics.json`
- `backend/ml/artifacts/model_info.json`

## Unified features

- `protocol`
- `source_port`
- `destination_port`
- `duration`
- `forward_packets`
- `backward_packets`
- `forward_bytes`
- `backward_bytes`
- `bytes_per_second`
- `packets_per_second`

The backend inference service uses these features for both trained-model inference and fallback heuristics.
