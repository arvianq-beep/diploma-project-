# AI-driven Intrusion Detection System with Verification Layer

Flutter diploma prototype backed by a Python ML inference service for tabular network events.

The system is intentionally built around one core idea:

raw AI prediction is not trusted blindly.

Every model output is passed through a separate verification layer before the application assigns the final status.

## Thesis Topic

AI-driven Intrusion Detection System with Verification Layer

## What Problem the System Solves

Many IDS demos stop at a classifier label or probability score. That is not enough for a convincing operational decision:

- a confident model can still be unstable
- a prediction can conflict with contextual evidence
- a security analyst needs justification, not only a score

This project addresses that by splitting the decision workflow into two stages:

1. ML model inference
2. Verification-driven final decision

## Final Statuses

The application always ends with one of these statuses:

- `Benign`
- `Verified Threat`
- `Suspicious`

Meaning:

- `Benign`: the event appears safe and the verification layer supports the benign interpretation
- `Verified Threat`: the ML prediction is supported by verification checks and cross-evidence
- `Suspicious`: the ML output is not sufficiently validated and the case should be reviewed manually

## System Architecture

```text
Flutter App
  ├─ Dashboard / Analysis / Event Details / Reports / About
  ├─ Domain models
  ├─ Verification layer
  ├─ Analyst workflow
  └─ PDF report export

Python Backend
  ├─ Flask API
  ├─ ML training pipeline
  ├─ Serialized model artifacts
  ├─ Inference wrapper
  └─ Metadata / dataset / report endpoints
```

### Flutter structure

```text
lib/
  core/
  data/
    repositories/
    services/
  domain/
    models/
  features/
    analysis/
    dashboard/
    event_details/
    home/
    reports/
    settings/
  shared/
    widgets/
```

### Backend structure

```text
backend/
  ml/
    preprocessing.py
    train_model.py
    inference.py
    schema.py
  server.py
  storage.py
  datasets_storage.py
```

## Datasets Used

The ML pipeline is prepared for:

- `CIC-IDS2017`
- `CIC-UNSW-NB15 (Augmented)`

Recommended usage:

- training and validation: `CIC-IDS2017`
- cross-dataset robustness check: `CIC-UNSW-NB15 (Augmented)`

The datasets are not committed to the repository because of size. They must be placed locally before training.

## Unified ML Feature Set

To keep the model explainable and compatible across datasets, the training pipeline uses a compact flow-based feature set:

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

The preprocessing pipeline:

- maps CIC and UNSW columns into a common schema
- handles missing values
- normalizes protocol values
- derives rates when a dataset does not provide them directly
- converts labels into a binary target: benign vs attack

## Chosen Model

The current ML pipeline uses:

- `Random Forest`

Why this choice:

- strong baseline for tabular security data
- stable and reproducible
- easy to explain in a diploma defense
- supports probability output for verification checks
- avoids unnecessary deep learning complexity

## ML Pipeline

### Training

Run from the `backend/` directory:

```bash
python -m ml.train_model --cic /path/to/CIC-IDS2017 --unsw /path/to/CIC-UNSW-NB15-AUGMENTED
```

This produces:

- `backend/ml/artifacts/rf_ids_model.joblib`
- `backend/ml/artifacts/evaluation_metrics.json`
- `backend/ml/artifacts/model_info.json`

### Inference

The Flask backend loads the serialized model if the artifact exists.

If the artifact is missing, the backend still works in fallback mode using a heuristic predictor. This keeps the app runnable for UI/demo work, but trained-model mode is the intended diploma path.

## Verification Layer

The verification layer is still the central contribution of the project.

It runs after ML inference and checks whether the raw AI output should be trusted.

Current checks:

- confidence threshold check
- stability and consistency check
- anomaly/context cross-check
- rule-based cross-evidence validation
- explainability support check

The ML model only provides:

- raw label
- confidence score
- stability score
- triggered indicators
- reasoning support

The verification layer then decides whether the result is strong enough for:

- `Benign`
- `Verified Threat`
- `Suspicious`

## End-to-End Pipeline

1. A network event is selected or imported
2. Flutter sends the event to the Python backend
3. Backend returns raw ML prediction and confidence
4. Flutter runs the verification layer locally
5. The final decision engine assigns one of three statuses
6. Analyst notes can be added
7. A PDF report can be exported

## CSV Import

The application supports CSV import for diploma demonstration.

Current workflow:

1. Select a CSV file in the `Analysis` screen
2. Flutter parses rows into `ThreatEvent` objects
3. Each event is sent to the backend for ML inference
4. Verification is applied locally to every returned prediction
5. The app shows a batch summary:
   `Benign`, `Verified Threat`, `Suspicious`

This allows a realistic demo without training inside Flutter.

## API Endpoints

Main backend endpoints:

- `GET /health`
- `GET /api/v1/ml/metadata`
- `POST /api/v1/analyze`
- `POST /api/v1/analyze/csv`
- `GET /api/v1/datasets`
- `POST /api/v1/datasets/upload`
- `POST /api/v1/datasets/<dataset_id>/analyze`

## Reports

Each report includes:

- event metadata
- raw AI prediction
- confidence
- model version
- verification results
- final decision
- explanation
- analyst notes
- timestamp

PDF export is generated in Flutter.

## How to Run

### 1. Install backend dependencies

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the backend

```bash
cd backend
python server.py
```

### 3. Run the Flutter app

```bash
flutter pub get
flutter run
```

## Metrics

The backend is designed to compute and save:

- accuracy
- precision
- recall
- F1-score
- false positive rate
- confusion matrix
- ROC-AUC
- PR-AUC

These metrics are stored in:

- `backend/ml/artifacts/evaluation_metrics.json`

Repository note:

- `backend/ml/artifacts/model_info.json` and `backend/ml/artifacts/evaluation_metrics.json` are suitable for version control
- `backend/ml/artifacts/rf_ids_model.joblib` is intentionally kept out of git because it is a large binary artifact
- if you want to distribute a pre-trained model together with the repository, use Git LFS or attach the artifact separately

### Important note about the current repository state

The codebase now supports real training and evaluation on `CIC-IDS2017` and `CIC-UNSW-NB15 (Augmented)`, but those full datasets are not currently present in this repository.

That means:

- the ML training pipeline is implemented
- the inference backend is implemented
- Flutter integration is implemented
- real metrics will appear after local training on the actual datasets

If the artifacts are missing, the app falls back to a heuristic backend/local path so the project remains runnable.

## What Is Real and What Is Still Mock

### Real / implemented

- Python ML preprocessing pipeline
- Random Forest training script
- serialized model artifact flow
- Flask inference API
- Flutter-to-backend integration
- verification layer
- analyst workflow
- report export
- CSV import pipeline

### Still conditional on local dataset availability

- trained model artifact itself
- final reported CIC/UNSW evaluation numbers
- trained-model runtime mode in the backend

## Demo Scenario

Recommended defense flow:

1. Open `Dashboard`
2. Explain the three final statuses
3. Open `Analysis`
4. Show backend model mode and version
5. Run a sample event
6. Show raw ML label and confidence
7. Show verification checks
8. Open `Event Details`
9. Add analyst notes
10. Import a CSV file and show batch summary
11. Open `Reports`
12. Export PDF

## Future Improvements

- train and store final thesis artifacts on the full CIC and UNSW datasets
- add multiclass attack-family prediction on top of binary attack detection
- persist analyst reviews in a real database
- add richer feature-level explainability
- support true dataset-scale batch inference from the backend

## Project Identity

This project is not just a classifier UI.

It is a diploma-ready prototype of an intrusion detection system where:

- AI produces a raw opinion
- verification validates that opinion
- the system exposes uncertainty explicitly
- the analyst remains part of the final decision loop
