# Phishing Website Detector

Local MVP for phishing website detection using a Flask web app, multi-layer feature extraction, and an offline-trained ML model.

## What The Project Includes

- Single URL analysis with risk score and explanation
- Full detail page for one analyzed URL
- JSON and Markdown export for a single analysis
- JSON API endpoint for programmatic analysis
- Training report page with metrics and evaluation plots
- Batch CSV analysis with downloadable results
- Recent activity tracking
- Read-only settings page for runtime configuration

## Fast Demo Start

If you are on Windows, use:

```bat
run_demo.bat
```

That helper will:

1. check Python
2. install dependencies
3. train the sample model if `data/model_artifact.pkl` is missing
4. start the Flask app

Then open:

```text
http://127.0.0.1:5000
```

## Manual Setup

```bash
python -m pip install -r requirements.txt
python -m phishing_detector.training --data data/sample_urls.csv --artifact data/model_artifact.pkl
python app.py
```

## API Security Settings

The JSON endpoint `POST /api/analyze` supports optional token auth and built-in rate limiting.

```text
API_REQUIRE_AUTH=1
API_AUTH_TOKEN=replace-with-strong-token
API_RATE_LIMIT_WINDOW_SECONDS=60
API_RATE_LIMIT_MAX_REQUESTS=30
```

Send token via:

- `Authorization: Bearer <token>`
- or `X-API-Key: <token>`

## App Pages

- `/` dashboard + single URL analyzer
- `/analysis-detail?url=...` full explanation for one URL
- `/analysis-export.json?url=...` JSON export for one URL
- `/analysis-export.md?url=...` Markdown export for one URL
- `/api/analyze` POST JSON API for one URL
- `/training-report` model metrics and evaluation plots
- `/batch-analysis` batch CSV upload and preview
- `/settings` read-only runtime configuration view

## End-To-End Demo Flow

1. Start the app with `run_demo.bat` or the manual commands above.
2. Open the dashboard at `http://127.0.0.1:5000`.
3. Submit a single URL to see the verdict, risk score, and short explanation.
4. Open the full detail page to inspect URL, domain, and content signals.
5. Export the same analysis as JSON or Markdown.
6. Open the training report to show model comparison and plots.
7. Upload a CSV on the batch-analysis page to analyze multiple URLs at once.

## Training Pipeline

Train with the sample dataset:

```bash
python -m phishing_detector.training --data data/sample_urls.csv --artifact data/model_artifact.pkl
```

Each run writes:

- model artifact: `data/model_artifact.pkl`
- JSON report: `data/model_artifact_report.json`
- Markdown summary: `data/model_artifact_summary.md`
- evaluation plots: `data/model_artifact_plots`

Optional overrides:

```bash
python -m phishing_detector.training --data data/sample_urls.csv --artifact data/model_artifact.pkl --report data/training_report.json --summary data/training_summary.md --plot-dir data/training_plots
```

Supported dataset styles:

- Raw URL datasets with columns like `url`, `URL`, `Domain`, `website`
- Engineered-feature datasets with numeric phishing features plus a label column

## Kaggle Dataset Workflow (Recommended)

1. Download a phishing URL dataset CSV from Kaggle.
2. Place it under `data/` (example: `data/kaggle_phishing_urls.csv`).
3. Ensure it has at least one URL-like column (`url`, `URL`, `Domain`, `website`, etc.) and one label column (`label`, `class`, `result`, etc.).
4. Train and generate full artifacts:

```bash
python -m phishing_detector.training --data data/kaggle_phishing_urls.csv --artifact data/model_artifact.pkl
```

5. Review quality in:

- `data/model_artifact_report.json`
- `data/model_artifact_summary.md`
- `data/model_artifact_plots/`

Tip:
- Use a larger dataset for realistic metrics and fewer overfitting artifacts.

Note:
- Engineered-feature artifacts are for offline experimentation.
- The live Flask analyzer expects artifacts trained from raw URLs through this project's own feature extractor.

## Batch CSV Format

The batch analyzer accepts CSV files with one URL-like column such as:

- `url`
- `URL`
- `Domain`
- `website`
- `link`
- `uri`

## Tests

```bash
python -m unittest discover -s tests -v
```

## Notes

- Live checks are best-effort and can fail without stopping the analysis.
- External reputation lookup is enabled by default and can be disabled with `ENABLE_REPUTATION_LOOKUPS=0`.
- Stitch redesign source files are stored in `stitch_phishing_detector_ui_redesign/` for design reference and iteration history.
- The bundled sample dataset is only for demonstration and pipeline verification.
- Replace it with a real public phishing dataset for better model quality.
