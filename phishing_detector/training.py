from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, Iterable, Tuple

import pandas as pd

from .config import DEFAULT_ARTIFACT_PATH
from .feature_extraction import FEATURE_COLUMNS, build_feature_vector

URL_COLUMN_CANDIDATES = (
    "url",
    "URL",
    "Url",
    "link",
    "Link",
    "domain",
    "Domain",
    "website",
    "Website",
    "uri",
    "URI",
)

LABEL_COLUMN_CANDIDATES = (
    "label",
    "Label",
    "class",
    "Class",
    "result",
    "Result",
    "status",
    "Status",
    "type",
    "Type",
    "is_phishing",
    "Is_Phishing",
)


def _require_sklearn():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
    from sklearn.model_selection import train_test_split

    return {
        "RandomForestClassifier": RandomForestClassifier,
        "LogisticRegression": LogisticRegression,
        "accuracy_score": accuracy_score,
        "confusion_matrix": confusion_matrix,
        "f1_score": f1_score,
        "precision_score": precision_score,
        "recall_score": recall_score,
        "roc_auc_score": roc_auc_score,
        "roc_curve": roc_curve,
        "train_test_split": train_test_split,
    }


def _optional_xgboost():
    try:
        from xgboost import XGBClassifier
    except Exception:
        return None
    return XGBClassifier


def normalize_label(value) -> int:
    text = str(value).strip().lower()
    if text in {"1", "true", "phishing", "malicious", "bad", "yes", "spam", "fraud"}:
        return 1
    if text in {"0", "false", "legitimate", "benign", "safe", "good", "no", "ham"}:
        return 0
    if text == "-1":
        return 1
    raise ValueError(f"Unsupported label value: {value}")


def _resolve_column(columns, candidates, kind: str) -> str:
    normalized = {str(column).strip().lower(): column for column in columns}
    for candidate in candidates:
        match = normalized.get(candidate.lower())
        if match is not None:
            return match
    raise ValueError(
        f"Could not find a {kind} column. Supported {kind} columns include: {', '.join(candidates)}."
    )


def _normalize_frame(frame: pd.DataFrame, path: Path) -> pd.DataFrame:
    url_column = _resolve_column(frame.columns, URL_COLUMN_CANDIDATES, "URL")
    label_column = _resolve_column(frame.columns, LABEL_COLUMN_CANDIDATES, "label")
    normalized = frame[[url_column, label_column]].copy()
    normalized.columns = ["url", "label"]
    try:
        normalized["label"] = normalized["label"].map(normalize_label)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    normalized["url"] = normalized["url"].astype(str).str.strip()
    normalized = normalized.dropna()
    normalized = normalized[normalized["url"] != ""]
    return normalized


def load_dataset(paths: Iterable[Path]) -> pd.DataFrame:
    frames = []
    for path in paths:
        frame = pd.read_csv(path)
        frames.append(_normalize_frame(frame, path))
    data = pd.concat(frames, ignore_index=True).dropna()
    data = data[data["url"] != ""].drop_duplicates(subset=["url"])
    return data


def _load_engineered_dataset(paths: Iterable[Path]) -> pd.DataFrame:
    frames = []
    for path in paths:
        frame = pd.read_csv(path).dropna()
        label_column = _resolve_column(frame.columns, LABEL_COLUMN_CANDIDATES, "label")
        normalized = frame.copy()
        try:
            normalized[label_column] = normalized[label_column].map(normalize_label)
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc

        feature_columns = []
        for column in normalized.columns:
            if column == label_column:
                continue
            converted = pd.to_numeric(normalized[column], errors="coerce")
            if converted.notna().all():
                normalized[column] = converted.astype(float)
                feature_columns.append(column)

        if not feature_columns:
            raise ValueError(f"{path}: no numeric engineered feature columns found.")

        normalized = normalized[feature_columns + [label_column]].copy()
        normalized = normalized.rename(columns={label_column: "label"})
        frames.append(normalized)

    base_columns = list(frames[0].columns)
    for frame in frames[1:]:
        if list(frame.columns) != base_columns:
            raise ValueError("Engineered feature datasets must have identical column order across files.")
    return pd.concat(frames, ignore_index=True).dropna()


def load_training_input(paths: Iterable[Path]) -> Tuple[pd.DataFrame, str]:
    path_list = [Path(item) for item in paths]
    first = pd.read_csv(path_list[0], nrows=1)
    has_url_column = any(str(column).strip().lower() in {candidate.lower() for candidate in URL_COLUMN_CANDIDATES} for column in first.columns)
    if has_url_column:
        return load_dataset(path_list), "raw_url"
    return _load_engineered_dataset(path_list), "engineered_features"


def extract_training_matrix(data: pd.DataFrame, dataset_mode: str = "raw_url") -> Tuple[pd.DataFrame, pd.Series]:
    if dataset_mode == "engineered_features":
        feature_columns = [column for column in data.columns if column != "label"]
        x = data[feature_columns].copy()
        y = data["label"].astype(int).copy()
        if x.empty:
            raise ValueError("No engineered feature columns available for training.")
        return x, y

    rows = []
    labels = []
    for item in data.itertuples(index=False):
        try:
            extraction = build_feature_vector(item.url)
        except Exception:
            continue
        rows.append({name: extraction.features.get(name, 0.0) for name in FEATURE_COLUMNS})
        labels.append(int(item.label))
    if not rows:
        raise ValueError("No usable rows found after feature extraction.")
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS), pd.Series(labels)


def train_models(x: pd.DataFrame, y: pd.Series, dataset_mode: str = "raw_url") -> Dict:
    deps = _require_sklearn()
    split = deps["train_test_split"](x, y, test_size=0.25, random_state=42, stratify=y)
    x_train, x_test, y_train, y_test = split

    candidates = {
        "logistic_regression": deps["LogisticRegression"](max_iter=1000),
        "random_forest": deps["RandomForestClassifier"](n_estimators=250, random_state=42),
    }
    xgb = _optional_xgboost()
    if xgb is not None:
        candidates["xgboost"] = xgb(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
        )

    metrics = {}
    evaluation_curves = {}
    best_name = None
    best_model = None
    best_score = -1.0

    for name, model in candidates.items():
        model.fit(x_train, y_train)
        predictions = model.predict(x_test)
        probabilities = model.predict_proba(x_test)[:, 1]
        result = {
            "accuracy": float(deps["accuracy_score"](y_test, predictions)),
            "precision": float(deps["precision_score"](y_test, predictions, zero_division=0)),
            "recall": float(deps["recall_score"](y_test, predictions, zero_division=0)),
            "f1": float(deps["f1_score"](y_test, predictions, zero_division=0)),
            "roc_auc": float(deps["roc_auc_score"](y_test, probabilities)),
        }
        metrics[name] = result
        tn, fp, fn, tp = deps["confusion_matrix"](y_test, predictions, labels=[0, 1]).ravel()
        fpr, tpr, thresholds = deps["roc_curve"](y_test, probabilities)
        evaluation_curves[name] = {
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
            "roc_curve": {
                "fpr": [float(value) for value in fpr],
                "tpr": [float(value) for value in tpr],
                "thresholds": [float(value) for value in thresholds],
            },
        }
        if result["f1"] > best_score:
            best_name = name
            best_model = model
            best_score = result["f1"]

    return {
        "model_name": best_name,
        "model": best_model,
        "metrics": metrics,
        "threshold": 0.5,
        "feature_order": list(x.columns),
        "dataset_mode": dataset_mode,
        "training_rows": int(len(x)),
        "feature_count": int(len(x.columns)),
        "test_rows": int(len(x_test)),
        "evaluation_curves": evaluation_curves,
    }


def save_artifact(artifact: Dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        pickle.dump(artifact, handle)


def build_report(artifact: Dict, data_paths: Iterable[Path], artifact_path: Path) -> Dict:
    report = {
        "artifact_path": str(artifact_path),
        "dataset_mode": artifact["dataset_mode"],
        "model_name": artifact["model_name"],
        "threshold": artifact["threshold"],
        "training_rows": artifact["training_rows"],
        "test_rows": artifact["test_rows"],
        "feature_count": artifact["feature_count"],
        "feature_order": artifact["feature_order"],
        "data_paths": [str(path) for path in data_paths],
        "metrics": artifact["metrics"],
        "evaluation_curves": artifact["evaluation_curves"],
    }
    return report


def save_report(report: Dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def default_report_path(artifact_path: Path) -> Path:
    return artifact_path.with_name(f"{artifact_path.stem}_report.json")


def build_markdown_summary(report: Dict) -> str:
    lines = [
        "# Training Summary",
        "",
        f"- Selected model: `{report['model_name']}`",
        f"- Dataset mode: `{report['dataset_mode']}`",
        f"- Threshold: `{report['threshold']}`",
        f"- Training rows: `{report['training_rows']}`",
        f"- Test rows: `{report['test_rows']}`",
        f"- Feature count: `{report['feature_count']}`",
        "",
        "## Data Sources",
        "",
    ]
    for data_path in report["data_paths"]:
        lines.append(f"- `{data_path}`")

    lines.extend(
        [
            "",
            "## Model Comparison",
            "",
            "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for model_name, metrics in report["metrics"].items():
        lines.append(
            f"| {model_name} | {metrics['accuracy']:.4f} | {metrics['precision']:.4f} | "
            f"{metrics['recall']:.4f} | {metrics['f1']:.4f} | {metrics['roc_auc']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Feature Order",
            "",
            ", ".join(f"`{feature}`" for feature in report["feature_order"]),
            "",
        ]
    )
    return "\n".join(lines)


def save_markdown_summary(content: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def default_summary_path(artifact_path: Path) -> Path:
    return artifact_path.with_name(f"{artifact_path.stem}_summary.md")


def default_plot_dir(artifact_path: Path) -> Path:
    return artifact_path.with_name(f"{artifact_path.stem}_plots")


def build_plot_manifest(report: Dict, plot_dir: Path) -> Dict:
    manifest = {}
    for model_name in report["metrics"]:
        manifest[model_name] = {
            "confusion_matrix": str(plot_dir / f"{model_name}_confusion_matrix.png"),
            "roc_curve": str(plot_dir / f"{model_name}_roc_curve.png"),
        }
    return manifest


def save_evaluation_plots(report: Dict, plot_dir: Path) -> Dict:
    import os
    import matplotlib

    mpl_config_dir = (plot_dir / "mplconfig").resolve()
    mpl_config_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(mpl_config_dir))

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    plot_dir.mkdir(parents=True, exist_ok=True)
    sns.set_theme(style="whitegrid")

    manifest = build_plot_manifest(report, plot_dir)

    for model_name, paths in manifest.items():
        curve_data = report["evaluation_curves"][model_name]
        matrix = curve_data["confusion_matrix"]
        _render_confusion_matrix_png(model_name, matrix, Path(paths["confusion_matrix"]), plt, sns)

        roc = curve_data["roc_curve"]
        _render_roc_curve_png(
            model_name,
            roc,
            report["metrics"][model_name]["roc_auc"],
            Path(paths["roc_curve"]),
            plt,
            sns,
        )

    return manifest


def _render_confusion_matrix_png(model_name: str, matrix: Dict[str, int], output_path: Path, plt, sns) -> None:
    heatmap_data = [
        [int(matrix["tn"]), int(matrix["fp"])],
        [int(matrix["fn"]), int(matrix["tp"])],
    ]
    fig, ax = plt.subplots(figsize=(6.2, 4.8))
    sns.heatmap(
        heatmap_data,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Pred Legit", "Pred Phish"],
        yticklabels=["Actual Legit", "Actual Phish"],
        ax=ax,
    )
    ax.set_title(f"{model_name} Confusion Matrix")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def _render_roc_curve_png(model_name: str, roc: Dict[str, list], auc_value: float, output_path: Path, plt, _sns) -> None:
    fig, ax = plt.subplots(figsize=(6.8, 4.8))
    ax.plot(roc["fpr"], roc["tpr"], color="#1f77b4", linewidth=2.2, label=f"ROC (AUC={auc_value:.4f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1.2, label="Random baseline")
    ax.set_title(f"{model_name} ROC Curve")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing detection models.")
    parser.add_argument("--data", nargs="+", required=True, help="CSV file(s) with raw URL rows or engineered features plus labels.")
    parser.add_argument("--artifact", default=str(DEFAULT_ARTIFACT_PATH), help="Output pickle artifact path.")
    parser.add_argument("--report", default=None, help="Optional JSON report path. Defaults next to the artifact.")
    parser.add_argument("--summary", default=None, help="Optional Markdown summary path. Defaults next to the artifact.")
    parser.add_argument("--plot-dir", default=None, help="Optional directory for confusion matrix and ROC curve images.")
    args = parser.parse_args()

    data_paths = [Path(item) for item in args.data]
    artifact_path = Path(args.artifact)
    report_path = Path(args.report) if args.report else default_report_path(artifact_path)
    summary_path = Path(args.summary) if args.summary else default_summary_path(artifact_path)
    plot_dir = Path(args.plot_dir) if args.plot_dir else default_plot_dir(artifact_path)

    dataset, dataset_mode = load_training_input(data_paths)
    x, y = extract_training_matrix(dataset, dataset_mode=dataset_mode)
    artifact = train_models(x, y, dataset_mode=dataset_mode)
    save_artifact(artifact, artifact_path)
    report = build_report(artifact, data_paths, artifact_path)
    plot_manifest = save_evaluation_plots(report, plot_dir)
    report["plot_files"] = plot_manifest
    save_report(report, report_path)
    save_markdown_summary(build_markdown_summary(report), summary_path)

    print(f"Saved {artifact['model_name']} artifact to {args.artifact}")
    print(f"report_path {report_path}")
    print(f"summary_path {summary_path}")
    print(f"plot_dir {plot_dir}")
    print(f"dataset_mode {artifact['dataset_mode']}")
    for model_name, metrics in artifact["metrics"].items():
        print(model_name, metrics)


if __name__ == "__main__":
    main()
