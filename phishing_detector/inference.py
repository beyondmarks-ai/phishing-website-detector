from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import pandas as pd

from .config import DEFAULT_ARTIFACT_PATH
from .feature_extraction import FEATURE_COLUMNS, FeatureExtractionResult, build_feature_vector


@dataclass
class AnalysisResult:
    normalized_url: str
    verdict: str
    risk_score: int
    probability: float
    explanation_items: List[str]
    warnings: List[str]
    features: Dict[str, float]
    suspicious_signals: List[str] = field(default_factory=list)
    reassuring_signals: List[str] = field(default_factory=list)
    feature_sections: List[Dict] = field(default_factory=list)


def load_artifact(artifact_path: Path | None = None) -> Dict:
    artifact_file = Path(artifact_path or DEFAULT_ARTIFACT_PATH)
    if not artifact_file.exists():
        raise FileNotFoundError(f"Model artifact not found at {artifact_file}")
    with artifact_file.open("rb") as handle:
        loaded = pickle.load(handle)
    return _normalize_artifact_schema(loaded)


def _normalize_artifact_schema(artifact: Dict) -> Dict:
    if not isinstance(artifact, dict):
        raise ValueError("Unsupported artifact format: expected a dictionary payload.")

    # Native training artifact format used by this project.
    if "dataset_mode" in artifact and "model" in artifact:
        return artifact

    # Colab export bundle format: {"model": ..., "feature_columns": [...], ...}
    if "model" in artifact and "feature_columns" in artifact:
        return {
            "model_name": artifact.get("model_name", "colab_bundle_model"),
            "model": artifact["model"],
            "metrics": artifact.get("metrics", {}),
            "threshold": float(artifact.get("threshold", 0.5)),
            "feature_order": list(artifact["feature_columns"]),
            "dataset_mode": artifact.get("dataset_mode", "engineered_features"),
            "training_rows": int(artifact.get("training_rows", 0)),
            "feature_count": int(len(artifact["feature_columns"])),
            "test_rows": int(artifact.get("test_rows", 0)),
            "evaluation_curves": artifact.get("evaluation_curves", {}),
        }

    raise ValueError(
        "Unsupported artifact schema. Expected project artifact or a bundle with feature_columns."
    )


def _feature_row(features: Dict[str, float], feature_order: List[str]) -> pd.DataFrame:
    row = {name: float(features.get(name, 0.0)) for name in feature_order}
    return pd.DataFrame([row], columns=feature_order)


def _heuristic_adjustment(extraction: FeatureExtractionResult) -> float:
    suspicious = 0.0
    suspicious += 0.07 if extraction.features["ip_address_host"] else 0.0
    suspicious += 0.06 if extraction.features["shortener_domain"] else 0.0
    suspicious += 0.04 if extraction.features["suspicious_tld"] else 0.0
    suspicious += 0.08 if extraction.features["password_field_count"] > 0 else 0.0
    suspicious += 0.08 if extraction.features["title_brand_mismatch"] else 0.0
    suspicious += 0.05 if extraction.features["external_link_ratio"] > 0.8 else 0.0
    suspicious += 0.1 if extraction.features.get("reputation_blacklist_hit", 0.0) else 0.0
    suspicious += min(extraction.features["phishing_keyword_count_content"] * 0.02, 0.1)
    suspicious += min(extraction.features.get("stemmed_keyword_count_content", 0.0) * 0.01, 0.05)
    suspicious -= 0.05 if extraction.features["https_scheme"] and extraction.features["ssl_available"] else 0.0
    return suspicious


def _trusted_domain_probability_cap(features: Dict[str, float]) -> float | None:
    if not features.get("trusted_domain", 0.0):
        return None

    high_risk_overrides = [
        features.get("reputation_blacklist_hit", 0.0),
        features.get("ip_address_host", 0.0),
        features.get("suspicious_tld", 0.0),
        features.get("shortener_domain", 0.0),
        features.get("password_field_count", 0.0),
        features.get("title_brand_mismatch", 0.0),
    ]
    if any(value > 0 for value in high_risk_overrides):
        return None

    return 0.35


def _build_feature_sections(features: Dict[str, float]) -> List[Dict]:
    return [
        {
            "title": "URL Signals",
            "rows": [
                {"label": "URL Length", "value": int(features["url_length"])},
                {"label": "Subdomain Count", "value": int(features["subdomain_count"])},
                {"label": "Digit Ratio", "value": f"{features['digit_ratio']:.3f}"},
                {"label": "Entropy", "value": f"{features['url_entropy']:.3f}"},
                {"label": "Contains @", "value": "Yes" if features["at_symbol_present"] else "No"},
                {"label": "Shortener Domain", "value": "Yes" if features["shortener_domain"] else "No"},
                {"label": "Suspicious TLD", "value": "Yes" if features["suspicious_tld"] else "No"},
                {"label": "IP Address Host", "value": "Yes" if features["ip_address_host"] else "No"},
            ],
        },
        {
            "title": "Domain Signals",
            "rows": [
                {"label": "HTTPS Scheme", "value": "Yes" if features["https_scheme"] else "No"},
                {"label": "DNS Resolves", "value": "Yes" if features["dns_resolves"] else "No"},
                {"label": "TLS Available", "value": "Yes" if features["ssl_available"] else "No"},
                {"label": "TLS Days Remaining", "value": int(features["ssl_days_remaining"])},
                {"label": "Domain Age (days)", "value": int(features["domain_age_days"])},
                {"label": "Brand In Subdomain", "value": "Yes" if features["brand_in_subdomain"] else "No"},
            ],
        },
        {
            "title": "Content Signals",
            "rows": [
                {"label": "Page Fetch Success", "value": "Yes" if features["page_fetch_success"] else "No"},
                {"label": "Forms", "value": int(features["form_count"])},
                {"label": "Password Fields", "value": int(features["password_field_count"])},
                {"label": "Iframes", "value": int(features["iframe_count"])},
                {"label": "Scripts", "value": int(features["script_count"])},
                {"label": "External Link Ratio", "value": f"{features['external_link_ratio']:.3f}"},
                {"label": "Title/Brand Mismatch", "value": "Yes" if features["title_brand_mismatch"] else "No"},
                {"label": "Content Keyword Hits", "value": int(features["phishing_keyword_count_content"])},
                {"label": "Stemmed Keyword Hits", "value": int(features.get("stemmed_keyword_count_content", 0.0))},
                {"label": "Blacklist Reputation Hit", "value": "Yes" if features.get("reputation_blacklist_hit", 0.0) else "No"},
            ],
        },
    ]


def _build_reassuring_signals(features: Dict[str, float]) -> List[str]:
    reassuring = []
    if features["https_scheme"] and features["ssl_available"]:
        reassuring.append("The URL uses HTTPS and a TLS certificate was available during analysis.")
    if features["dns_resolves"]:
        reassuring.append("The domain resolved successfully during DNS lookup.")
    if not features["shortener_domain"]:
        reassuring.append("The URL is not using a known shortening service.")
    if not features["ip_address_host"]:
        reassuring.append("The URL uses a hostname instead of a raw IP address.")
    if not features["title_brand_mismatch"] and features["page_fetch_success"]:
        reassuring.append("The fetched page title did not show an obvious brand mismatch.")
    if not features.get("reputation_blacklist_hit", 0.0):
        reassuring.append("The URL was not found in the external reputation feed lookup.")
    if features.get("trusted_domain", 0.0):
        reassuring.append("The hostname belongs to a trusted platform domain list.")
    return reassuring[:5]


def analyze_url(raw_url: str, artifact_path: Path | None = None) -> AnalysisResult:
    artifact = load_artifact(artifact_path)
    dataset_mode = artifact.get("dataset_mode", "raw_url")
    if dataset_mode != "raw_url":
        raise ValueError(
            "The loaded model was trained on engineered features and is not compatible with live URL analysis in this app. "
            "Use a raw-URL artifact from `python -m phishing_detector.training --data <csv_with_url_and_label> --artifact data/model_artifact.pkl`."
        )
    extraction = build_feature_vector(raw_url)
    feature_order = artifact.get("feature_order", FEATURE_COLUMNS)
    model = artifact["model"]
    row = _feature_row(extraction.features, feature_order)
    probability = float(model.predict_proba(row)[0][1])
    probability = min(max(probability + _heuristic_adjustment(extraction), 0.0), 1.0)
    trusted_cap = _trusted_domain_probability_cap(extraction.features)
    if trusted_cap is not None:
        probability = min(probability, trusted_cap)
    risk_score = int(round(probability * 100))
    verdict = "Phishing" if probability >= artifact.get("threshold", 0.5) else "Legitimate"
    explanation_items = list(dict.fromkeys(extraction.explanation_signals))[:6]
    if not explanation_items:
        explanation_items.append("No strong phishing indicators were triggered by the current checks.")
    suspicious_signals = explanation_items
    reassuring_signals = _build_reassuring_signals(extraction.features)
    return AnalysisResult(
        normalized_url=extraction.normalized_url,
        verdict=verdict,
        risk_score=risk_score,
        probability=probability,
        explanation_items=explanation_items,
        warnings=extraction.warnings,
        features=extraction.features,
        suspicious_signals=suspicious_signals,
        reassuring_signals=reassuring_signals,
        feature_sections=_build_feature_sections(extraction.features),
    )
