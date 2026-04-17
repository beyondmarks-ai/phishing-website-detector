from __future__ import annotations

from .config import (
    DEFAULT_ARTIFACT_PATH,
    ENABLE_NETWORK_LOOKUPS,
    ENABLE_REPUTATION_LOOKUPS,
    HTTP_USER_AGENT,
    PHISHING_KEYWORDS,
    REQUEST_TIMEOUT_SECONDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
)


def build_settings_view() -> dict:
    return {
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "http_user_agent": HTTP_USER_AGENT,
        "default_artifact_path": str(DEFAULT_ARTIFACT_PATH),
        "enable_network_lookups": ENABLE_NETWORK_LOOKUPS,
        "enable_reputation_lookups": ENABLE_REPUTATION_LOOKUPS,
        "suspicious_tlds": sorted(SUSPICIOUS_TLDS),
        "shortener_domains": sorted(SHORTENER_DOMAINS),
        "phishing_keywords": sorted(PHISHING_KEYWORDS),
        "counts": {
            "suspicious_tlds": len(SUSPICIOUS_TLDS),
            "shortener_domains": len(SHORTENER_DOMAINS),
            "phishing_keywords": len(PHISHING_KEYWORDS),
        },
    }
