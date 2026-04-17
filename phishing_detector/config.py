from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_ARTIFACT_PATH = Path(
    os.getenv("MODEL_ARTIFACT_PATH", str(DATA_DIR / "model_artifact.pkl"))
).expanduser()
REQUEST_TIMEOUT_SECONDS = 5
HTTP_USER_AGENT = "PhishingDetectorMVP/1.0"
REPUTATION_LOOKUP_TIMEOUT_SECONDS = 4
ENABLE_REPUTATION_LOOKUPS = os.getenv("ENABLE_REPUTATION_LOOKUPS", "1").strip().lower() not in {"0", "false", "no"}
ENABLE_NETWORK_LOOKUPS = os.getenv("ENABLE_NETWORK_LOOKUPS", "1").strip().lower() not in {"0", "false", "no"}
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "").strip()
API_REQUIRE_AUTH = os.getenv("API_REQUIRE_AUTH", "1").strip().lower() not in {"0", "false", "no"}
API_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("API_RATE_LIMIT_WINDOW_SECONDS", "60"))
API_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("API_RATE_LIMIT_MAX_REQUESTS", "30"))

SUSPICIOUS_TLDS = {
    "zip",
    "review",
    "country",
    "kim",
    "work",
    "support",
    "click",
    "top",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
}

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "reddit.com",
    "wikipedia.org",
    "youtube.com",
}

PHISHING_KEYWORDS = {
    "login",
    "verify",
    "verify account",
    "update",
    "update payment",
    "banking",
    "confirm",
    "confirm identity",
    "secure",
    "security alert",
    "account suspended",
    "reset password",
    "otp",
    "aadhar",
    "pan",
    "wallet",
    "gift card",
}
