from __future__ import annotations

import ipaddress
import importlib
import json
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .config import (
    ENABLE_NETWORK_LOOKUPS,
    ENABLE_REPUTATION_LOOKUPS,
    HTTP_USER_AGENT,
    PHISHING_KEYWORDS,
    REPUTATION_LOOKUP_TIMEOUT_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    TRUSTED_DOMAINS,
)

SUSPICIOUS_BRANDS = ("paypal", "google", "microsoft", "amazon", "apple", "bank", "instagram", "facebook")
TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]{2,}")

try:
    from nltk.stem import PorterStemmer
except Exception:  # pragma: no cover - optional dependency at runtime
    PorterStemmer = None

_STEMMER = PorterStemmer() if PorterStemmer is not None else None
_STEMMED_KEYWORDS = set()
if _STEMMER is not None:
    _STEMMED_KEYWORDS = {_STEMMER.stem(token) for keyword in PHISHING_KEYWORDS for token in TOKEN_PATTERN.findall(keyword.lower())}


@dataclass
class FeatureExtractionResult:
    normalized_url: str
    features: Dict[str, float]
    warnings: List[str] = field(default_factory=list)
    explanation_signals: List[str] = field(default_factory=list)


class _SignalHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_fields = 0
        self.iframes = 0
        self.scripts = 0
        self.links_internal = 0
        self.links_external = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_dict = dict(attrs)
        if tag == "form":
            self.forms += 1
        elif tag == "iframe":
            self.iframes += 1
        elif tag == "script":
            self.scripts += 1
        elif tag == "input" and attrs_dict.get("type", "").lower() == "password":
            self.password_fields += 1
        elif tag == "a":
            href = attrs_dict.get("href", "")
            if href.startswith("http://") or href.startswith("https://"):
                self.links_external += 1
            elif href:
                self.links_internal += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def normalize_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("URL is required.")
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = f"http://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    return value


def _hostname(parsed) -> str:
    return (parsed.hostname or "").lower()


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _digit_ratio(value: str) -> float:
    return sum(ch.isdigit() for ch in value) / max(len(value), 1)


def _subdomain_count(hostname: str) -> int:
    parts = [part for part in hostname.split(".") if part]
    return max(len(parts) - 2, 0)


def _is_trusted_domain(hostname: str) -> bool:
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in TRUSTED_DOMAINS)


def _suspicious_keyword_count(value: str) -> int:
    lowered = value.lower()
    return sum(1 for keyword in PHISHING_KEYWORDS if keyword in lowered)


def _stemmed_keyword_count(value: str) -> int:
    if _STEMMER is None or not _STEMMED_KEYWORDS:
        return 0
    stems = {_STEMMER.stem(token.lower()) for token in TOKEN_PATTERN.findall(value.lower())}
    return sum(1 for keyword in _STEMMED_KEYWORDS if keyword in stems)


def _fetch_html(normalized_url: str) -> str:
    request = Request(normalized_url, headers={"User-Agent": HTTP_USER_AGENT})
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            return ""
        return response.read(200_000).decode("utf-8", errors="ignore")


def _ssl_days_remaining(hostname: str) -> Optional[int]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()
            if not cert or "notAfter" not in cert:
                return None
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            remaining = max(expires - time.time(), 0)
            return int(remaining // 86400)


def _urlhaus_reputation_hit(normalized_url: str) -> Optional[bool]:
    body = urlencode({"url": normalized_url}).encode("utf-8")
    request = Request(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data=body,
        headers={
            "User-Agent": HTTP_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urlopen(request, timeout=REPUTATION_LOOKUP_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
    status = str(payload.get("query_status", "")).lower()
    if not status:
        return None
    if status in {"ok", "hit"}:
        return True
    if status in {"no_results", "not_found"}:
        return False
    return None


def _domain_age_days(hostname: str) -> Optional[int]:
    try:
        whois_module = importlib.import_module("whois")
    except Exception:
        return None

    try:
        record = whois_module.whois(hostname)
    except Exception:
        return None

    creation_date = getattr(record, "creation_date", None)
    created_at = _coerce_creation_datetime(creation_date)
    if created_at is None:
        return None
    now = datetime.now(timezone.utc)
    return max((now - created_at).days, 0)


def _coerce_creation_datetime(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            parsed = _coerce_creation_datetime(item)
            if parsed is not None:
                return parsed
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        cleaned = value.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
        ):
            try:
                parsed = datetime.strptime(cleaned, fmt)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "question_mark_count",
    "equals_count",
    "at_symbol_present",
    "https_scheme",
    "ip_address_host",
    "digit_ratio",
    "url_entropy",
    "suspicious_tld",
    "shortener_domain",
    "phishing_keyword_count_url",
    "brand_in_subdomain",
    "dns_resolves",
    "ssl_available",
    "ssl_days_remaining",
    "domain_age_days",
    "page_fetch_success",
    "form_count",
    "password_field_count",
    "iframe_count",
    "script_count",
    "external_link_ratio",
    "title_brand_mismatch",
    "phishing_keyword_count_content",
    "stemmed_keyword_count_content",
    "reputation_blacklist_hit",
]


def build_feature_vector(raw_url: str) -> FeatureExtractionResult:
    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    hostname = _hostname(parsed)
    url_value = normalized_url.lower()
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    trusted_domain = _is_trusted_domain(hostname)

    features: Dict[str, float] = {
        "url_length": float(len(normalized_url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(parsed.path or "")),
        "query_length": float(len(parsed.query or "")),
        "subdomain_count": float(_subdomain_count(hostname)),
        "dot_count": float(normalized_url.count(".")),
        "hyphen_count": float(normalized_url.count("-")),
        "underscore_count": float(normalized_url.count("_")),
        "slash_count": float(normalized_url.count("/")),
        "question_mark_count": float(normalized_url.count("?")),
        "equals_count": float(normalized_url.count("=")),
        "at_symbol_present": float("@" in normalized_url),
        "https_scheme": float(parsed.scheme == "https"),
        "ip_address_host": float(_is_ip_host(hostname)),
        "digit_ratio": _digit_ratio(normalized_url),
        "url_entropy": _shannon_entropy(normalized_url),
        "suspicious_tld": float(tld in SUSPICIOUS_TLDS),
        "shortener_domain": float(hostname in SHORTENER_DOMAINS),
        "phishing_keyword_count_url": float(_suspicious_keyword_count(url_value)),
        "brand_in_subdomain": float(any(brand in hostname.split(".")[0] for brand in SUSPICIOUS_BRANDS if hostname)),
        "dns_resolves": 0.0,
        "ssl_available": 0.0,
        "ssl_days_remaining": 0.0,
        "domain_age_days": 0.0,
        "page_fetch_success": 0.0,
        "form_count": 0.0,
        "password_field_count": 0.0,
        "iframe_count": 0.0,
        "script_count": 0.0,
        "external_link_ratio": 0.0,
        "title_brand_mismatch": 0.0,
        "phishing_keyword_count_content": 0.0,
        "stemmed_keyword_count_content": 0.0,
        "reputation_blacklist_hit": 0.0,
        "trusted_domain": float(trusted_domain),
    }
    warnings: List[str] = []
    signals: List[str] = []

    if ENABLE_NETWORK_LOOKUPS:
        try:
            socket.gethostbyname(hostname)
            features["dns_resolves"] = 1.0
        except Exception:
            warnings.append("DNS lookup failed.")
            signals.append("Domain did not resolve during analysis.")

        if parsed.scheme == "https" and features["dns_resolves"]:
            try:
                remaining = _ssl_days_remaining(hostname)
                features["ssl_available"] = 1.0 if remaining is not None else 0.0
                features["ssl_days_remaining"] = float(remaining or 0.0)
                if remaining is not None and remaining < 15:
                    signals.append("TLS certificate is close to expiry.")
            except Exception:
                warnings.append("TLS certificate lookup failed.")

        age_days = _domain_age_days(hostname)
        if age_days is not None:
            features["domain_age_days"] = float(age_days)
            if age_days < 60:
                signals.append("Domain appears recently registered.")
        else:
            warnings.append("WHOIS/domain age lookup unavailable.")

        try:
            html = _fetch_html(normalized_url)
            if html:
                parser = _SignalHTMLParser()
                parser.feed(html)
                features["page_fetch_success"] = 1.0
                features["form_count"] = float(parser.forms)
                features["password_field_count"] = float(parser.password_fields)
                features["iframe_count"] = float(parser.iframes)
                features["script_count"] = float(parser.scripts)
                total_links = parser.links_internal + parser.links_external
                features["external_link_ratio"] = parser.links_external / max(total_links, 1)
                content_keywords = _suspicious_keyword_count(html.lower())
                features["phishing_keyword_count_content"] = float(content_keywords)
                features["stemmed_keyword_count_content"] = float(_stemmed_keyword_count(html))
                if parser.title and hostname:
                    title = parser.title.lower()
                    domain_token = hostname.split(".")[-2] if "." in hostname else hostname
                    features["title_brand_mismatch"] = float(domain_token not in title and any(brand in title for brand in SUSPICIOUS_BRANDS))
            else:
                warnings.append("Remote page was reachable but not HTML.")
        except Exception:
            warnings.append("Page content fetch failed.")

        if ENABLE_REPUTATION_LOOKUPS:
            try:
                reputation_hit = _urlhaus_reputation_hit(normalized_url)
                if reputation_hit is True:
                    features["reputation_blacklist_hit"] = 1.0
                    signals.append("External URL reputation feed marked this URL as malicious.")
            except Exception:
                warnings.append("External reputation lookup unavailable.")
    else:
        warnings.append("Network lookups disabled by configuration.")

    if features["at_symbol_present"]:
        signals.append("URL contains '@', which is commonly used to obfuscate links.")
    if features["ip_address_host"]:
        signals.append("URL uses an IP address instead of a domain name.")
    if features["shortener_domain"]:
        signals.append("URL uses a shortening service.")
    if features["suspicious_tld"]:
        signals.append("Domain uses a suspicious top-level domain.")
    if features["subdomain_count"] >= 3:
        signals.append("URL contains many subdomains.")
    if features["url_entropy"] > 4.2 and not trusted_domain:
        signals.append("URL appears highly random or encoded.")
    if features["password_field_count"] > 0 and features["phishing_keyword_count_content"] > 0:
        signals.append("Page combines credential inputs with phishing-related language.")
    if features["stemmed_keyword_count_content"] >= 3:
        signals.append("Content includes multiple stemmed phishing terms.")
    if features["title_brand_mismatch"]:
        signals.append("Page title references a brand that does not match the domain.")
    if features["external_link_ratio"] > 0.8:
        signals.append("Most links on the page point to external destinations.")
    if features["reputation_blacklist_hit"]:
        signals.append("URL appears in an external phishing/malware reputation feed.")

    return FeatureExtractionResult(
        normalized_url=normalized_url,
        features=features,
        warnings=warnings,
        explanation_signals=signals,
    )
