from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import httpx
import tldextract
import validators

from pipeline.utils import DEFAULT_TIMEOUT, ensure_runtime_dirs, logger

SHORTENER_HOSTS = {"bit.ly", "t.co", "goo.gl", "t.me"}
BANK_KEYWORDS = [
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "paytm",
    "aadhaar",
    "epfo",
    "itr",
    "nse",
    "bse",
    "uidai",
    "gov.in",
    "nic.in",
    "india",
]
BETTING_KEYWORDS = ["bet", "cricket", "ipl", "lottery", "casino", "rummy", "teen patti", "play win"]
APK_KEYWORDS = [".apk", "android", "download", "install"]


@dataclass
class DomainEntry:
    domain: str
    url: str
    original: str
    priority_score: int
    source_host: str
    from_shortener: bool = False

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "url": self.url,
            "original": self.original,
            "priority_score": self.priority_score,
            "source_host": self.source_host,
            "from_shortener": self.from_shortener,
        }


def _strip_wrapping(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _ensure_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"https://{value}"


def _apex_domain(value: str) -> str | None:
    extract = tldextract.extract(value)
    if not extract.domain or not extract.suffix:
        return None
    return ".".join(part for part in (extract.domain, extract.suffix) if part)


def _normalise_candidate(raw_line: str) -> tuple[str, str] | None:
    cleaned = _strip_wrapping(raw_line)
    if not cleaned or cleaned.startswith("#"):
        return None

    url = _ensure_url(cleaned)
    parsed = urlparse(url)
    if not parsed.netloc:
        return None

    apex = _apex_domain(parsed.netloc)
    if not apex or not validators.domain(apex):
        return None

    safe_path = parsed.path.rstrip("/")
    rebuilt = f"https://{parsed.netloc.lower()}{safe_path}"
    if parsed.query:
        rebuilt = f"{rebuilt}?{parsed.query}"
    return apex.lower(), rebuilt


def _is_shortener(host: str) -> bool:
    host = host.lower().split(":")[0]
    return host in SHORTENER_HOSTS


def resolve_shortened_url(url: str) -> tuple[str, bool]:
    parsed = urlparse(url)
    if not _is_shortener(parsed.netloc):
        return url, False

    headers = {"User-Agent": "Mozilla/5.0"}
    with httpx.Client(follow_redirects=True, timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            response = client.get(url)
            return str(response.url), True
        except Exception as exc:
            logger.warning(f"[yellow]Shortener resolution failed for {url}: {exc}[/yellow]")
            return url, True


def calculate_priority_score(domain: str, url: str, registration_date: str | None = None) -> int:
    score = 0
    domain_lower = domain.lower()
    url_lower = url.lower()

    if any(keyword in domain_lower for keyword in BANK_KEYWORDS):
        score += 35

    if any(keyword in url_lower for keyword in APK_KEYWORDS):
        score += 15

    if any(keyword in url_lower for keyword in BETTING_KEYWORDS):
        score += 20

    if domain_lower.endswith(".in") or domain_lower.endswith(".co.in"):
        score += 10

    if registration_date:
        from datetime import date

        try:
            registered_on = date.fromisoformat(registration_date[:10])
            age_days = (date.today() - registered_on).days
            if age_days < 30:
                score += 20
            elif age_days > 365 * 2:
                score -= 10
        except ValueError:
            pass

    return max(0, min(score, 100))


def load_and_normalise(input_file: str | Path, max_domains: int | None = None) -> list[dict]:
    ensure_runtime_dirs()
    source_path = Path(input_file)
    if not source_path.is_absolute():
        source_path = Path.cwd() / source_path
    if not source_path.exists():
        raise FileNotFoundError(f"Input file not found: {source_path}")

    seen: set[str] = set()
    entries: list[DomainEntry] = []

    for line in source_path.read_text(encoding="utf-8").splitlines():
        normalised = _normalise_candidate(line)
        if normalised is None:
            continue

        _, normalised_url = normalised
        resolved_url, from_shortener = resolve_shortened_url(normalised_url)
        reparsed = _normalise_candidate(resolved_url)
        if reparsed is None:
            continue

        domain, final_url = reparsed
        if domain in seen:
            continue
        seen.add(domain)

        source_host = urlparse(final_url).netloc.lower()
        score = calculate_priority_score(domain, final_url)
        entries.append(
            DomainEntry(
                domain=domain,
                url=final_url,
                original=_strip_wrapping(line),
                priority_score=score,
                source_host=source_host,
                from_shortener=from_shortener,
            )
        )

    entries.sort(key=lambda item: item.priority_score, reverse=True)
    if max_domains is not None:
        entries = entries[:max_domains]
    return [entry.as_dict() for entry in entries]
