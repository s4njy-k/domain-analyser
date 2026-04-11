from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import httpx

from pipeline.ingest import calculate_priority_score
from pipeline.utils import (
    DEFAULT_TIMEOUT,
    generic_limiter,
    logger,
    rdap_limiter,
    urlscan_limiter,
    vt_limiter,
)

DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; DomainAnalyser/1.0)"}


def _default_registration(error: str | None = None) -> dict[str, Any]:
    payload = {
        "registrar": None,
        "registered": None,
        "expires": None,
        "nameservers": [],
        "status": [],
        "country": None,
    }
    if error:
        payload["error"] = error
    return payload


def _default_ti() -> dict[str, Any]:
    return {
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_total": 0,
        "vt_categories": {},
        "vt_reputation": None,
        "vt_last_analysis_date": None,
        "urlscan_verdict": None,
        "urlscan_score": None,
        "urlscan_screenshot_url": None,
        "urlscan_page_title": None,
        "urlscan_page_ip": None,
        "urlscan_page_country": None,
        "urlhaus_listed": False,
        "urlhaus_threat": None,
        "urlhaus_tags": [],
        "urlhaus_status": None,
        "gsb_threats": [],
        "otx_pulse_count": 0,
        "otx_pulses": [],
        "phishtank_verified": False,
        "phishtank_in_database": False,
        "abuseipdb_score": None,
        "abuseipdb_isp": None,
        "abuseipdb_usage_type": None,
        "abuseipdb_country": None,
        "abuseipdb_total_reports": None,
        "abuseipdb_last_reported_at": None,
        "errors": {},
    }


async def rdap_lookup(domain: str) -> dict:
    await rdap_limiter.acquire()
    url = f"https://rdap.org/domain/{domain}"
    async with httpx.AsyncClient(timeout=15, headers=DEFAULT_HEADERS) as client:
        try:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
            result = _default_registration()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    result["registered"] = (event.get("eventDate") or "")[:10] or None
                elif event.get("eventAction") == "expiration":
                    result["expires"] = (event.get("eventDate") or "")[:10] or None
            result["nameservers"] = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")]
            result["status"] = data.get("status", [])
            for entity in data.get("entities", []):
                for role in entity.get("roles", []):
                    if role == "registrar":
                        vcard = entity.get("vcardArray", [[], []])[1]
                        for field in vcard:
                            if field and field[0] == "fn":
                                result["registrar"] = field[3]
                    if role == "registrant":
                        vcard = entity.get("vcardArray", [[], []])[1]
                        for field in vcard:
                            if field and field[0] == "adr" and isinstance(field[3], list) and field[3]:
                                result["country"] = field[3][-1]
            return result
        except Exception as exc:
            return _default_registration(str(exc))


async def virustotal_lookup(domain: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {"error": "API unavailable"}
    await vt_limiter.acquire()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {**DEFAULT_HEADERS, "x-apikey": api_key}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            return {
                "vt_malicious": int(stats.get("malicious", 0) or 0),
                "vt_suspicious": int(stats.get("suspicious", 0) or 0),
                "vt_total": int(sum(value for value in stats.values() if isinstance(value, int))),
                "vt_categories": attributes.get("categories", {}) or {},
                "vt_reputation": attributes.get("reputation"),
                "vt_last_analysis_date": attributes.get("last_analysis_date"),
            }
        except Exception as exc:
            return {"error": str(exc)}


async def urlscan_lookup(domain: str, url: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {"error": "API unavailable"}
    await urlscan_limiter.acquire()
    search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=3"
    headers = {**DEFAULT_HEADERS, "API-Key": api_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            search_response = await client.get(search_url)
            search_response.raise_for_status()
            results = search_response.json().get("results", [])
            if results:
                result = results[0]
                verdicts = result.get("verdicts", {}).get("overall", {})
                page = result.get("page", {})
                return {
                    "urlscan_verdict": "malicious" if verdicts.get("malicious") else "benign",
                    "urlscan_score": verdicts.get("score"),
                    "urlscan_screenshot_url": result.get("screenshot"),
                    "urlscan_page_title": page.get("title"),
                    "urlscan_page_ip": page.get("ip"),
                    "urlscan_page_country": page.get("country"),
                }

            submit_response = await client.post(
                "https://urlscan.io/api/v1/scan/",
                json={"url": url, "visibility": "unlisted"},
            )
            submit_response.raise_for_status()
            uuid = submit_response.json().get("uuid")
            if not uuid:
                return {"error": "No UUID returned"}

            for _ in range(6):
                await asyncio.sleep(10)
                result_response = await client.get(f"https://urlscan.io/api/v1/result/{uuid}/")
                if result_response.status_code == 404:
                    continue
                result_response.raise_for_status()
                result = result_response.json()
                verdicts = result.get("verdicts", {}).get("overall", {})
                page = result.get("page", {})
                return {
                    "urlscan_verdict": "malicious" if verdicts.get("malicious") else "benign",
                    "urlscan_score": verdicts.get("score"),
                    "urlscan_screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
                    "urlscan_page_title": page.get("title"),
                    "urlscan_page_ip": page.get("ip"),
                    "urlscan_page_country": page.get("country"),
                }
            return {"error": "Timed out waiting for URLScan result"}
        except Exception as exc:
            return {"error": str(exc)}


async def urlhaus_lookup(url: str) -> dict[str, Any]:
    await generic_limiter.acquire()
    payload = {"url": url}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=DEFAULT_HEADERS) as client:
        try:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded", **DEFAULT_HEADERS},
            )
            response.raise_for_status()
            data = response.json()
            return {
                "urlhaus_listed": data.get("query_status") not in {"not_found", "no_results"},
                "urlhaus_threat": data.get("threat"),
                "urlhaus_tags": data.get("tags") or [],
                "urlhaus_status": data.get("url_status"),
                "urlhaus_date_added": data.get("date_added"),
            }
        except Exception as exc:
            return {"error": str(exc)}


async def google_safe_browsing_lookup(url: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {"error": "API unavailable"}
    await generic_limiter.acquire()
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "domain-analyser", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=DEFAULT_HEADERS) as client:
        try:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            matches = response.json().get("matches", [])
            return {"gsb_threats": [match.get("threatType") for match in matches if match.get("threatType")]}
        except Exception as exc:
            return {"error": str(exc)}


async def otx_lookup(domain: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {"error": "API unavailable"}
    await generic_limiter.acquire()
    headers = {**DEFAULT_HEADERS, "X-OTX-API-KEY": api_key}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            response = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
            response.raise_for_status()
            pulse_info = response.json().get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            return {
                "otx_pulse_count": pulse_info.get("count", 0),
                "otx_pulses": [
                    {
                        "name": pulse.get("name"),
                        "description": pulse.get("description"),
                        "tags": pulse.get("tags", []),
                        "tlp": pulse.get("TLP"),
                        "created": pulse.get("created"),
                    }
                    for pulse in pulses[:10]
                ],
            }
        except Exception as exc:
            return {"error": str(exc)}


async def phishtank_lookup(url: str) -> dict[str, Any]:
    await generic_limiter.acquire()
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=DEFAULT_HEADERS) as client:
        try:
            response = await client.post(
                "http://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"},
                headers={"Content-Type": "application/x-www-form-urlencoded", **DEFAULT_HEADERS},
            )
            response.raise_for_status()
            text = response.text.strip()
            if text.startswith("phishtank/"):
                text = text.split("\n", 1)[-1]
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else httpx.Response(200, text=text).json()
            results = data.get("results", {})
            return {
                "phishtank_in_database": bool(results.get("in_database")),
                "phishtank_verified": bool(results.get("verified") and results.get("valid")),
            }
        except Exception as exc:
            return {"error": str(exc)}


def _resolve_dns_records_sync(domain: str) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 5
    resolver.lifetime = 8
    records: dict[str, list[str]] = {"A": [], "MX": [], "NS": [], "TXT": []}
    for record_type in ("A", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(domain, record_type)
            if record_type == "TXT":
                records[record_type] = ["".join(part.decode() for part in answer.strings) for answer in answers]
            else:
                records[record_type] = [str(answer).rstrip(".") for answer in answers]
        except Exception:
            records[record_type] = []
    return records


async def dns_lookup(domain: str) -> dict[str, list[str]]:
    return await asyncio.to_thread(_resolve_dns_records_sync, domain)


async def resolve_first_ip(domain: str) -> str | None:
    records = await dns_lookup(domain)
    return (records.get("A") or [None])[0]


async def abuseipdb_lookup(domain: str, api_key: str | None) -> dict[str, Any]:
    if not api_key:
        return {"error": "API unavailable"}
    ip_address = await resolve_first_ip(domain)
    if not ip_address:
        return {"error": "No A record resolved"}
    await generic_limiter.acquire()
    headers = {"Key": api_key, "Accept": "application/json", **DEFAULT_HEADERS}
    endpoint = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as client:
        try:
            response = await client.get(endpoint)
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                "abuseipdb_ip": ip_address,
                "abuseipdb_score": data.get("abuseConfidenceScore"),
                "abuseipdb_isp": data.get("isp"),
                "abuseipdb_usage_type": data.get("usageType"),
                "abuseipdb_country": data.get("countryCode"),
                "abuseipdb_total_reports": data.get("totalReports"),
                "abuseipdb_last_reported_at": data.get("lastReportedAt"),
            }
        except Exception as exc:
            return {"error": str(exc)}


async def crt_lookup(domain: str) -> list:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with httpx.AsyncClient(timeout=20, headers=DEFAULT_HEADERS) as client:
        try:
            r = await client.get(url)
            r.raise_for_status()
            certs = r.json()
            # Return unique name_value entries = subdomains/SANs
            seen = set()
            results = []
            for cert in certs[:50]:  # Cap at 50
                for name in cert.get("name_value", "").split("\n"):
                    if name and name not in seen:
                        seen.add(name)
                        results.append(
                            {
                                "name": name,
                                "issuer": cert.get("issuer_name", ""),
                                "not_before": cert.get("not_before", ""),
                            }
                        )
            return results
        except Exception as exc:
            logger.warning(f"[yellow]crt.sh lookup failed for {domain}: {exc}[/yellow]")
            return []


def _merge_errors(payload: dict[str, Any], source_name: str, result: dict[str, Any]) -> None:
    error = result.get("error")
    if error:
        payload["errors"][source_name] = error


async def gather_passive_intel(domain: str, url: str) -> dict[str, Any]:
    parsed = urlparse(url if "://" in url else f"https://{domain}")
    input_url = url if parsed.scheme else f"https://{domain}"

    vt_key = None
    urlscan_key = None
    abuseipdb_key = None
    otx_key = None
    gsb_key = None
    from pipeline.utils import env

    vt_key = env("VT_API_KEY")
    urlscan_key = env("URLSCAN_API_KEY")
    abuseipdb_key = env("ABUSEIPDB_API_KEY")
    otx_key = env("OTX_API_KEY")
    gsb_key = env("GOOGLE_SAFE_BROWSING_KEY")

    tasks = {
        "registration": rdap_lookup(domain),
        "virustotal": virustotal_lookup(domain, vt_key),
        "urlscan": urlscan_lookup(domain, input_url, urlscan_key),
        "urlhaus": urlhaus_lookup(input_url),
        "google_safe_browsing": google_safe_browsing_lookup(input_url, gsb_key),
        "otx": otx_lookup(domain, otx_key),
        "phishtank": phishtank_lookup(input_url),
        "abuseipdb": abuseipdb_lookup(domain, abuseipdb_key),
        "dns": dns_lookup(domain),
        "crt": crt_lookup(domain),
    }

    resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
    combined = _default_ti()
    registration = _default_registration()
    dns_records = {"A": [], "MX": [], "NS": [], "TXT": []}
    cert_transparency: list[dict[str, Any]] = []

    for key, value in zip(tasks.keys(), resolved):
        if isinstance(value, Exception):
            if key == "registration":
                registration = _default_registration(str(value))
            elif key == "dns":
                dns_records = {"A": [], "MX": [], "NS": [], "TXT": []}
                combined["errors"][key] = str(value)
            elif key == "crt":
                combined["errors"][key] = str(value)
            else:
                combined["errors"][key] = str(value)
            continue

        if key == "registration":
            registration = value
        elif key == "dns":
            dns_records = value
        elif key == "crt":
            cert_transparency = value
        else:
            combined.update({k: v for k, v in value.items() if k != "error"})
            _merge_errors(combined, key, value)

    passive_priority = calculate_priority_score(domain, input_url, registration.get("registered"))
    if combined.get("phishtank_verified") or combined.get("urlhaus_listed"):
        passive_priority = min(100, passive_priority + 25)

    return {
        "domain": domain,
        "input_url": input_url,
        "analysis_started_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registration": registration,
        "dns_records": dns_records,
        "cert_transparency": cert_transparency,
        "threat_intel": combined,
        "passive_priority_score": passive_priority,
        "registrar": registration.get("registrar"),
        "registered": registration.get("registered"),
        "expires": registration.get("expires"),
        "country": registration.get("country"),
        "nameservers": registration.get("nameservers", []),
        **combined,
    }
