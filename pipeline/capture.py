from __future__ import annotations

import asyncio
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx
import tldextract
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async

from pipeline.utils import logger, perceptual_hash, sha256_file


PROFILES = {
    "desktop": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1440, "height": 900},
        "locale": "en-IN",
        "timezone_id": "Asia/Kolkata",
        "geolocation": {"latitude": 28.6139, "longitude": 77.2090},
        "is_mobile": False,
    },
    "mobile_android": {
        "user_agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "viewport": {"width": 412, "height": 915},
        "locale": "en-IN",
        "timezone_id": "Asia/Kolkata",
        "geolocation": {"latitude": 28.6139, "longitude": 77.2090},
        "is_mobile": True,
        "has_touch": True,
    },
}

PAYMENT_PATTERNS = {
    "UPI": (" upi", "upi id", "upi:", "upi payment", "pay via upi", "upi app", "@oksbi", "@okicici", "@paytm", "@ibl"),
    "Paytm": ("paytm", "paytm wallet", "paytm payments bank"),
    "PhonePe": ("phonepe", "phone pe"),
    "Google Pay": ("google pay", "gpay", "googlepay"),
    "BHIM": ("bhim", "bhim upi"),
    "Debit/Credit Card": ("visa", "mastercard", "rupay", "credit card", "debit card", "card payment", "cards accepted"),
    "NetBanking": ("netbanking", "net banking", "bank transfer", "neft", "rtgs", "imps"),
    "Wallet": ("wallet", "e-wallet", "ewallet"),
    "Crypto": ("bitcoin", "ethereum", "usdt", "tether", "trc20", "erc20", "binance pay", "crypto wallet", "crypto deposit"),
    "QR Payment": ("scan qr", "qr code", "pay by qr"),
    "Razorpay": ("razorpay",),
    "Cashfree": ("cashfree",),
    "PayU": ("payu", "payubiz"),
    "Juspay": ("juspay",),
    "Instamojo": ("instamojo",),
    "Skrill": ("skrill",),
    "Neteller": ("neteller",),
    "AstroPay": ("astropay",),
    "JazzCash": ("jazzcash",),
    "Easypaisa": ("easypaisa",),
    "Bank Deposit": ("deposit now", "cashier", "make deposit", "withdrawal", "add money"),
}

OVERLAY_HINTS = (
    "accept",
    "agree",
    "got it",
    "allow",
    "continue",
    "close",
    "dismiss",
    "skip",
    "no thanks",
    "enter",
    "i am 18",
    "i'm 18",
    "yes",
    "okay",
)


def _registered_domain(value: str) -> str:
    extract = tldextract.extract(value or "")
    return ".".join(part for part in (extract.domain, extract.suffix) if part)


def _candidate_urls(domain: str, url: str) -> list[str]:
    parsed = urlparse(url if "://" in url else f"https://{domain}")
    host = parsed.netloc or domain
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    candidates: list[str] = []

    def add(candidate: str) -> None:
        if candidate not in candidates:
            candidates.append(candidate)

    preferred_scheme = parsed.scheme or "https"
    add(f"{preferred_scheme}://{host}{path}{query}")
    add(f"https://{host}{path}{query}")
    add(f"http://{host}{path}{query}")
    if host and not host.startswith("www."):
        add(f"https://www.{host}{path}{query}")
        add(f"http://www.{host}{path}{query}")
    return candidates


def _group_network_requests(domain: str, requests: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    registered = _registered_domain(domain)
    grouped = {"first_party": [], "third_party": [], "api_calls": []}
    for request in requests:
        hostname = _registered_domain(urlparse(request["url"]).hostname or "")
        record = {
            "method": request["method"],
            "url": request["url"],
            "resource_type": request["resource_type"],
        }
        if request["resource_type"] in {"xhr", "fetch"} or "/api" in request["url"]:
            grouped["api_calls"].append(record)
        elif hostname and hostname == registered:
            grouped["first_party"].append(record)
        else:
            grouped["third_party"].append(record)
    return grouped


def _redirect_chain_from_response(response: Any) -> list[str]:
    chain: list[str] = []
    request = response.request if response else None
    while request is not None:
        chain.append(request.url)
        request = request.redirected_from
    chain.reverse()
    return chain


async def _lookup_wayback_snapshot(url: str) -> dict[str, str | None]:
    endpoint = f"https://archive.org/wayback/available?url={url}"
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.get(endpoint)
            response.raise_for_status()
            closest = response.json().get("archived_snapshots", {}).get("closest", {})
            return {
                "available": "true" if closest else "false",
                "url": closest.get("url"),
                "timestamp": closest.get("timestamp"),
            }
        except Exception:
            return {"available": "false", "url": None, "timestamp": None}


def _capture_quality_score(http_status: int | None, title: str, page_text: str, meta_desc: str, error: str | None) -> int:
    if error:
        return 0
    score = 0
    lowered = " ".join(filter(None, [title, meta_desc, page_text])).lower()
    if http_status and 200 <= http_status < 400:
        score += 35
    elif http_status:
        score += 10
    score += min(len(title.strip()), 120) // 6
    score += min(len(meta_desc.strip()), 180) // 12
    score += min(len(re.sub(r"\s+", " ", page_text).strip()), 2400) // 30
    if any(flag in lowered for flag in ("access denied", "forbidden", "captcha", "verify you are human", "cloudflare")):
        score -= 20
    return max(score, 0)


def _extract_snippet(text: str, index: int, length: int) -> str:
    start = max(index - 50, 0)
    end = min(index + length + 100, len(text))
    return re.sub(r"\s+", " ", text[start:end]).strip()[:240]


def _extract_payment_methods(
    title: str,
    meta_desc: str,
    page_text: str,
    page_html: str,
    grouped_requests: dict[str, list[dict[str, Any]]],
) -> list[dict[str, str]]:
    network_urls = "\n".join(
        request.get("url", "")
        for group in grouped_requests.values()
        for request in group
    )
    sources = [
        ("title", title or ""),
        ("meta description", meta_desc or ""),
        ("page text", page_text or ""),
        ("page HTML", page_html or ""),
        ("network requests", network_urls),
    ]
    found: dict[str, dict[str, str]] = {}
    for method, aliases in PAYMENT_PATTERNS.items():
        for source_name, source_text in sources:
            lowered = source_text.lower()
            for alias in aliases:
                position = lowered.find(alias)
                if position == -1:
                    continue
                found[method] = {
                    "method": method,
                    "source": source_name,
                    "evidence": _extract_snippet(source_text, position, len(alias)),
                }
                break
            if method in found:
                break
    return sorted(found.values(), key=lambda item: item["method"])


def _merge_payment_methods(captures: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for capture in captures:
        for entry in capture.get("payment_methods", []) or []:
            merged.setdefault(entry["method"], entry)
    return sorted(merged.values(), key=lambda item: item["method"])


async def _dismiss_ui_noise(page) -> None:
    try:
        await page.evaluate(
            """
            (phrases) => {
              const isVisible = (element) => {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 32 && rect.height > 18;
              };
              let clicks = 0;
              for (const element of document.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]')) {
                if (clicks >= 8) break;
                const text = (element.innerText || element.value || element.getAttribute('aria-label') || '').trim().toLowerCase();
                if (!text || !isVisible(element)) continue;
                if (!phrases.some((phrase) => text.includes(phrase))) continue;
                element.click();
                clicks += 1;
              }
              for (const element of document.querySelectorAll('div, section, aside')) {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                const coversViewport = rect.width >= window.innerWidth * 0.6 && rect.height >= window.innerHeight * 0.24;
                const overlay = ['fixed', 'sticky'].includes(style.position) && coversViewport && Number(style.zIndex || 0) >= 20;
                if (overlay) {
                  element.style.display = 'none';
                }
              }
            }
            """,
            list(OVERLAY_HINTS),
        )
    except Exception:
        return


async def _prime_page_for_capture(page) -> None:
    try:
        await page.evaluate("window.scrollTo(0, 0)")
        await asyncio.sleep(0.4)
        await _dismiss_ui_noise(page)
        for ratio in (0.2, 0.45, 0.7, 1.0):
            await page.evaluate("(position) => window.scrollTo(0, Math.floor(document.body.scrollHeight * position))", ratio)
            await asyncio.sleep(random.uniform(0.5, 1.0))
        await page.evaluate("window.scrollTo(0, 0)")
        await asyncio.sleep(0.6)
        await _dismiss_ui_noise(page)
    except Exception:
        return


async def _collect_frame_content(page) -> tuple[str, str]:
    frame_text_parts: list[str] = []
    frame_html_parts: list[str] = []
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        try:
            frame_text = await frame.evaluate("document.body ? document.body.innerText : ''")
            if frame_text and frame_text.strip():
                frame_text_parts.append(frame_text)
        except Exception:
            pass
        try:
            frame_html = await frame.content()
            if frame_html and frame_html.strip():
                frame_html_parts.append(frame_html)
        except Exception:
            pass
    return "\n".join(frame_text_parts), "\n".join(frame_html_parts)


def _primary_capture(captures: list[dict[str, Any]]) -> dict[str, Any] | None:
    successful = [capture for capture in captures if not capture.get("error")]
    if not successful:
        return captures[0] if captures else None
    return max(
        successful,
        key=lambda capture: (
            int(capture.get("capture_quality_score") or 0),
            1 if capture.get("profile") == "desktop" else 0,
            int(capture.get("http_status") or 0),
        ),
    )


def _cloaking_suspected(captures: list[dict[str, Any]]) -> bool:
    by_profile = {capture.get("profile"): capture for capture in captures}
    desktop = by_profile.get("desktop")
    mobile = by_profile.get("mobile_android")
    if not desktop or not mobile or desktop.get("error") or mobile.get("error"):
        return False
    if (desktop.get("title") or "").strip() != (mobile.get("title") or "").strip():
        return True
    desktop_text = desktop.get("page_text") or ""
    mobile_text = mobile.get("page_text") or ""
    longer = max(len(desktop_text), len(mobile_text), 1)
    return abs(len(desktop_text) - len(mobile_text)) / longer > 0.20


async def _capture_attempt(context, domain: str, candidate_url: str, output_dir: Path, profile_name: str, profile: dict[str, Any]) -> dict[str, Any]:
    page = await context.new_page()
    await stealth_async(page)
    captured_requests: list[dict[str, Any]] = []
    page.on(
        "request",
        lambda request: captured_requests.append(
            {
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
            }
        ),
    )

    try:
        response = await page.goto(candidate_url, wait_until="load", timeout=45000)
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        await asyncio.sleep(random.uniform(1.0, 2.0))
        await page.mouse.move(profile["viewport"]["width"] / 2, profile["viewport"]["height"] / 2)
        await _prime_page_for_capture(page)

        title = await page.title()
        page_text = await page.evaluate("document.body ? document.body.innerText : ''")
        if len(page_text.strip()) < 120:
            await asyncio.sleep(2.0)
            await _dismiss_ui_noise(page)
            page_text = await page.evaluate("document.body ? document.body.innerText : ''")
        meta_desc = await page.evaluate("document.querySelector(\"meta[name=description]\")?.content || ''")
        page_html = await page.content()
        frame_text, frame_html = await _collect_frame_content(page)
        combined_text = "\n".join(part for part in (page_text, frame_text) if part).strip()
        combined_html = "\n".join(part for part in (page_html, frame_html) if part).strip()
        response_headers = await response.all_headers() if response else {}
        redirect_chain = _redirect_chain_from_response(response)
        grouped_requests = _group_network_requests(domain, captured_requests)
        payment_methods = _extract_payment_methods(title, meta_desc, combined_text, combined_html, grouped_requests)
        quality = _capture_quality_score(response.status if response else None, title, combined_text, meta_desc, None)

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_name = f"{domain}_{profile_name}_{ts}"
        shot_vp = output_dir / f"{base_name}_viewport.png"
        shot_full = output_dir / f"{base_name}_fullpage.png"
        await page.screenshot(path=str(shot_vp), full_page=False, animations="disabled")
        await page.screenshot(path=str(shot_full), full_page=True, animations="disabled")

        return {
            "profile": profile_name,
            "http_status": response.status if response else None,
            "final_url": page.url,
            "title": title,
            "page_text": combined_text,
            "meta_desc": meta_desc,
            "payment_methods": payment_methods,
            "screenshot_viewport_path": str(shot_vp),
            "screenshot_viewport_hash": sha256_file(shot_vp),
            "screenshot_full_path": str(shot_full),
            "screenshot_full_hash": sha256_file(shot_full),
            "capture_ts_utc": ts,
            "capture_ts_ist": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST"),
            "profile_name": profile_name,
            "response_headers": response_headers,
            "redirect_chain": redirect_chain,
            "network_requests": grouped_requests,
            "screenshot_phash": perceptual_hash(shot_vp),
            "capture_quality_score": quality,
            "attempted_url": candidate_url,
            "error": None,
        }
    except Exception as exc:
        return {
            "profile": profile_name,
            "http_status": None,
            "final_url": None,
            "title": None,
            "page_text": None,
            "meta_desc": None,
            "payment_methods": [],
            "screenshot_viewport_path": None,
            "screenshot_viewport_hash": None,
            "screenshot_full_path": None,
            "screenshot_full_hash": None,
            "capture_ts_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "capture_ts_ist": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST"),
            "profile_name": profile_name,
            "response_headers": {},
            "redirect_chain": [],
            "network_requests": {"first_party": [], "third_party": [], "api_calls": []},
            "screenshot_phash": None,
            "capture_quality_score": 0,
            "attempted_url": candidate_url,
            "error": str(exc),
        }
    finally:
        await page.close()


async def capture_domain(domain: str, url: str, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    captures: list[dict[str, Any]] = []
    wayback = await _lookup_wayback_snapshot(url)
    candidate_urls = _candidate_urls(domain, url)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        preferred_candidate_url: str | None = None
        for profile_name, profile in PROFILES.items():
            context = await browser.new_context(
                user_agent=profile["user_agent"],
                viewport=profile["viewport"],
                locale=profile["locale"],
                timezone_id=profile["timezone_id"],
                geolocation=profile.get("geolocation"),
                permissions=["geolocation"],
                is_mobile=profile.get("is_mobile", False),
                has_touch=profile.get("has_touch", False),
                ignore_https_errors=True,
                extra_http_headers={"Accept-Language": "en-IN,en;q=0.9,hi;q=0.8"},
            )

            profile_candidates = list(candidate_urls)
            if preferred_candidate_url and preferred_candidate_url in profile_candidates:
                profile_candidates = [preferred_candidate_url] + [
                    candidate for candidate in profile_candidates if candidate != preferred_candidate_url
                ]

            best_capture: dict[str, Any] | None = None
            for index, candidate_url in enumerate(profile_candidates):
                attempt = await _capture_attempt(context, domain, candidate_url, output_dir, profile_name, profile)
                if best_capture is None or int(attempt.get("capture_quality_score") or 0) > int(best_capture.get("capture_quality_score") or 0):
                    best_capture = attempt
                if not attempt.get("error") and int(attempt.get("capture_quality_score") or 0) >= 55:
                    break
                if attempt.get("error"):
                    logger.warning(
                        f"[yellow]Capture attempt {index + 1} failed for {domain} ({profile_name}) via {candidate_url}: {attempt['error']}[/yellow]"
                    )

            captures.append(best_capture or {"profile": profile_name, "error": "No capture attempt completed", "payment_methods": []})
            if best_capture and not best_capture.get("error"):
                preferred_candidate_url = best_capture.get("attempted_url") or preferred_candidate_url
            await context.close()

        await browser.close()

    cloaking = _cloaking_suspected(captures)
    for capture in captures:
        capture["cloaking_suspected"] = cloaking

    primary = _primary_capture(captures) or {}
    payment_methods = _merge_payment_methods(captures)
    return {
        "captures": captures,
        "capture_ts": primary.get("capture_ts_ist"),
        "capture_ts_utc": primary.get("capture_ts_utc"),
        "http_status": primary.get("http_status"),
        "final_url": primary.get("final_url") or url,
        "title": primary.get("title"),
        "page_text": primary.get("page_text"),
        "meta_desc": primary.get("meta_desc"),
        "redirect_chain": primary.get("redirect_chain", []),
        "response_headers": primary.get("response_headers", {}),
        "network_requests": primary.get("network_requests", {}),
        "screenshot_phash": primary.get("screenshot_phash"),
        "capture_quality_score": primary.get("capture_quality_score", 0),
        "cloaking_suspected": cloaking,
        "payment_methods": payment_methods,
        "payment_summary": ", ".join(entry["method"] for entry in payment_methods) if payment_methods else None,
        "wayback_snapshot": wayback,
    }
