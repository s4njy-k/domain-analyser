from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx
import tldextract
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async

from pipeline.utils import perceptual_hash, sha256_file


# Device profiles for capture
PROFILES = {
    "desktop": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "viewport": {"width": 1366, "height": 768},
        "locale": "en-IN",
        "timezone_id": "Asia/Kolkata",
        "geolocation": {"latitude": 28.6139, "longitude": 77.2090},  # New Delhi
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


def _registered_domain(value: str) -> str:
    extract = tldextract.extract(value or "")
    return ".".join(part for part in (extract.domain, extract.suffix) if part)


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


def _primary_capture(captures: list[dict[str, Any]]) -> dict[str, Any] | None:
    successful = [capture for capture in captures if not capture.get("error")]
    if not successful:
        return captures[0] if captures else None
    for capture in successful:
        if capture.get("profile") == "desktop":
            return capture
    return successful[0]


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


async def capture_domain(domain: str, url: str, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    captures: list[dict[str, Any]] = []
    wayback = await _lookup_wayback_snapshot(url)
    async with async_playwright() as p:
        for profile_name, profile in PROFILES.items():
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = await browser.new_context(
                user_agent=profile["user_agent"],
                viewport=profile["viewport"],
                locale=profile["locale"],
                timezone_id=profile["timezone_id"],
                geolocation=profile.get("geolocation"),
                permissions=["geolocation"],
                is_mobile=profile.get("is_mobile", False),
                has_touch=profile.get("has_touch", False),
                extra_http_headers={"Accept-Language": "en-IN,en;q=0.9,hi;q=0.8"},
            )
            page = await context.new_page()
            await stealth_async(page)  # Apply stealth patches

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

            # Navigation and capture core (inside capture_domain loop)
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as exc:
                captures.append(
                    {
                        "profile": profile_name,
                        "http_status": None,
                        "final_url": None,
                        "title": None,
                        "page_text": None,
                        "meta_desc": None,
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
                        "error": str(exc),
                    }
                )
                await context.close()
                await browser.close()
                continue

            # Human simulation
            await asyncio.sleep(random.uniform(1.5, 3.0))
            await page.mouse.move(profile["viewport"]["width"] / 2, profile["viewport"]["height"] / 2)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 3)")
            await asyncio.sleep(random.uniform(0.5, 1.5))

            # Screenshots
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            base_name = f"{domain}_{profile_name}_{ts}"
            shot_vp = output_dir / f"{base_name}_viewport.png"
            shot_full = output_dir / f"{base_name}_fullpage.png"
            await page.screenshot(path=str(shot_vp), full_page=False)
            await page.screenshot(path=str(shot_full), full_page=True)

            response_headers = await response.all_headers() if response else {}
            redirect_chain = _redirect_chain_from_response(response)
            grouped_requests = _group_network_requests(domain, captured_requests)
            capture_ts_ist = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")
            title = await page.title()
            text = await page.evaluate("document.body?.innerText || ''")
            meta_desc = await page.evaluate(
                "document.querySelector(\"meta[name=description]\")?.content || ''"
            )

            captures.append(
                {
                    "profile": profile_name,
                    "http_status": response.status if response else None,
                    "final_url": page.url,
                    "title": title,
                    "page_text": text,
                    "meta_desc": meta_desc,
                    "screenshot_viewport_path": str(shot_vp),
                    "screenshot_viewport_hash": sha256_file(shot_vp),
                    "screenshot_full_path": str(shot_full),
                    "screenshot_full_hash": sha256_file(shot_full),
                    "capture_ts_utc": ts,
                    "capture_ts_ist": capture_ts_ist,
                    "response_headers": response_headers,
                    "redirect_chain": redirect_chain,
                    "network_requests": grouped_requests,
                    "screenshot_phash": perceptual_hash(shot_vp),
                    "error": None,
                }
            )
            await context.close()
            await browser.close()

    cloaking = _cloaking_suspected(captures)
    for capture in captures:
        capture["cloaking_suspected"] = cloaking

    primary = _primary_capture(captures) or {}
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
        "cloaking_suspected": cloaking,
        "wayback_snapshot": wayback,
    }
