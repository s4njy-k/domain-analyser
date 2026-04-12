from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional
from zipfile import ZIP_DEFLATED, ZipFile

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, ConfigDict, Field

from pipeline.utils import (
    DATA_DIR,
    REPORTS_DIR,
    ROOT_DIR,
    ensure_runtime_dirs,
    json_dumps,
    logger,
    manifest_hash,
    path_to_data_uri,
    perceptual_hash,
    safe_filename,
    sha256_file,
    write_json,
)

TEMPLATES_DIR = ROOT_DIR / "templates"
REPORT_DISCLAIMER = (
    "Analyst-generated draft for internal cybercrime review by the National Cybercrime Threat Analytics Unit "
    "(NCTAU), Indian Cyber Crime Coordination Centre (I4C); not an official government issuance or blocking order."
)


class ThreatIntelResult(BaseModel):
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total: int = 0
    vt_categories: dict = Field(default_factory=dict)
    urlscan_verdict: Optional[str] = None
    urlscan_score: Optional[int] = None
    urlscan_screenshot_url: Optional[str] = None
    urlhaus_listed: bool = False
    urlhaus_threat: Optional[str] = None
    gsb_threats: list[str] = Field(default_factory=list)
    otx_pulse_count: int = 0
    otx_pulses: list[dict] = Field(default_factory=list)
    phishtank_verified: bool = False
    abuseipdb_score: Optional[int] = None
    abuseipdb_isp: Optional[str] = None


class RegistrationData(BaseModel):
    registrar: Optional[str] = None
    registered: Optional[str] = None
    expires: Optional[str] = None
    nameservers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    country: Optional[str] = None


class CaptureData(BaseModel):
    profile: str
    http_status: Optional[int] = None
    final_url: Optional[str] = None
    title: Optional[str] = None
    page_text: Optional[str] = None
    meta_desc: Optional[str] = None
    screenshot_viewport_path: Optional[str] = None
    screenshot_viewport_hash: Optional[str] = None
    screenshot_full_path: Optional[str] = None
    screenshot_full_hash: Optional[str] = None
    capture_ts_utc: Optional[str] = None
    cloaking_suspected: bool = False
    error: Optional[str] = None


class APNICAllocation(BaseModel):
    ip_address: Optional[str] = None
    ip_version: Optional[int] = None
    resource: Optional[str] = None
    start: Optional[str] = None
    value: Optional[str] = None
    nir: Optional[str] = None
    cc: Optional[str] = None
    economy_name: Optional[str] = None
    delegation_date: Optional[str] = None
    transfer_date: Optional[str] = None
    opaque_id: Optional[str] = None
    holder_name: Optional[str] = None
    registry: Optional[str] = None
    type: Optional[str] = None
    allocation_type: Optional[str] = None


class HolderLinkedASN(BaseModel):
    resource: Optional[str] = None
    start: Optional[str] = None
    value: Optional[str] = None
    nir: Optional[str] = None
    cc: Optional[str] = None
    economy_name: Optional[str] = None
    delegation_date: Optional[str] = None
    transfer_date: Optional[str] = None
    opaque_id: Optional[str] = None
    holder_name: Optional[str] = None
    registry: Optional[str] = None
    type: Optional[str] = None


class NetworkAttribution(BaseModel):
    resolved_ips: list[str] = Field(default_factory=list)
    matched_allocations: list[APNICAllocation] = Field(default_factory=list)
    primary_holder: Optional[str] = None
    primary_cc: Optional[str] = None
    primary_economy_name: Optional[str] = None
    holder_linked_asns: list[HolderLinkedASN] = Field(default_factory=list)


class AIAnalysis(BaseModel):
    threat_category: str = "UNKNOWN"
    brand_impersonated: Optional[str] = None
    confidence: str = "LOW"
    severity: str = "UNKNOWN"
    fraud_mechanism: Optional[str] = None
    victim_profile: Optional[str] = None
    illegal_activity_description: Optional[str] = None
    applicable_laws: list[dict] = Field(default_factory=list)
    recommended_action: Optional[str] = None
    priority_score: int = 0


class DomainReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str
    input_url: str
    batch_id: str
    analysis_ts_utc: str
    registration: RegistrationData
    dns_records: dict
    cert_transparency: list[dict]
    threat_intel: ThreatIntelResult
    network_attribution: NetworkAttribution = Field(default_factory=NetworkAttribution)
    captures: list[CaptureData]
    ai_analysis: AIAnalysis
    evidence_manifest_hash: Optional[str] = None


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(("html", "xml")),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _capture_entries(payload: list[dict[str, Any]]) -> list[CaptureData]:
    captures = []
    for item in payload:
        captures.append(
            CaptureData(
                profile=item.get("profile") or item.get("profile_name") or "unknown",
                http_status=item.get("http_status"),
                final_url=item.get("final_url"),
                title=item.get("title"),
                page_text=item.get("page_text"),
                meta_desc=item.get("meta_desc"),
                screenshot_viewport_path=item.get("screenshot_viewport_path") or item.get("screenshot_viewport"),
                screenshot_viewport_hash=item.get("screenshot_viewport_hash"),
                screenshot_full_path=item.get("screenshot_full_path") or item.get("screenshot_full"),
                screenshot_full_hash=item.get("screenshot_full_hash"),
                capture_ts_utc=item.get("capture_ts_utc"),
                cloaking_suspected=bool(item.get("cloaking_suspected")),
                error=item.get("error"),
            )
        )
    return captures


def _build_model(domain: str, merged: dict[str, Any], ai_result: dict[str, Any], batch_id: str) -> DomainReport:
    return DomainReport(
        domain=domain,
        input_url=merged.get("input_url", merged.get("final_url", f"https://{domain}")),
        batch_id=batch_id,
        analysis_ts_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        registration=RegistrationData(**(merged.get("registration") or {})),
        dns_records=merged.get("dns_records") or {},
        cert_transparency=merged.get("cert_transparency") or [],
        threat_intel=ThreatIntelResult(**(merged.get("threat_intel") or {})),
        network_attribution=NetworkAttribution(**(merged.get("network_attribution") or {})),
        captures=_capture_entries(merged.get("captures") or []),
        ai_analysis=AIAnalysis(**(ai_result or {})),
        evidence_manifest_hash=None,
    )


def _domain_age(registered: str | None) -> dict[str, Any]:
    if not registered:
        return {"days": None, "is_new_domain": False}
    try:
        registered_date = date.fromisoformat(registered[:10])
        days = (date.today() - registered_date).days
        return {"days": days, "is_new_domain": days < 30}
    except ValueError:
        return {"days": None, "is_new_domain": False}


def _screenshot_manifest_entries(report: DomainReport) -> list[dict[str, Any]]:
    entries = []
    for capture in report.captures:
        if capture.screenshot_viewport_path:
            entries.append(
                {
                    "file": Path(capture.screenshot_viewport_path).name,
                    "path": capture.screenshot_viewport_path,
                    "hash": capture.screenshot_viewport_hash,
                    "timestamp": capture.capture_ts_utc,
                    "profile": capture.profile,
                    "type": "viewport",
                }
            )
        if capture.screenshot_full_path:
            entries.append(
                {
                    "file": Path(capture.screenshot_full_path).name,
                    "path": capture.screenshot_full_path,
                    "hash": capture.screenshot_full_hash,
                    "timestamp": capture.capture_ts_utc,
                    "profile": capture.profile,
                    "type": "full_page",
                }
            )
    return entries


def _capture_cards(report: DomainReport) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for capture in report.captures:
        cards.append(
            {
                "profile": capture.profile,
                "http_status": capture.http_status,
                "title": capture.title,
                "meta_desc": capture.meta_desc,
                "timestamp": capture.capture_ts_utc,
                "viewport_path": capture.screenshot_viewport_path,
                "viewport_hash": capture.screenshot_viewport_hash,
                "viewport_data_uri": path_to_data_uri(capture.screenshot_viewport_path),
                "full_path": capture.screenshot_full_path,
                "full_hash": capture.screenshot_full_hash,
                "full_data_uri": path_to_data_uri(capture.screenshot_full_path),
                "cloaking_suspected": capture.cloaking_suspected,
                "error": capture.error,
            }
        )
    return cards


def _primary_capture(captures: list[CaptureData]) -> CaptureData | None:
    successful = [capture for capture in captures if not capture.error and capture.http_status is not None]
    for capture in successful:
        if capture.profile == "desktop":
            return capture
    if successful:
        return successful[0]
    return captures[0] if captures else None


def _linked_domains_from_existing(report: DomainReport, current_json_path: Path | None = None) -> list[str]:
    linked: set[str] = set()
    current_ip = (report.dns_records.get("A") or [None])[0]
    current_registrar = report.registration.registrar
    current_nameserver = (report.registration.nameservers or [None])[0]
    current_phash = None
    current_capture = _primary_capture(report.captures)
    if current_capture and current_capture.screenshot_viewport_path:
        current_phash = perceptual_hash(current_capture.screenshot_viewport_path)

    for json_file in sorted(DATA_DIR.glob("*.json")):
        if current_json_path and json_file.resolve() == current_json_path.resolve():
            continue
        try:
            other = DomainReport.model_validate_json(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if other.domain == report.domain:
            continue
        other_ip = (other.dns_records.get("A") or [None])[0]
        other_registrar = other.registration.registrar
        other_nameserver = (other.registration.nameservers or [None])[0]
        other_phash = None
        other_capture = _primary_capture(other.captures)
        if other_capture and other_capture.screenshot_viewport_path:
            other_phash = perceptual_hash(other_capture.screenshot_viewport_path)
        shared = False
        if current_ip and other_ip and current_ip == other_ip:
            shared = True
        if current_registrar and other_registrar and current_registrar == other_registrar:
            shared = True
        if current_nameserver and other_nameserver and current_nameserver.lower() == other_nameserver.lower():
            shared = True
        if current_phash and other_phash and current_phash == other_phash:
            shared = True
        if shared:
            linked.add(other.domain)
    return sorted(linked)


def render_domain_report(
    report_dict: dict[str, Any],
    raw_json_link: str,
    pdf_report_link: str,
    evidence_zip_link: str,
    manifest_entries: list[dict[str, Any]],
    linked_domains: list[str] | None = None,
    is_pdf: bool = False,
) -> str:
    env = _jinja_env()
    template = env.get_template("domain_report.html.j2")
    style_css = (TEMPLATES_DIR / "assets" / "style.css").read_text(encoding="utf-8")
    report = DomainReport.model_validate(report_dict)
    primary_capture = _primary_capture(report.captures)
    return template.render(
        report=report,
        style_css=style_css,
        report_identifier=report_dict.get("report_identifier"),
        report_disclaimer=REPORT_DISCLAIMER,
        is_pdf=is_pdf,
        capture_cards=_capture_cards(report),
        domain_age=_domain_age(report.registration.registered),
        raw_json_link=raw_json_link,
        pdf_report_link=pdf_report_link,
        evidence_zip_link=evidence_zip_link,
        manifest_entries=manifest_entries,
        linked_domains=linked_domains or [],
        first_ten_certs=(report.cert_transparency or [])[:10],
        redirect_chain=report_dict.get("redirect_chain", []),
        response_headers=report_dict.get("response_headers", {}),
        network_requests=report_dict.get("network_requests", {}),
        wayback_snapshot=report_dict.get("wayback_snapshot", {}),
        primary_capture=primary_capture,
    )


def _report_identifier(domain: str, analysis_ts_utc: str) -> str:
    compact_ts = analysis_ts_utc.replace("-", "").replace(":", "").replace("T", "-").replace("Z", "")
    return f"NCTAU-DAR-{safe_filename(domain).upper()}-{compact_ts}"


def _render_pdf(html: str, output_path: Path) -> None:
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(ROOT_DIR)).write_pdf(str(output_path))
        return
    except Exception as exc:
        weasyprint_error = exc
        logger.warning(
            f"[yellow]WeasyPrint PDF rendering unavailable ({exc}); falling back to Playwright PDF output.[/yellow]"
        )

    try:
        from playwright.sync_api import sync_playwright

        with TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            html_path.write_text(html, encoding="utf-8")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(viewport={"width": 1440, "height": 1080})
                page.goto(html_path.as_uri(), wait_until="load")
                page.pdf(
                    path=str(output_path),
                    format="A4",
                    print_background=True,
                    margin={"top": "16mm", "right": "12mm", "bottom": "18mm", "left": "12mm"},
                )
                browser.close()
        return
    except Exception as fallback_exc:
        raise RuntimeError(
            "PDF generation failed with both WeasyPrint and Playwright fallback: "
            f"{weasyprint_error}; {fallback_exc}"
        ) from fallback_exc


def generate_domain_report(
    domain: str,
    merged: dict[str, Any],
    ai_result: dict[str, Any],
    batch_id: str,
    linked_domains: list[str] | None = None,
) -> dict[str, Any]:
    ensure_runtime_dirs()
    report = _build_model(domain, merged, ai_result, batch_id)
    report_identifier = _report_identifier(domain, report.analysis_ts_utc)
    screenshot_entries = _screenshot_manifest_entries(report)
    report.evidence_manifest_hash = manifest_hash(screenshot_entries)

    json_path = DATA_DIR / f"{safe_filename(domain)}.json"
    report_payload = report.model_dump()
    report_payload.update(
        {
            "redirect_chain": merged.get("redirect_chain", []),
            "response_headers": merged.get("response_headers", {}),
            "network_requests": merged.get("network_requests", {}),
            "wayback_snapshot": merged.get("wayback_snapshot", {}),
            "screenshot_phash": merged.get("screenshot_phash"),
            "linked_domains": linked_domains or _linked_domains_from_existing(report, json_path),
            "report_identifier": report_identifier,
        }
    )
    write_json(json_path, report_payload)

    manifest_entries = list(screenshot_entries)
    manifest_entries.append(
        {
            "file": json_path.name,
            "path": str(json_path),
            "hash": sha256_file(json_path),
            "timestamp": report.analysis_ts_utc,
            "profile": "system",
            "type": "raw_json",
        }
    )

    report_path = REPORTS_DIR / f"{safe_filename(domain)}.html"
    pdf_path = REPORTS_DIR / f"{safe_filename(domain)}.pdf"
    html = render_domain_report(
        report_payload,
        raw_json_link=f"../data/{json_path.name}",
        pdf_report_link=f"./{pdf_path.name}",
        evidence_zip_link=f"./{safe_filename(domain)}_evidence.zip",
        manifest_entries=manifest_entries,
        linked_domains=report_payload.get("linked_domains", []),
    )
    report_path.write_text(html, encoding="utf-8")
    pdf_html = render_domain_report(
        report_payload,
        raw_json_link=f"../data/{json_path.name}",
        pdf_report_link=f"./{pdf_path.name}",
        evidence_zip_link=f"./{safe_filename(domain)}_evidence.zip",
        manifest_entries=manifest_entries,
        linked_domains=report_payload.get("linked_domains", []),
        is_pdf=True,
    )
    _render_pdf(pdf_html, pdf_path)

    manifest_path = REPORTS_DIR / f"{safe_filename(domain)}_manifest.json"
    html_entry = {
        "file": report_path.name,
        "path": str(report_path),
        "hash": sha256_file(report_path),
        "timestamp": report.analysis_ts_utc,
        "profile": "system",
        "type": "html_report",
    }
    pdf_entry = {
        "file": pdf_path.name,
        "path": str(pdf_path),
        "hash": sha256_file(pdf_path),
        "timestamp": report.analysis_ts_utc,
        "profile": "system",
        "type": "pdf_report",
    }
    manifest_payload = {
        "domain": domain,
        "batch_id": batch_id,
        "analysis_ts_utc": report.analysis_ts_utc,
        "evidence_manifest_hash": report.evidence_manifest_hash,
        "report_identifier": report_identifier,
        "files": manifest_entries + [html_entry, pdf_entry],
    }
    write_json(manifest_path, manifest_payload)

    zip_path = package_evidence_zip(domain, report_path, pdf_path, json_path, manifest_path, report)
    return {
        "report": report,
        "report_dict": report_payload,
        "report_path": report_path,
        "pdf_path": pdf_path,
        "json_path": json_path,
        "manifest_path": manifest_path,
        "zip_path": zip_path,
    }


def package_evidence_zip(
    domain: str,
    report_path: Path,
    pdf_path: Path,
    json_path: Path,
    manifest_path: Path,
    report: DomainReport,
) -> Path:
    zip_path = REPORTS_DIR / f"{safe_filename(domain)}_evidence.zip"
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        archive.write(report_path, arcname=report_path.name)
        archive.write(pdf_path, arcname=pdf_path.name)
        archive.write(json_path, arcname=json_path.name)
        archive.write(manifest_path, arcname=manifest_path.name)
        for capture in report.captures:
            for file_path in (capture.screenshot_viewport_path, capture.screenshot_full_path):
                if file_path and Path(file_path).exists():
                    archive.write(file_path, arcname=Path(file_path).name)
    return zip_path
