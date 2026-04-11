from __future__ import annotations

import csv
import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape

from pipeline.report import DomainReport, render_domain_report
from pipeline.utils import DATA_DIR, DOCS_DIR, REPORTS_DIR, ROOT_DIR, copy_if_exists, ensure_runtime_dirs, safe_filename

TEMPLATES_DIR = ROOT_DIR / "templates"
CHART_JS_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"


# dashboard.py — infrastructure clustering
def cluster_infrastructure(domain_reports: list) -> dict:
    ip_clusters = defaultdict(list)       # IP -> [domains]
    ns_clusters = defaultdict(list)       # Nameserver -> [domains]
    registrar_clusters = defaultdict(list) # Registrar -> [domains]
    template_clusters = defaultdict(list) # PHash -> [domains]

    for report in domain_reports:
        # Cluster by hosting IP
        ip = report["dns_records"].get("A", [None])[0]
        if ip:
            ip_clusters[ip].append(report["domain"])

        # Cluster by primary nameserver
        ns = report["registration"]["nameservers"]
        if ns:
            ns_clusters[ns[0].lower()].append(report["domain"])

        # Cluster by registrar
        reg = report["registration"].get("registrar")
        if reg:
            registrar_clusters[reg].append(report["domain"])

        # Cluster by visual hash (perceptual hash of viewport screenshot)
        phash = report.get("screenshot_phash")
        if phash:
            template_clusters[phash].append(report["domain"])

    # Return clusters with >1 member only
    return {
        "by_ip": {k: v for k, v in ip_clusters.items() if len(v) > 1},
        "by_nameserver": {k: v for k, v in ns_clusters.items() if len(v) > 1},
        "by_registrar": {k: v for k, v in registrar_clusters.items() if len(v) > 2},
        "by_template": {k: v for k, v in template_clusters.items() if len(v) > 1},
    }


def _load_report_payloads() -> list[dict]:
    payloads = []
    for json_file in sorted(DATA_DIR.glob("*.json")):
        payloads.append(json.loads(json_file.read_text(encoding="utf-8")))
    return payloads


def _ensure_clean_docs() -> None:
    ensure_runtime_dirs()
    for relative in ("domains", "data", "evidence"):
        directory = DOCS_DIR / relative
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "assets").mkdir(parents=True, exist_ok=True)


def _copy_static_assets() -> None:
    copy_if_exists(TEMPLATES_DIR / "assets" / "style.css", DOCS_DIR / "assets" / "style.css")
    copy_if_exists(TEMPLATES_DIR / "assets" / "dashboard.js", DOCS_DIR / "assets" / "dashboard.js")
    chart_target = DOCS_DIR / "assets" / "chart.min.js"
    try:
        response = httpx.get(CHART_JS_URL, timeout=30)
        response.raise_for_status()
        chart_target.write_text(response.text, encoding="utf-8")
    except Exception:
        chart_target.write_text(
            "document.write('<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js\"><\\/script>');",
            encoding="utf-8",
        )


def _flatten_clusters(clusters: dict[str, dict[str, list[str]]]) -> list[dict]:
    rows = []
    labels = {
        "by_ip": "Shared IP",
        "by_nameserver": "Shared Nameserver",
        "by_registrar": "Shared Registrar",
        "by_template": "Shared Visual Template",
    }
    for cluster_type, values in clusters.items():
        for indicator, domains in values.items():
            rows.append(
                {
                    "cluster_type": labels.get(cluster_type, cluster_type),
                    "indicator": indicator,
                    "size": len(domains),
                    "domains": sorted(domains),
                }
            )
    rows.sort(key=lambda row: (row["size"], row["cluster_type"]), reverse=True)
    return rows


def _domain_rows(report_payloads: list[dict]) -> list[dict]:
    rows = []
    for payload in report_payloads:
        dns_a = payload.get("dns_records", {}).get("A") or []
        capture_list = payload.get("captures") or []
        primary_capture = capture_list[0] if capture_list else {}
        row = {
            "domain": payload["domain"],
            "severity": payload.get("ai_analysis", {}).get("severity", "UNKNOWN"),
            "category": payload.get("ai_analysis", {}).get("threat_category", "UNKNOWN"),
            "brand_impersonated": payload.get("ai_analysis", {}).get("brand_impersonated"),
            "vt_score": f"{payload.get('threat_intel', {}).get('vt_malicious', 0)}/{payload.get('threat_intel', {}).get('vt_total', 0)}",
            "vt_malicious": payload.get("threat_intel", {}).get("vt_malicious", 0),
            "registered": payload.get("registration", {}).get("registered"),
            "status": "DOWN" if primary_capture.get("http_status") is None else "ACTIVE",
            "hosting_country": payload.get("registration", {}).get("country") or payload.get("threat_intel", {}).get("abuseipdb_country") or "Unknown",
            "registrar": payload.get("registration", {}).get("registrar") or "Unknown",
            "ip": dns_a[0] if dns_a else None,
            "report_link": f"domains/{safe_filename(payload['domain'])}/report.html",
            "raw_json_link": f"domains/{safe_filename(payload['domain'])}/data.json",
            "evidence_link": f"evidence/{safe_filename(payload['domain'])}_evidence.zip",
            "priority_score": payload.get("ai_analysis", {}).get("priority_score", 0),
        }
        rows.append(row)
    return rows


def _summary_payload(report_payloads: list[dict], domain_rows: list[dict], clusters: dict[str, dict[str, list[str]]], batch_id: str | None) -> dict:
    severity_counts = Counter(row["severity"] for row in domain_rows)
    category_counts = Counter(row["category"] for row in domain_rows)
    countries = Counter(row["hosting_country"] for row in domain_rows)
    brands = Counter(row["brand_impersonated"] for row in domain_rows if row.get("brand_impersonated"))
    unique_ips = {row["ip"] for row in domain_rows if row.get("ip")}
    unique_registrars = {row["registrar"] for row in domain_rows if row.get("registrar") and row["registrar"] != "Unknown"}
    flat_clusters = _flatten_clusters(clusters)

    return {
        "batch_id": batch_id or (report_payloads[0]["batch_id"] if report_payloads else "batch-unknown"),
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_domains": len(domain_rows),
        "active_malicious": sum(1 for row in domain_rows if row["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} and row["category"] != "BENIGN"),
        "inactive_down": sum(1 for row in domain_rows if row["status"] == "DOWN" or row["severity"] == "INACTIVE"),
        "unique_ips": len(unique_ips),
        "unique_registrars": len(unique_registrars),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "top_impersonated_brands": [{"brand": brand, "count": count} for brand, count in brands.most_common(10)],
        "top_hosting_countries": [{"country": country, "count": count} for country, count in countries.most_common(10)],
        "clusters": flat_clusters,
    }


def _write_domains_csv(rows: list[dict]) -> None:
    csv_path = DOCS_DIR / "data" / "domains.csv"
    fieldnames = [
        "domain",
        "severity",
        "category",
        "vt_score",
        "registered",
        "status",
        "hosting_country",
        "registrar",
        "ip",
        "priority_score",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})


def _bundle_all_evidence(zip_paths: list[Path]) -> Path:
    all_zip_path = DOCS_DIR / "evidence" / "all_evidence_packages.zip"
    with ZipFile(all_zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for zip_path in zip_paths:
            if zip_path.exists():
                archive.write(zip_path, arcname=zip_path.name)
    return all_zip_path


def _write_per_domain_docs(report_payloads: list[dict]) -> list[Path]:
    copied_zips: list[Path] = []
    for payload in report_payloads:
        domain_slug = safe_filename(payload["domain"])
        domain_dir = DOCS_DIR / "domains" / domain_slug
        domain_dir.mkdir(parents=True, exist_ok=True)
        docs_json_path = domain_dir / "data.json"
        docs_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

        manifest_path = REPORTS_DIR / f"{domain_slug}_manifest.json"
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"files": []}
        report_html = render_domain_report(
            payload,
            raw_json_link="data.json",
            evidence_zip_link=f"../../evidence/{domain_slug}_evidence.zip",
            manifest_entries=manifest_payload.get("files", []),
            linked_domains=payload.get("linked_domains", []),
        )
        (domain_dir / "report.html").write_text(report_html, encoding="utf-8")

        evidence_source = REPORTS_DIR / f"{domain_slug}_evidence.zip"
        evidence_target = DOCS_DIR / "evidence" / evidence_source.name
        copy_if_exists(evidence_source, evidence_target)
        copied_zips.append(evidence_target)
    return copied_zips


def generate_dashboard(results: list[dict] | None = None, batch_id: str | None = None) -> dict:
    del results  # The dashboard is generated from persisted per-domain JSON payloads.
    _ensure_clean_docs()
    _copy_static_assets()

    report_payloads = _load_report_payloads()
    domain_rows = _domain_rows(report_payloads)
    clusters = cluster_infrastructure(report_payloads)
    summary = _summary_payload(report_payloads, domain_rows, clusters, batch_id)

    summary_path = DOCS_DIR / "data" / "summary.json"
    domains_path = DOCS_DIR / "data" / "domains.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    domains_path.write_text(json.dumps(domain_rows, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_domains_csv(domain_rows)
    zip_paths = _write_per_domain_docs(report_payloads)
    all_zip = _bundle_all_evidence(zip_paths)

    template = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(("html", "xml")),
    ).get_template("dashboard.html.j2")
    html = template.render(
        batch_id=summary["batch_id"],
        generated_at_utc=summary["generated_at_utc"],
        total_domains=summary["total_domains"],
        chart_js_url=CHART_JS_URL,
        summary_json_path="data/summary.json",
        domains_json_path="data/domains.json",
        domains_csv_path="data/domains.csv",
        all_evidence_zip_path=f"evidence/{all_zip.name}",
    )
    (DOCS_DIR / "index.html").write_text(html, encoding="utf-8")
    return summary


if __name__ == "__main__":
    generate_dashboard()
