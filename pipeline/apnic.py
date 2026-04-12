from __future__ import annotations

import csv
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from pipeline.utils import APNIC_DATA_PATH, logger


def _normalise_holder_name(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def _serialise_row(row: dict[str, str]) -> dict[str, Any]:
    return {
        "resource": row.get("resource"),
        "start": row.get("start"),
        "value": row.get("value"),
        "nir": row.get("nir"),
        "cc": row.get("cc"),
        "economy_name": row.get("economy_name"),
        "delegation_date": row.get("delegation_date"),
        "transfer_date": row.get("transfer_date") or None,
        "opaque_id": row.get("opaque_id"),
        "holder_name": row.get("holder_name"),
        "registry": row.get("registry"),
        "type": row.get("type"),
    }


@dataclass(frozen=True)
class APNICIndex:
    ipv4_records: tuple[tuple[ipaddress.IPv4Network, dict[str, str]], ...]
    ipv6_records: tuple[tuple[ipaddress.IPv6Network, dict[str, str]], ...]
    asn_by_holder: dict[str, tuple[dict[str, Any], ...]]


def _ipv4_networks_from_row(row: dict[str, str]) -> list[ipaddress.IPv4Network]:
    resource = (row.get("resource") or "").strip()
    if resource:
        try:
            return [ipaddress.IPv4Network(resource, strict=False)]
        except Exception:
            pass

    start_value = (row.get("start") or "").strip()
    count_value = (row.get("value") or "").strip()
    try:
        start_ip = ipaddress.IPv4Address(start_value)
    except Exception:
        return []

    if count_value.isdigit():
        try:
            end_ip = ipaddress.IPv4Address(int(start_ip) + int(count_value) - 1)
            return list(ipaddress.summarize_address_range(start_ip, end_ip))
        except Exception:
            return []

    if "-" in resource:
        start_text, end_text = [part.strip() for part in resource.split("-", 1)]
        try:
            return list(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(start_text),
                    ipaddress.IPv4Address(end_text),
                )
            )
        except Exception:
            return []

    return []


@lru_cache(maxsize=4)
def load_apnic_index(csv_path: str = "") -> APNICIndex:
    path = Path(csv_path) if csv_path else APNIC_DATA_PATH
    if not path.exists():
        logger.warning(f"[yellow]APNIC dataset not found at {path}; network attribution will be skipped.[/yellow]")
        return APNICIndex(ipv4_records=(), ipv6_records=(), asn_by_holder={})

    ipv4_records: list[tuple[ipaddress.IPv4Network, dict[str, str]]] = []
    ipv6_records: list[tuple[ipaddress.IPv6Network, dict[str, str]]] = []
    asn_by_holder: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_type = (row.get("type") or "").strip().lower()
            if row_type == "ipv4":
                networks = _ipv4_networks_from_row(row)
                if not networks:
                    continue
                for network in networks:
                    ipv4_records.append((network, row))
            elif row_type == "ipv6":
                try:
                    network = ipaddress.IPv6Network(row.get("resource", ""), strict=False)
                except Exception:
                    continue
                ipv6_records.append((network, row))
            elif row_type == "asn":
                holder_key = _normalise_holder_name(row.get("holder_name"))
                if not holder_key:
                    continue
                asn_by_holder[holder_key].append(_serialise_row(row))

    ipv4_records.sort(key=lambda item: item[0].prefixlen, reverse=True)
    ipv6_records.sort(key=lambda item: item[0].prefixlen, reverse=True)
    frozen_asn_map = {key: tuple(values) for key, values in asn_by_holder.items()}
    return APNICIndex(
        ipv4_records=tuple(ipv4_records),
        ipv6_records=tuple(ipv6_records),
        asn_by_holder=frozen_asn_map,
    )


def _match_ip(ip_value: str, index: APNICIndex) -> dict[str, Any] | None:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return None

    records = index.ipv4_records if ip_obj.version == 4 else index.ipv6_records
    for network, row in records:
        if ip_obj in network:
            payload = _serialise_row(row)
            payload["ip_address"] = ip_value
            payload["ip_version"] = ip_obj.version
            payload["allocation_type"] = row.get("type")
            return payload
    return None


def enrich_network_attribution(ip_addresses: list[str], csv_path: str = "") -> dict[str, Any]:
    unique_ips = sorted({ip for ip in ip_addresses if ip})
    if not unique_ips:
        return {
            "resolved_ips": [],
            "matched_allocations": [],
            "primary_holder": None,
            "primary_cc": None,
            "primary_economy_name": None,
            "holder_linked_asns": [],
        }

    index = load_apnic_index(csv_path)
    matched_allocations: list[dict[str, Any]] = []
    holder_counter: Counter[str] = Counter()
    holder_rows: dict[str, dict[str, Any]] = {}

    for ip in unique_ips:
        match = _match_ip(ip, index)
        if not match:
            continue
        matched_allocations.append(match)
        holder_name = match.get("holder_name")
        if holder_name:
            holder_counter[holder_name] += 1
            holder_rows.setdefault(holder_name, match)

    primary_holder = holder_counter.most_common(1)[0][0] if holder_counter else None
    primary_row = holder_rows.get(primary_holder or "")
    holder_linked_asns: list[dict[str, Any]] = []
    seen_asns: set[str] = set()

    for holder_name in holder_rows:
        holder_key = _normalise_holder_name(holder_name)
        for asn_row in index.asn_by_holder.get(holder_key, ()):
            resource = asn_row.get("resource")
            if resource and resource not in seen_asns:
                seen_asns.add(resource)
                holder_linked_asns.append(asn_row)

    holder_linked_asns.sort(key=lambda item: item.get("resource") or "")
    return {
        "resolved_ips": unique_ips,
        "matched_allocations": matched_allocations,
        "primary_holder": primary_holder,
        "primary_cc": primary_row.get("cc") if primary_row else None,
        "primary_economy_name": primary_row.get("economy_name") if primary_row else None,
        "holder_linked_asns": holder_linked_asns,
    }
