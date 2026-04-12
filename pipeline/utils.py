from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from dotenv import load_dotenv
from PIL import Image
from imagehash import phash
from rich.logging import RichHandler

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = ROOT_DIR / "input"
RESOURCES_DIR = ROOT_DIR / "resources"
OUTPUT_DIR = ROOT_DIR / "output"
DOCS_DIR = ROOT_DIR / "docs"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
REPORTS_DIR = OUTPUT_DIR / "reports"
DATA_DIR = OUTPUT_DIR / "data"
DASHBOARD_DIR = OUTPUT_DIR / "dashboard"
APNIC_DATA_PATH = RESOURCES_DIR / "APNIC_(IP&ASN)_Resources.csv"

DEFAULT_TIMEOUT = 20.0
INDIA_TIMEZONE = "Asia/Kolkata"


# utils.py — simple async rate limiter
class RateLimiter:
    def __init__(self, calls_per_minute: int):
        self.calls = calls_per_minute
        self.timestamps = deque()

    async def acquire(self):
        now = time.monotonic()
        # Remove timestamps older than 60 seconds
        while self.timestamps and now - self.timestamps[0] > 60:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.calls:
            sleep_time = 60 - (now - self.timestamps[0]) + 0.1
            await asyncio.sleep(sleep_time)
        self.timestamps.append(time.monotonic())


# Global rate limiters
vt_limiter = RateLimiter(4)        # 4/min
urlscan_limiter = RateLimiter(10)  # 10/min
generic_limiter = RateLimiter(30)  # 30/min for others
rdap_limiter = RateLimiter(60)     # 1 request/second
gemini_limiter = RateLimiter(15)   # 15/min


def get_logger(name: str = "domain_analyser") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = RichHandler(rich_tracebacks=True, markup=True, show_time=True, show_path=False)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


logger = get_logger()


def ensure_runtime_dirs() -> None:
    for directory in (
        INPUT_DIR,
        SCREENSHOTS_DIR,
        REPORTS_DIR,
        DATA_DIR,
        DASHBOARD_DIR,
        DOCS_DIR / "assets",
        DOCS_DIR / "data",
        DOCS_DIR / "domains",
        DOCS_DIR / "evidence",
    ):
        directory.mkdir(parents=True, exist_ok=True)


def chunked(items: list[Any], size: int) -> Iterator[list[Any]]:
    for index in range(0, len(items), size):
        yield items[index:index + size]


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "item"


def safe_filename(value: str) -> str:
    return slugify(value.replace("/", "-"))


def sha256_file(path: Path | str) -> str:
    file_path = Path(path)
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def write_json(path: Path | str, data: Any) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json_dumps(data), encoding="utf-8")


def read_json(path: Path | str, default: Any = None) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        return default
    return json.loads(file_path.read_text(encoding="utf-8"))


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def now_utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def remove_if_exists(path: Path | str) -> None:
    file_path = Path(path)
    if file_path.is_dir():
        shutil.rmtree(file_path)
    elif file_path.exists():
        file_path.unlink()


def path_to_data_uri(path: Path | str | None) -> str | None:
    if path is None:
        return None
    file_path = Path(path)
    if not file_path.exists() or file_path.stat().st_size == 0:
        return None
    mime = "image/png"
    data = base64.b64encode(file_path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{data}"


def perceptual_hash(path: Path | str | None) -> str | None:
    if path is None:
        return None
    file_path = Path(path)
    if not file_path.exists() or file_path.stat().st_size == 0:
        return None
    try:
        with Image.open(file_path) as image:
            return str(phash(image))
    except Exception:
        return None


def manifest_hash(entries: Iterable[dict[str, Any]]) -> str:
    serialised = json_dumps(list(entries)).encode("utf-8")
    return sha256_bytes(serialised)


def copy_if_exists(source: Path | str, destination: Path | str) -> None:
    source_path = Path(source)
    destination_path = Path(destination)
    if not source_path.exists():
        return
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination_path)


def extract_json_payload(raw_text: str) -> str:
    if not raw_text:
        return "{}"
    stripped = raw_text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return "{}"
    return stripped[start:end + 1]


def env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
