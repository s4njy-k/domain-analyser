#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(uname -s)" == "Linux" ]] && command -v apt-get >/dev/null 2>&1; then
  SUDO=""
  if [[ "${EUID}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
  ${SUDO} apt-get update
  ${SUDO} apt-get install -y \
    libcairo2 \
    libffi-dev \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    libharfbuzz0b \
    libharfbuzz-subset0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    shared-mime-info \
    fonts-liberation
fi

python3 -m pip install --upgrade pip
python3 -m pip install --use-deprecated=legacy-resolver -r "${ROOT_DIR}/requirements.txt"
python3 -m pip install grpcio grpcio-status lxml_html_clean
python3 -m playwright install chromium

mkdir -p \
  "${ROOT_DIR}/input" \
  "${ROOT_DIR}/output/screenshots" \
  "${ROOT_DIR}/output/reports" \
  "${ROOT_DIR}/output/data" \
  "${ROOT_DIR}/output/dashboard" \
  "${ROOT_DIR}/docs/assets" \
  "${ROOT_DIR}/docs/data" \
  "${ROOT_DIR}/docs/domains" \
  "${ROOT_DIR}/docs/evidence"

if [[ ! -f "${ROOT_DIR}/.env" && -f "${ROOT_DIR}/.env.example" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
fi

echo "Environment prepared in ${ROOT_DIR}"
