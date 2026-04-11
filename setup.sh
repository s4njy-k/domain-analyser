#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
