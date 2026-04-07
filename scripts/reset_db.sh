#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Uruchamiam postgres..."
docker compose up -d postgres >/dev/null

echo "==> Tworzę tabele detektora, jeśli ich jeszcze nie ma..."
docker compose exec -T postgres sh -lc \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < sql/003_detector_tables.sql

echo "==> Czyszczę dane..."
docker compose exec -T postgres sh -lc '
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
TRUNCATE TABLE anomaly_events, traffic_observations, device_listen_ports, device_settings, devices RESTART IDENTITY CASCADE;
SQL
'

echo "==> Ładuję seed..."
docker compose exec -T postgres sh -lc \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < sql/002_seed.sql

echo "==> Reset bazy zakończony."