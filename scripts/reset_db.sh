#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

trap 'echo "Wystąpił błąd podczas resetowania bazy danych." >&2' ERR

run_psql_file() {
  local file_path="$1"
  docker compose exec -T postgres sh -lc '
    PGOPTIONS="--client-min-messages=warning" \
    psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"
  ' < "$file_path" >/dev/null
}

run_psql_sql() {
  docker compose exec -T postgres sh -lc '
    PGOPTIONS="--client-min-messages=warning" \
    psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"
  ' >/dev/null
}

echo "Uruchamianie bazy danych PostgreSQL..."
docker compose up -d postgres >/dev/null 2>&1
echo "PostgreSQL jest gotowy."

echo "Sprawdzanie i przygotowanie tabel detektora..."
run_psql_file "sql/003_detector_tables.sql"
echo "Struktura tabel została przygotowana."

echo "Czyszczenie dotychczasowych danych..."
run_psql_sql <<'SQL'
TRUNCATE TABLE anomaly_events, traffic_observations, device_listen_ports, device_settings, devices RESTART IDENTITY CASCADE;
SQL
echo "Baza została wyczyszczona."

echo "Ładowanie danych początkowych..."
run_psql_file "sql/002_seed.sql"
echo "Dane startowe zostały załadowane."

echo "Reset bazy danych został zakończony pomyślnie."