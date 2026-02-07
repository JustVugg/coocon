#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/4] Checking prerequisites"
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
command -v cargo >/dev/null || { echo "cargo not found"; exit 1; }

echo "[2/4] Building daemon"
cargo build --release

if [[ -f "target/release/coocon" || -f "target/release/coocon.exe" ]]; then
  echo "Daemon build complete"
else
  echo "Daemon binary not found after build"
  exit 1
fi

echo "[3/4] Installing Python package (editable)"
python3 -m pip install -e .

echo "[4/4] Done"
echo "Run: coocon start"
