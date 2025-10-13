#!/usr/bin/env bash
set -euo pipefail
NOTES_DIR="${1:-notes}"
OUT_FILE="$NOTES_DIR/combined.md"

first_title() {
  awk '/^# /{sub(/^# /,""); print; exit}' "$1"
}

echo "# Birleşik Notlar" > "$OUT_FILE"
echo >> "$OUT_FILE"
echo "Aşağıda, notların tamamı tek sayfada derlenmiştir. Ayrıntılar için özgün dosyalara bakınız." >> "$OUT_FILE"
echo >> "$OUT_FILE"
echo "## İçindekiler" >> "$OUT_FILE"

shopt -s nullglob
files=()
for f in "$NOTES_DIR"/*.md; do
  base="$(basename "$f")"
  [[ "$base" == "README.md" || "$base" == "combined.md" || "$base" == _* ]] && continue
  files+=("$f")
  title="$(first_title "$f")"; [[ -z "$title" ]] && title="${base%.md}" && title="${title//-/ }"
  anchor="$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]+/-/g')"
  echo "- [$title](#$anchor)" >> "$OUT_FILE"
done

echo >> "$OUT_FILE"

for f in "${files[@]}"; do
  base="$(basename "$f")"
  title="$(first_title "$f")"; [[ -z "$title" ]] && title="${base%.md}" && title="${title//-/ }"
  echo "## $title" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
  echo "Kaynak: \\`$base\\`" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
  # drop first H1 line if present
  awk 'NR==1 && /^# /{next} {print}' "$f" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
  echo "---" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
done

echo "Generated $OUT_FILE"

