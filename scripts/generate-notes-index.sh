#!/usr/bin/env bash
set -euo pipefail
NOTES_DIR="${1:-notes}"
OUT_FILE="$NOTES_DIR/README.md"

title_of() {
  awk 'BEGIN{FS="\n"} /^# /{sub(/^# /,""); print; exit}' "$1"
}
tags_of() {
  awk 'match($0,/^(Etiketler|Tags) *: *(.*)$/){print substr($0,RSTART+RLENGTH-(RLENGTH-\
index(substr($0,RSTART,RLENGTH),":")-1)); exit}' "$1" | sed 's/^ *//;s/ *$//' || true
}
summary_of() {
  awk 'BEGIN{p=0} { if(/^#/||/^\s*$/){if(p==0)next}; if(p==0){printf $0; p=1; next} if(/^\s*$/){exit} printf " %s",$0 }' "$1" | sed 's/\s\+/ /g' | cut -c1-160
}

echo "# Notlar Dizini" > "$OUT_FILE"
echo >> "$OUT_FILE"
echo "Bu sayfa \`scripts/generate-notes-index.sh\` ile otomatik üretilir. Birleşik özet: \`notes/combined.md\`." >> "$OUT_FILE"
echo >> "$OUT_FILE"
echo "| Başlık | Tarih | Etiketler | Dosya |" >> "$OUT_FILE"
echo "|---|---|---|---|" >> "$OUT_FILE"

shopt -s nullglob
for f in "$NOTES_DIR"/*.md; do
  base="$(basename "$f")"
  [[ "$base" == "README.md" || "$base" == "combined.md" || "$base" == _* ]] && continue
  title="$(title_of "$f")"; [[ -z "$title" ]] && title="${base%.md}" && title="${title//-/ }"
  tags="$(tags_of "$f" || true)"
  date="$(date -r "$f" +%F 2>/dev/null || stat -f %Sm -t %F "$f" 2>/dev/null || echo "")"
  summary="$(summary_of "$f" || true)"
  echo "| [$title](./$base) | ${date} | ${tags} | \`$base\` |" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
  echo "> ${summary}" >> "$OUT_FILE"
  echo >> "$OUT_FILE"
done

echo "Generated $OUT_FILE"

