#!/usr/bin/env bash
# 예시 사진을 R2 버킷에 올려요. 사용법: bash seed/upload-sample-photos.sh yuhan-csr-photos
set -euo pipefail
BUCKET="${1:-yuhan-csr-photos}"
cd "$(dirname "$0")/sample-photos"
for f in *.jpg; do
  key="${f%.jpg}"
  npx wrangler r2 object put "$BUCKET/$key" --file "$f" --content-type image/jpeg --remote
done
