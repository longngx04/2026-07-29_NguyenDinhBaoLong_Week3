#!/usr/bin/env bash
# ==============================================================================
# scripts/check-kb-links.sh — Kiem tra cac URL tham chieu trong KB co con song khong
#
# Chu thich:
# Bo test toan ven hien tai (test_kb_integrity.py) chi kiem tra DINH DANG URL
# (phai bat dau bang http:// hoac https://), khong kiem tra URL co thuc su ton tai
# va song hay khong (HTTP 200) — do la cach 2 link 404 da lot vao co so tri thuc.
#
# Script nay gom moi URL trong frontmatter `references:` cua:
#   - data/knowledge-base/tier1/*.md
#   - data/knowledge-base/tier2/*.md
# Voi moi URL, script gui yeu cau curl de xac thuc HTTP status code la 200.
# Script CAN KET NOI MANG (Internet) nen KHONG nam trong `make quality` hoac CI mac dinh.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON="${PYTHON:-python3}"

echo "======================================================================"
echo "Project Sentinel — Kiem tra URL tham chieu trong Knowledge Base"
echo "======================================================================"

# Gom tat ca cac URL duy nhat tu frontmatter `references:`
URLS=$("$PYTHON" -c "
import glob
import sys
import yaml

urls = set()
files = sorted(glob.glob('data/knowledge-base/tier1/*.md') + glob.glob('data/knowledge-base/tier2/*.md'))
for path in files:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                fm = yaml.safe_load(parts[1])
                if isinstance(fm, dict) and 'references' in fm:
                    refs = fm['references']
                    if isinstance(refs, list):
                        for u in refs:
                            if isinstance(u, str) and u.strip():
                                urls.add(u.strip())
    except Exception as e:
        print(f'Loi doc file {path}: {e}', file=sys.stderr)

for u in sorted(urls):
    print(u)
")

if [ -z "$URLS" ]; then
    echo "Khong tim thay URL nao trong frontmatter references."
    exit 0
fi

TOTAL=$(echo "$URLS" | wc -l)
echo "Tim thay $TOTAL URL duy nhat trong Tier 1 va Tier 2."
echo "----------------------------------------------------------------------"

FAILED=0
PASSED=0
COUNT=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    COUNT=$((COUNT + 1))
    
    # Gui HTTP request bang curl, follow redirect, timeout toi da 15 giay
    HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -L --max-time 15 "$url" 2>/dev/null || echo "000")
    
    if [ "$HTTP_CODE" = "200" ]; then
        printf "[%2d/%2d] OK (200): %s\n" "$COUNT" "$TOTAL" "$url"
        PASSED=$((PASSED + 1))
    else
        printf "[%2d/%2d] FAIL (%s): %s\n" "$COUNT" "$TOTAL" "$HTTP_CODE" "$url" >&2
        FAILED=$((FAILED + 1))
    fi
done <<< "$URLS"

echo "======================================================================"
echo "Ket qua kiem tra: $PASSED URL song (200), $FAILED URL that bai / tong $TOTAL URL."

if [ "$FAILED" -gt 0 ]; then
    echo "Loi: Co it nhat mot URL chet hoac khong tra ve HTTP 200." >&2
    exit 1
fi

echo "Tat ca URL tham chieu trong Knowledge Base deu hoat dong tot (HTTP 200)."
exit 0
