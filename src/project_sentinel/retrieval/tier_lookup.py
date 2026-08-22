"""Tra cứu Tier 2 bằng khóa tất định, không phải khớp chữ.

Thứ tự có ý: rule_id trước vì nó chính xác (một rule ứng một họ sink), cwe sau
vì nó gần đúng (một CWE bao nhiều sink khác nhau). Luật provenance 10 chỉ ràng
buộc với kết quả từ rule_id — xem spec §5.2.
"""

from __future__ import annotations

from pathlib import Path

from project_sentinel.retrieval.kb_schema import Tier2Entry, load_tier2


def lookup_tier2(
    rule_id: str,
    cwe: list[str] | None,
    tier2_dir: Path,
) -> tuple[Tier2Entry | None, str | None]:
    """Tra entry Tier 2 cho một finding. Trả về (entry, match_kind)."""
    entries = load_tier2(tier2_dir)
    if not entries:
        return None, None

    normalized_rule = (rule_id or "").strip()
    if normalized_rule:
        for entry in entries:
            if normalized_rule in entry.matches_rule_ids:
                return entry, "rule_id"

    wanted = {str(item).strip().upper() for item in (cwe or []) if str(item).strip()}
    if wanted:
        for entry in entries:
            if wanted & {item.upper() for item in entry.cwe}:
                return entry, "cwe"

    return None, None
