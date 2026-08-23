"""Doc frontmatter YAML cua entry Tier 2 va kiem no du dung hop dong.

`keyword_search.parse_markdown` co bo doc frontmatter rieng, nhung no viet tay
va chi hieu `title:` voi `tags:` mot dong. Tier 2 can list nhieu dong va folded
scalar, nen o day dung PyYAML that. Hai bo doc ton tai song song la co y: Tier 1
van di duong cu, khong bi anh huong.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CANONICAL_CATEGORIES: frozenset[str] = frozenset({
    "SQL Injection",
    "XSS",
    "Command Injection",
    "Path Traversal",
    "Insecure Deserialization",
    "CSRF",
    "JWT Weak Verification",
    "Hardcoded Credentials",
    "Insecure Randomness",
    "XXE",
    "Security Misconfiguration",
    "Information Disclosure",
})

_REQUIRED = (
    "id",
    "canonical_category",
    "cwe",
    "tier1_parent",
    "language",
    "sink_signatures",
    "safe_alternative",
    "exploitable_when",
    "not_exploitable_when",
)


class KbSchemaError(ValueError):
    """Entry Tier 2 khong dung hop dong. Kem duong dan de sua duoc ngay."""


@dataclass(frozen=True)
class Tier2Entry:
    path: Path
    id: str
    canonical_category: str
    cwe: tuple[str, ...]
    tier1_parent: str
    language: str
    sink_signatures: tuple[str, ...]
    matches_rule_ids: tuple[str, ...]
    safe_alternative: str
    exploitable_when: str
    not_exploitable_when: str
    no_rule_yet: bool
    body: str
    references: tuple[str, ...] = ()


def _split_frontmatter(text: str, path: Path) -> tuple[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise KbSchemaError(f"{path}: thieu frontmatter mo dau bang ---")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i]), "\n".join(lines[i + 1:]).strip()
    raise KbSchemaError(f"{path}: frontmatter khong duoc dong bang ---")


def _as_str_tuple(value: Any, field: str, path: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise KbSchemaError(f"{path}: '{field}' phai la danh sach")
    out = tuple(str(item).strip() for item in value if str(item).strip())
    if not out:
        raise KbSchemaError(f"{path}: '{field}' rong")
    return out


def parse_tier2(path: Path) -> Tier2Entry:
    """Doc mot entry Tier 2. Nem KbSchemaError neu sai hop dong."""
    raw, body = _split_frontmatter(path.read_text(encoding="utf-8"), path)
    try:
        meta = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise KbSchemaError(f"{path}: frontmatter khong phai YAML hop le: {exc}") from exc
    if not isinstance(meta, dict):
        raise KbSchemaError(f"{path}: frontmatter phai la mot mapping")

    if meta.get("tier") != 2:
        raise KbSchemaError(f"{path}: 'tier' phai bang 2")

    missing = [key for key in _REQUIRED if key not in meta]
    if missing:
        raise KbSchemaError(f"{path}: thieu truong bat buoc: {', '.join(missing)}")

    category = str(meta["canonical_category"]).strip()
    if category not in CANONICAL_CATEGORIES:
        raise KbSchemaError(
            f"{path}: canonical_category '{category}' khong nam trong tap dong. "
            f"Cho phep: {', '.join(sorted(CANONICAL_CATEGORIES))}"
        )

    no_rule_yet = bool(meta.get("no_rule_yet", False))
    rule_ids_raw = meta.get("matches_rule_ids")
    rule_ids = () if no_rule_yet and not rule_ids_raw else _as_str_tuple(
        rule_ids_raw, "matches_rule_ids", path
    )

    references_raw = meta.get("references")
    references: tuple[str, ...] = ()
    if references_raw is not None:
        # references chua danh sach URL tham khao chuan hoa (OWASP, CWE, Oracle docs...).
        # Kiem tra tung URL phai bat dau bang http:// hoac https:// de loai bo URL sai dinh dang,
        # tranh loi link hoac schema khong dong nhat tren giao dien Web va prompt.
        refs_tuple = _as_str_tuple(references_raw, "references", path)
        for ref in refs_tuple:
            if not (ref.startswith("http://") or ref.startswith("https://")):
                raise KbSchemaError(
                    f"{path}: reference '{ref}' khong phai URL hop le (phai bat dau bang http:// hoac https://)"
                )
        references = refs_tuple

    return Tier2Entry(
        path=path,
        id=str(meta["id"]).strip(),
        canonical_category=category,
        cwe=_as_str_tuple(meta["cwe"], "cwe", path),
        tier1_parent=str(meta["tier1_parent"]).strip(),
        language=str(meta["language"]).strip(),
        sink_signatures=_as_str_tuple(meta["sink_signatures"], "sink_signatures", path),
        matches_rule_ids=rule_ids,
        safe_alternative=str(meta["safe_alternative"]).strip(),
        exploitable_when=str(meta["exploitable_when"]).strip(),
        not_exploitable_when=str(meta["not_exploitable_when"]).strip(),
        no_rule_yet=no_rule_yet,
        body=body,
        references=references,
    )


def load_tier2(tier2_dir: Path) -> list[Tier2Entry]:
    """Doc moi entry trong thu muc. Thu muc khong ton tai thi tra ve rong."""
    if not tier2_dir.is_dir():
        return []
    return [parse_tier2(path) for path in sorted(tier2_dir.glob("*.md"))]
