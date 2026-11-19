"""BIAC entities (what a grant, mask or filter applies to): comparison and display."""

# Non-data entity categories and the attributes each accepts besides
# category/allEntities (formats read back from the BIAC API, 2026-10-15).
NON_DATA_CATEGORIES_KEYS = {
    "DATA_PRODUCTS": ("domainName", "dataProductName"),
    "AI_MODELS": (),
    "USER_INTERFACE": ("uiFeature",),
}
NON_DATA_CATEGORIES = tuple(NON_DATA_CATEGORIES_KEYS)

_COMPARED_KEYS = ("category", "catalog", "schema", "table", "function",
                  "domainName", "dataProductName", "uiFeature")


def _norm(v):
    # The BIAC API normalizes catalog/schema/table/function names to
    # lowercase regardless of the case sent (confirmed on a lab cluster, 2026-10-01:
    # 'sales_5M' sent, 'sales_5m' stored) — compare case-insensitively so
    # idempotency checks don't false-negative into recreating the same
    # grant/mask on every run.
    return v.lower() if isinstance(v, str) else v


def _sorted_columns(entity):
    return sorted(_norm(c) for c in (entity.get("columns") or []))


def entities_equal(a, b):
    if bool(a.get("allEntities")) != bool(b.get("allEntities")):
        return False
    a_cols, b_cols = _sorted_columns(a), _sorted_columns(b)
    return all(_norm(a.get(k)) == _norm(b.get(k)) for k in _COMPARED_KEYS) and a_cols == b_cols


def describe_entity(entity):
    category = entity.get("category")
    if category == "AI_MODELS":
        return "AI_MODELS:*" if entity.get("allEntities") else f"AI_MODELS:{entity.get('entityKey', '?')}"
    if category == "USER_INTERFACE":
        return f"UI:{entity.get('uiFeature')}"
    if category == "DATA_PRODUCTS":
        if entity.get("allEntities"):
            return "DATA_PRODUCTS:*"
        return f"DATA_PRODUCTS:{entity.get('domainName')}.{entity.get('dataProductName') or '*'}"
    narrow_field = "function" if category == "FUNCTIONS" else "table"
    parts = [entity.get("catalog"), entity.get("schema"), entity.get(narrow_field)]
    parts = [p for p in parts if p]  # catalog-only or catalog+schema grants omit the rest
    base = ".".join(parts) + (".*" if len(parts) < 3 else "")
    if entity.get("columns"):
        base += f".{','.join(entity['columns'])}"
    return base
