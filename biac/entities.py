"""BIAC entities (what a grant, mask or filter applies to): comparison, display and wire format.

The per-category rules (attributes, how "all" is expressed) live in categories.py.
"""
from .categories import CASE_SENSITIVE, CATEGORIES, GLOBAL, GLOBAL_SENDS_ALL_ENTITIES, KEYED

# Legacy names (kept for callers of the facade): the non-data categories of the first versions.
NON_DATA_CATEGORIES_KEYS = {
    "DATA_PRODUCTS": ("domainName", "dataProductName"),
    "AI_MODELS": ("entityKey",),
    "USER_INTERFACE": ("uiFeature",),
}
NON_DATA_CATEGORIES = tuple(NON_DATA_CATEGORIES_KEYS)

# Used when the category is unknown (a read-back of a category this tool does not manage).
_FALLBACK_KEYS = ("catalog", "schema", "table", "tableBranch", "tableType", "branch", "function", "procedure",
                  "property", "value", "entityKey", "domainName", "dataProductName", "uiFeature")


def _norm(v, category=None, key=None):
    # The BIAC API normalizes catalog/schema/table/function names to
    # lowercase regardless of the case sent (confirmed on a lab cluster, 2026-10-01:
    # 'sales_5M' sent, 'sales_5m' stored) — compare case-insensitively so
    # idempotency checks don't false-negative into recreating the same
    # grant/mask on every run. An empty string reads as absent. A user name keeps its case.
    if v == "":
        return None
    if isinstance(v, str) and (category, key) not in CASE_SENSITIVE:
        return v.lower()
    return v


def _sorted_columns(entity):
    return sorted(_norm(c) for c in (entity.get("columns") or []))


def _all_flag(entity):
    """allEntities as the comparison sees it: a GLOBAL category has a single form, written either way."""
    spec = CATEGORIES.get(entity.get("category"))
    if spec and spec.shape == GLOBAL:
        return True
    return bool(entity.get("allEntities"))


def entities_equal(a, b):
    category = a.get("category")
    if _norm(category) != _norm(b.get("category")):
        return False
    if _all_flag(a) != _all_flag(b):
        return False
    spec = CATEGORIES.get(category)
    keys = spec.attrs if spec else _FALLBACK_KEYS
    return (all(_norm(a.get(k), category, k) == _norm(b.get(k), category, k) for k in keys if k != "columns")
            and _sorted_columns(a) == _sorted_columns(b))


def wire_entity(entity):
    """The entity as sent to the API: as written, except that a GLOBAL category carries `allEntities: true`
    (see categories.GLOBAL_SENDS_ALL_ENTITIES)."""
    spec = CATEGORIES.get(entity.get("category"))
    if spec and spec.shape == GLOBAL and GLOBAL_SENDS_ALL_ENTITIES:
        return {**entity, "allEntities": True}
    return entity


def _path(entity, fields):
    """Dotted path of the leading catalog/schema/narrow fields; a missing tail reads as `.*`."""
    parts = [entity.get(f) for f in fields]
    parts = [p for p in parts if p]  # catalog-only or catalog+schema grants omit the rest
    return ".".join(parts) + (".*" if len(parts) < len(fields) else "")


def describe_entity(entity):
    category = entity.get("category")
    spec = CATEGORIES.get(category)
    if category == "USER_INTERFACE":
        return f"UI:{entity.get('uiFeature') or '*'}"
    if category == "DATA_PRODUCTS":
        if not entity.get("domainName"):
            return "DATA_PRODUCTS:*"
        return f"DATA_PRODUCTS:{entity.get('domainName')}.{entity.get('dataProductName') or '*'}"
    if spec and spec.shape == KEYED:
        return f"{category}:*" if entity.get("allEntities") else f"{category}:{entity.get('entityKey', '?')}"
    if spec and spec.shape == GLOBAL:
        return category
    if category == "CATALOG_SESSION_PROPERTIES":
        return f"{category}:{entity.get('catalog')}.{entity.get('entityKey') or '*'}"
    if category == "TABLE_BRANCHES":
        return f"{category}:{_path(entity, ('catalog', 'schema', 'table'))}@{entity.get('branch') or '*'}"
    if category in ("SCHEMA_PROPERTIES", "TABLE_PROPERTIES"):
        fields = ("catalog", "schema") + (("table",) if category == "TABLE_PROPERTIES" else ())
        text = f"{category}:{_path(entity, fields)}#{entity.get('property') or '*'}"
        return text + (f"={entity['value']}" if entity.get("value") else "")
    if category == "PROCEDURES":
        return f"{category}:{_path(entity, ('catalog', 'schema', 'procedure'))}"
    narrow_field = "function" if category == "FUNCTIONS" else "table"
    base = _path(entity, ("catalog", "schema", narrow_field))
    if entity.get("tableBranch"):
        base += f"@{entity['tableBranch']}"
    if entity.get("tableType"):
        base += f"[{entity['tableType']}]"
    if entity.get("columns"):
        base += f".{','.join(entity['columns'])}"
    return base
