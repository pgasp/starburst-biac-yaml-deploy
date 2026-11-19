"""Structural validation of one entity (offline, pure): returns the list of error messages.

The rules per category come from categories.py: which attributes it accepts, which
are required, how "all entities" is expressed. A guardrail (admin opt-in, catalog-wide
opt-in) is NOT checked here: it depends on the grant, not on the entity alone.
"""
from .categories import CATEGORIES, ENUM_ATTRS, KEYED, OMIT, OUT_OF_SCOPE_CATEGORIES, SCOPED


def entity_errors(entity, context, tables_only=False):
    if not isinstance(entity, dict):
        return [f"{context}: missing or invalid 'entity' (expected a mapping)"]
    category = entity.get("category")
    allowed = ("TABLES",) if tables_only else tuple(CATEGORIES)
    if category in OUT_OF_SCOPE_CATEGORIES and not tables_only:
        return [f"{context}: entity category {category!r} is out of scope for this tool "
                f"(Spark, notebooks and S3 governance are not managed here)"]
    if category not in allowed:
        return [f"{context}: unsupported or missing entity category {category!r} "
                f"(expected one of {', '.join(allowed)})"]
    spec = CATEGORIES[category]
    errors = _attribute_errors(entity, category, spec, context)
    if errors:
        return errors   # the shape rules below assume well-formed attributes
    return _all_entities_errors(entity, category, spec, context) + _shape_errors(entity, spec, context)


def _attribute_errors(entity, category, spec, context):
    """Known attributes only, each a non-empty string (columns: a list of them), '*' refused, enums checked."""
    errors = []
    accepted = {"category", "allEntities"} | set(spec.attrs)
    stray = set(entity) - accepted
    if stray:
        errors.append(f"{context}: {category} entity does not accept {sorted(stray)} "
                      f"(allowed: {sorted(accepted)})")
    for attr in spec.attrs:
        if attr not in entity:
            continue
        value = entity[attr]
        if attr == "columns":
            if not isinstance(value, list) or not all(isinstance(c, str) and c for c in value):
                errors.append(f"{context}: 'columns' must be a list of non-empty column names")
            continue
        if not isinstance(value, str) or not value:
            errors.append(f"{context}: '{attr}' must be a non-empty string — omit it instead "
                          f"(an empty value does not reliably work)")
        elif value == "*":
            errors.append(_wildcard_error(context, attr))
        elif attr in ENUM_ATTRS and value not in ENUM_ATTRS[attr]:
            errors.append(f"{context}: invalid {attr} {value!r} (expected one of {', '.join(ENUM_ATTRS[attr])})")
    flag = entity.get("allEntities")
    if flag is not None and not isinstance(flag, bool):
        errors.append(f"{context}: 'allEntities' must be true or false")
    return errors


def _wildcard_error(context, attr):
    # A catalog-wide or schema-wide grant is expressed by OMITTING the narrower field(s) — 'catalog' alone means
    # catalog.*, 'catalog'+'schema' alone means catalog.schema.*. A literal '*' string is NOT the mechanism for
    # this (confirmed on a test cluster, 2026-10-01) — reject it explicitly so it's never confused with omission.
    if attr in ("schema", "table", "function"):
        return (f"{context}: '*' is not a valid wildcard for '{attr}' — "
                f"omit '{attr}' entirely instead for a catalog/schema-wide grant")
    return (f"{context}: '*' is not a valid wildcard for '{attr}' — omit it (or, for a category with an "
            f"entityKey, write 'allEntities: true')")


def _all_entities_errors(entity, category, spec, context):
    all_true = entity.get("allEntities") is True
    if spec.shape == SCOPED and all_true:
        return [f"{context}: allEntities:true is forbidden by this tool "
                f"— scope the entity explicitly (catalog, or catalog+schema, "
                f"or catalog+schema+table/function)"]
    if spec.shape == OMIT and all_true:
        return [f"{context}: allEntities:true is forbidden for {category} "
                f"— scope it explicitly (omit the narrowing attribute for the 'all' form)"]
    if spec.shape == KEYED:
        has_key = "entityKey" in entity
        if all_true and has_key:
            return [f"{context}: {category} entity sets both 'entityKey' and 'allEntities: true' — pick one"]
        if not all_true and not has_key:
            return [f"{context}: {category} entity needs 'entityKey' (one {_what(category)}) or "
                    f"'allEntities: true' (all of them) — omitting both is ambiguous and refused"]
    return []


def _what(category):
    return {"USERS": "user name", "ROLES": "role name", "AI_MODELS": "model", "AGENT_SKILLS": "skill",
            "EXTERNAL_MCP_SERVERS": "server", "SYSTEM_SESSION_PROPERTIES": "property"}.get(category, "name")


def _shape_errors(entity, spec, context):
    errors = []
    if spec.shape == SCOPED and not entity.get("catalog"):
        errors.append(f"{context}: entity missing 'catalog'")
    for narrow, wider in spec.chain:
        if entity.get(narrow) and not entity.get(wider):
            errors.append(f"{context}: '{narrow}' given without '{wider}' "
                          f"— a {narrow} always needs its {wider} specified")
    return errors
