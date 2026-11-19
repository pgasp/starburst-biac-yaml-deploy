"""Structural validation and guardrails of a policy file. Offline, fail closed.

`validate_config` collects every problem and raises one ValueError listing
them; nothing is guessed for a missing security-relevant field. The checks of
each section of the file live in one small method of `_Validator`; the entity
checks are pure functions returning their error messages.
"""
import re
import sys

from .entities import NON_DATA_CATEGORIES, NON_DATA_CATEGORIES_KEYS
from .policy import (COLUMN_MASKS, EFFECTS, FORBIDDEN_ROLES, MAX_DESCRIPTION_LENGTH,
                     MAX_EXPRESSION_NAME_LENGTH, ROLE_NAME_RE, ROW_FILTERS, WIDENING_EFFECTS,
                     grant_actions)
from .remove_validation import check_remove

KNOWN_TOP_LEVEL_KEYS = {"roles", "grants", "location_grants", "column_masks", "row_filters", "assignments",
                        "allow_catalog_wide", "allowed_users", "allowed_groups", "remove"}
KNOWN_GRANT_KEYS = {"role", "effect", "action", "entity"}
KNOWN_LOCATION_GRANT_KEYS = {"role", "location", "grant_option"}
KNOWN_EXPRESSION_KEYS = {"name", "description", "expression", "role", "entity"}  # masks and filters


# --------------------------------------------------------------------------
# Entities (pure: return the list of error messages)
# --------------------------------------------------------------------------

def entity_errors(entity, context, tables_only=False):
    category = entity.get("category")
    if not tables_only and category in NON_DATA_CATEGORIES:
        return _non_data_entity_errors(entity, context)
    if entity.get("allEntities") is True:
        return [f"{context}: allEntities:true is forbidden by this tool "
                f"— scope the entity explicitly (catalog, or catalog+schema, "
                f"or catalog+schema+table/function)"]
    errors = []
    # A catalog-wide or schema-wide grant is expressed by OMITTING the
    # narrower field(s) entirely — 'catalog' alone means catalog.*,
    # 'catalog'+'schema' alone means catalog.schema.*. A literal '*'
    # string is NOT the mechanism for this (confirmed on a test
    # cluster, 2026-10-01) — reject it explicitly so it's never confused with
    # omission.
    for field in ("schema", "table", "function"):
        if entity.get(field) == "*":
            errors.append(f"{context}: '*' is not a valid wildcard for '{field}' — "
                          f"omit '{field}' entirely instead for a catalog/schema-wide grant")
    allowed = ("TABLES",) if tables_only else ("TABLES", "FUNCTIONS") + NON_DATA_CATEGORIES
    if category not in allowed:
        errors.append(f"{context}: unsupported or missing entity category {category!r} "
                      f"(expected one of {', '.join(allowed)})")
        return errors
    return errors + _data_scope_errors(entity, category, context)


def _data_scope_errors(entity, category, context):
    """TABLES / FUNCTIONS: a catalog is required, a table/function needs its schema."""
    errors = []
    if not entity.get("catalog"):
        errors.append(f"{context}: entity missing 'catalog'")
    if category == "TABLES" and entity.get("function"):
        errors.append(f"{context}: TABLES entity must not set 'function'")
    if category == "FUNCTIONS" and entity.get("table"):
        errors.append(f"{context}: FUNCTIONS entity must not set 'table'")
    narrow_field = "table" if category == "TABLES" else "function"
    if entity.get(narrow_field) and not entity.get("schema"):
        errors.append(f"{context}: '{narrow_field}' given without 'schema' "
                      f"— a {narrow_field} always needs its schema specified")
    return errors


def _non_data_entity_errors(entity, context):
    """DATA_PRODUCTS / AI_MODELS / USER_INTERFACE."""
    errors = []
    category = entity["category"]
    allowed_keys = {"category", "allEntities"} | set(NON_DATA_CATEGORIES_KEYS[category])
    stray = set(entity.keys()) - allowed_keys
    if stray:
        errors.append(f"{context}: {category} entity does not accept {sorted(stray)} "
                      f"(allowed: {sorted(allowed_keys)})")
    if category == "AI_MODELS":
        if entity.get("allEntities") is not True:
            errors.append(f"{context}: AI_MODELS entity must set 'allEntities: true' "
                          f"(per-model scoping is not supported by this tool)")
        return errors
    if entity.get("allEntities") is True:
        errors.append(f"{context}: allEntities:true is forbidden for {category} "
                      f"— scope it explicitly")
    if category == "DATA_PRODUCTS":
        if not entity.get("domainName"):
            errors.append(f"{context}: DATA_PRODUCTS entity needs 'domainName' "
                          f"(add 'dataProductName' to target a single data product)")
        if entity.get("domainName") == "*" or entity.get("dataProductName") == "*":
            errors.append(f"{context}: '*' is not a wildcard — omit 'dataProductName' instead")
    if category == "USER_INTERFACE" and not entity.get("uiFeature"):
        errors.append(f"{context}: USER_INTERFACE entity needs 'uiFeature'")
    return errors


# --------------------------------------------------------------------------
# The file, section by section
# --------------------------------------------------------------------------

class _Validator:
    def __init__(self, config):
        self.config = config
        self.errors = []
        self.warnings = []
        self.role_names = set()
        self.allow_catalog_wide = set()
        self.allowed_users = set()
        self.allowed_groups = set()

    def run(self):
        self.check_top_level_keys()
        self.read_guardrail_lists()
        self.check_roles()
        self.check_grants()
        self.check_location_grants()
        self.check_expression_objects(COLUMN_MASKS, self.check_mask_entity)
        self.check_expression_objects(ROW_FILTERS, self.check_row_filter_entity)
        self.check_assignments()
        check_remove(self)

    # --- shared checks ---

    def check_role_not_forbidden(self, role, context):
        if isinstance(role, str) and role.lower() in FORBIDDEN_ROLES:
            self.errors.append(f"{context}: role {role!r} is forbidden by this tool "
                               f"(never grant, mask, filter or assign anything on "
                               f"{' / '.join(sorted(FORBIDDEN_ROLES))})")

    def check_role_declared(self, role, subject):
        if role not in self.role_names:
            self.errors.append(f"{subject} references undeclared role: {role!r}")

    def check_unknown_keys(self, item, known, context):
        unknown_keys = set(item.keys()) - known
        if unknown_keys:
            self.errors.append(f"{context}: unknown key(s) {sorted(unknown_keys)}")

    def check_entity(self, entity, context, tables_only=False):
        self.errors.extend(entity_errors(entity, context, tables_only))

    # --- root ---

    def check_top_level_keys(self):
        unknown = set(self.config.keys()) - KNOWN_TOP_LEVEL_KEYS
        if unknown:
            self.errors.append(f"unknown top-level key(s): {sorted(unknown)}")

    def declared_names(self, key):
        """Root guardrail lists: must be a list of non-empty strings. A
        missing key means an empty list (fail closed)."""
        value = self.config.get(key)
        if value is None:
            return set()
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            self.errors.append(f"'{key}' must be a list of non-empty strings")
            return set()
        return set(value)

    def read_guardrail_lists(self):
        self.allow_catalog_wide = {c.lower() for c in self.declared_names("allow_catalog_wide")}
        self.allowed_users = self.declared_names("allowed_users")
        self.allowed_groups = self.declared_names("allowed_groups")

    # --- roles ---

    def check_roles(self):
        for r in self.config.get("roles", []):
            name = r.get("name")
            if not name or not ROLE_NAME_RE.match(name):
                self.errors.append(f"invalid role name: {name!r} (must match ^[a-z0-9_]+$)")
            self.role_names.add(name)
            self.check_role_not_forbidden(name, "role declaration")

    # --- grants ---

    def check_grants(self):
        for g in self.config.get("grants", []):
            self.check_grant(g)

    def check_grant(self, g):
        role = g.get("role")
        context = f"grant on role {role!r}"
        unknown_keys = set(g.keys()) - KNOWN_GRANT_KEYS
        if unknown_keys:
            self.errors.append(f"{context}: unknown key(s) {sorted(unknown_keys)} — "
                               f"likely an unquoted comma inside a flow mapping (e.g. "
                               f"'action: CREATE,DELETE,SELECT' does NOT mean a multi-action grant, "
                               f"it's parsed as stray keys DELETE/SELECT with null values — "
                               f"use 'action: [CREATE, DELETE, SELECT]' instead)")
        if role not in self.role_names:
            self.errors.append(f"grant references undeclared role: {role!r}")
        if g.get("effect") not in EFFECTS:
            self.errors.append(f"{context}: invalid or missing 'effect'")
        if not grant_actions(g):
            self.errors.append(f"{context}: missing 'action' (string or list of strings)")
        self.check_role_not_forbidden(role, context)
        entity = g.get("entity", {})
        self.check_entity(entity, context)
        self.check_catalog_wide(g, entity, context)

    def check_catalog_wide(self, g, entity, context):
        """ALLOW on a whole catalog needs an explicit opt-in (root 'allow_catalog_wide')."""
        if (g.get("effect") in WIDENING_EFFECTS
                and entity.get("category") in ("TABLES", "FUNCTIONS")
                and entity.get("catalog") and not entity.get("schema")
                and str(entity["catalog"]).lower() not in self.allow_catalog_wide):
            self.errors.append(f"{context}: {g.get('effect')} on the whole catalog "
                               f"{entity['catalog']!r} (no schema) requires an explicit opt-in — add "
                               f"'allow_catalog_wide: [{entity['catalog']}]' at the root of the file, "
                               f"or scope the grant to a schema")

    # --- location grants ---

    def check_location_grants(self):
        for lg in self.config.get("location_grants", []):
            role = lg.get("role")
            context = f"location_grant on role {role!r}"
            stray = set(lg.keys()) - KNOWN_LOCATION_GRANT_KEYS
            if stray:
                self.errors.append(f"{context}: unknown key(s) {sorted(stray)}")
            if role not in self.role_names:
                self.errors.append(f"location_grant references undeclared role: {role!r}")
            self.check_role_not_forbidden(role, context)
            loc = lg.get("location")
            if not isinstance(loc, str) or not re.match(r"^[a-z0-9]+://[^/]+/", loc):
                self.errors.append(f"{context}: 'location' must be a full URI "
                                   f"with a bucket and a path (e.g. s3://bucket/prefix/*), got {loc!r}")
            if not isinstance(lg.get("grant_option", False), bool):
                self.errors.append(f"{context}: 'grant_option' must be true/false")

    # --- column masks and row filters (same shape: a named expression + a role + a table) ---

    def check_expression_objects(self, kind, check_entity_shape):
        for item in self.config.get(kind.section, []):
            label = f"{kind.name} {item.get('name')!r}"
            self.check_expression_object(kind, label, item)
            entity = item.get("entity", {})
            check_entity_shape(label, entity)
            self.check_entity(entity, label, tables_only=True)

    def check_expression_object(self, kind, label, item):
        role = item.get("role")
        self.check_role_not_forbidden(role, label)
        self.check_unknown_keys(item, KNOWN_EXPRESSION_KEYS, label)
        self.check_role_declared(role, label)
        if not item.get("expression"):
            self.errors.append(f"{label}: missing 'expression'")
        name = item.get("name")
        if isinstance(name, str) and len(name) > MAX_EXPRESSION_NAME_LENGTH:
            self.errors.append(f"{kind.name} {name!r}: expression name is {len(name)} chars, exceeds the "
                               f"{MAX_EXPRESSION_NAME_LENGTH}-char BIAC API limit (rename it)")
        description = item.get("description", "")
        if len(description) > MAX_DESCRIPTION_LENGTH:
            self.errors.append(f"{label}: description is {len(description)} "
                               f"chars, exceeds the {MAX_DESCRIPTION_LENGTH}-char BIAC API limit")

    def check_mask_entity(self, label, entity):
        if not entity.get("columns"):
            self.errors.append(f"{label}: entity must list 'columns'")
        if not entity.get("table"):
            self.errors.append(f"{label}: entity must specify a 'table' "
                               f"— a column mask always targets one specific table, never catalog/schema-wide")

    def check_row_filter_entity(self, label, entity):
        if not entity.get("table"):
            self.errors.append(f"{label}: entity must specify a 'table' "
                               f"— a row filter always targets one specific table, never catalog/schema-wide")
        if entity.get("columns"):
            self.errors.append(f"{label}: entity must not specify 'columns' "
                               f"— row filters apply to whole rows, not specific columns (did you mean column_masks?)")

    # --- assignments ---

    def check_assignments(self):
        for a in self.config.get("assignments", []):
            role = a.get("role")
            self.check_role_not_forbidden(role, "assignment")
            self.check_role_declared(role, "assignment")
            self.check_assignment_subjects(a, role, "users", self.allowed_users, "allowed_users")
            self.check_assignment_subjects(a, role, "groups", self.allowed_groups, "allowed_groups")
            if not a.get("users") and not a.get("groups"):
                self.warnings.append(f"assignment on role {role!r}: no users or groups listed "
                                     f"(nothing to do here — check this isn't a mistake)")

    def check_assignment_subjects(self, a, role, key, allowed, declared_key):
        listed = a.get(key) or []
        if not isinstance(listed, list) or not all(isinstance(x, str) and x for x in listed):
            self.errors.append(f"assignment on role {role!r}: '{key}' must be a list of non-empty strings")
            return
        for name in listed:
            if name not in allowed:
                self.errors.append(f"assignment on role {role!r}: {key[:-1]} {name!r} is not declared in "
                                   f"the root '{declared_key}' list of this file (fail closed)")


def validate_config(config):
    """Structural validation. Aborts (raises) on anything malformed or
    ambiguous — never guesses a default for a missing security-relevant
    field. Non-blocking oddities are reported as warnings instead."""
    validator = _Validator(config)
    validator.run()
    if validator.warnings:
        print("Config warnings:", file=sys.stderr)
        for w in validator.warnings:
            print(f"  - {w}", file=sys.stderr)
    if validator.errors:
        raise ValueError("Config validation failed:\n" + "\n".join(f"  - {e}" for e in validator.errors))
