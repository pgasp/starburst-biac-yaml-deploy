"""Structural validation and guardrails of a policy file. Offline, fail closed.

`validate_config` collects every problem and raises one ValueError listing
them; nothing is guessed for a missing security-relevant field. The checks of
each section of the file live in one small method of `_Validator`; the entity
checks are pure functions returning their error messages.
"""
import re
import sys

from .categories import CATEGORIES, SCOPED, admin_opt_ins_needed, is_all_form, valid_admin_token
from .entity_validation import entity_errors  # noqa: F401  (re-exported: the pure entity checks)
from .policy import (APPLY_EFFECTS, COLUMN_MASKS, EFFECTS, FORBIDDEN_ROLES, MAX_DESCRIPTION_LENGTH,
                     MAX_EXPRESSION_NAME_LENGTH, ROLE_NAME_RE, ROW_FILTERS, WIDENING_EFFECTS,
                     apply_kind, grant_actions)
from .remove_validation import check_remove

KNOWN_TOP_LEVEL_KEYS = {"roles", "grants", "location_grants", "column_masks", "row_filters", "assignments",
                        "allow_catalog_wide", "allowed_users", "allowed_groups", "allow_admin_privileges", "remove"}
KNOWN_GRANT_KEYS = {"role", "effect", "action", "entity", "column_mask", "row_filter"}
KNOWN_LOCATION_GRANT_KEYS = {"role", "location", "grant_option"}
KNOWN_EXPRESSION_KEYS = {"name", "description", "expression", "role", "entity"}  # masks and filters


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
        self.allow_admin = set()

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
        self.allow_admin = self.declared_names("allow_admin_privileges")
        for token in sorted(self.allow_admin):
            if not valid_admin_token(token):
                self.errors.append(f"allow_admin_privileges: {token!r} is not 'CATEGORY' or 'CATEGORY:ACTION' of a "
                                   f"supported category/action (upper case, e.g. ROLES or QUERIES:KILL)")

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
        self.check_role_not_forbidden(role, context)
        entity = self.check_grant_content(g, context)
        if entity is not None:
            self.check_catalog_wide(g, entity, context)
            self.check_admin_privileges(g, entity, context)
            self.check_impersonation_targets(g, entity, context)

    def check_grant_content(self, g, context):
        """What a grant and a removed grant have in common: effect, actions per category, the APPLY_* expression
        key, the entity. Returns the entity (None when it is not a mapping)."""
        if g.get("effect") not in EFFECTS:
            self.errors.append(f"{context}: invalid or missing 'effect'")
        if not grant_actions(g):
            self.errors.append(f"{context}: missing 'action' (string or list of strings)")
        entity = g.get("entity")
        if not isinstance(entity, dict):
            self.errors.append(f"{context}: missing or invalid 'entity'")
            return None
        self.check_entity(entity, context)
        self.check_actions(g, entity, context)
        self.check_apply_grant(g, entity, context)
        return entity

    def check_actions(self, g, entity, context):
        """Offline per-category action matrix (categories.CATEGORIES)."""
        spec = CATEGORIES.get(entity.get("category"))
        if not spec:
            return   # the entity check already reported the category
        for action in grant_actions(g):
            if not isinstance(action, str):
                self.errors.append(f"{context}: action {action!r} must be a string")
            elif action not in spec.actions:
                self.errors.append(f"{context}: action {action!r} is not valid for category "
                                   f"{entity.get('category')} (allowed: {', '.join(spec.actions)})")

    def check_apply_grant(self, g, entity, context):
        """APPLY_* grants: a mask / filter named by `column_mask` / `row_filter`, on TABLES, action SELECT."""
        effect, kind = g.get("effect"), apply_kind(g)
        others = [k for k in ("column_mask", "row_filter") if k in g and not (kind and k == kind.name)]
        if kind is None:
            for key in others:
                self.errors.append(f"{context}: '{key}' is only for the APPLY_* effects "
                                   f"({', '.join(APPLY_EFFECTS)})")
            return
        for key in others:
            self.errors.append(f"{context}: {effect} takes '{kind.name}', not '{key}'")
        name = g.get(kind.name)
        if not isinstance(name, str) or not name:
            self.errors.append(f"{context}: {effect} needs '{kind.name}: <expression name>' "
                               f"(declared under '{kind.section}' in this file, or already on the cluster)")
        elif len(name) > MAX_EXPRESSION_NAME_LENGTH:
            self.errors.append(f"{context}: expression name {name!r} is {len(name)} chars, exceeds the "
                               f"{MAX_EXPRESSION_NAME_LENGTH}-char BIAC API limit")
        if entity.get("category") != "TABLES":
            self.errors.append(f"{context}: {effect} applies to a TABLES entity only")
        if [a for a in grant_actions(g) if a != "SELECT"] or len(grant_actions(g)) != 1:
            self.errors.append(f"{context}: {effect} takes the single action SELECT "
                               f"(masks and filters apply to SELECT)")
        if entity.get("category") == "TABLES":
            (self.check_mask_entity if kind is COLUMN_MASKS else self.check_row_filter_entity)(context, entity)

    def check_catalog_wide(self, g, entity, context):
        """ALLOW on a whole catalog needs an explicit opt-in (root 'allow_catalog_wide')."""
        if (g.get("effect") in WIDENING_EFFECTS and _catalog_wide(entity)
                and str(entity["catalog"]).lower() not in self.allow_catalog_wide):
            self.errors.append(f"{context}: {g.get('effect')} on the whole catalog "
                               f"{entity['catalog']!r} (no schema) requires an explicit opt-in — add "
                               f"'allow_catalog_wide: [{entity['catalog']}]' at the root of the file, "
                               f"or scope the grant to a schema")

    def check_admin_privileges(self, g, entity, context):
        """A widening grant on an administrative category, or on an 'all' form, needs the root opt-in
        'allow_admin_privileges' (the category, or CATEGORY:ACTION). DENY never does. Delegating the right to
        apply a mask / filter (APPLY_*_WITH_GRANT_OPTION) needs the category of its expressions."""
        effect = g.get("effect")
        if effect not in WIDENING_EFFECTS or not isinstance(entity.get("category"), str):
            return
        needed = admin_opt_ins_needed(entity["category"], grant_actions(g), entity)
        kind = apply_kind(g)
        if kind and effect.endswith("_WITH_GRANT_OPTION"):
            needed.append((kind.admin_category, None))
        for category, action in needed:
            if category in self.allow_admin or (action and f"{category}:{action}" in self.allow_admin):
                continue
            if action:
                what, tokens = f"{action} on {category} ({_admin_reason(entity)})", f"{category}:{action}' (or '{category}"
            else:
                what, tokens = f"delegating a {kind.name} (grant option)", category
            self.errors.append(f"{context}: {effect} {what} requires an explicit opt-in — add "
                               f"'allow_admin_privileges: [{tokens}]' at the root of the file, or scope the grant")

    def check_impersonation_targets(self, g, entity, context):
        """Allowing a role to impersonate a named user is subject to `allowed_users`, like an assignment;
        a role or a user named sysadmin/public can never be the target of a widening grant."""
        if g.get("effect") not in WIDENING_EFFECTS:
            return
        key = entity.get("entityKey")
        if entity.get("category") == "USERS" and isinstance(key, str) and key not in self.allowed_users:
            self.errors.append(f"{context}: IMPERSONATE on user {key!r}, which is not declared in the root "
                               f"'allowed_users' list of this file (fail closed)")
        if entity.get("category") == "ROLES" and isinstance(key, str) and key.lower() in FORBIDDEN_ROLES:
            self.errors.append(f"{context}: role {key!r} is forbidden by this tool (never grant anything on "
                               f"{' / '.join(sorted(FORBIDDEN_ROLES))})")

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


def _catalog_wide(entity):
    """A catalog-rooted entity with nothing narrower than the catalog: everything in the catalog."""
    spec = CATEGORIES.get(entity.get("category"))
    if not spec or spec.shape != SCOPED or not entity.get("catalog"):
        return False
    if entity["category"] == "CATALOG_SESSION_PROPERTIES":
        return not entity.get("entityKey")
    return not entity.get("schema")


def _admin_reason(entity):
    return "all entities" if is_all_form(entity) else "administrative category"


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
