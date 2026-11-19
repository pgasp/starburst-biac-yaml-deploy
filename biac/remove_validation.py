"""Validation of the root key `remove:` (offline, fail closed).

Called by `_Validator.check_remove`; it reuses the validator's helpers
(`errors`, `check_entity`, the mask/filter entity checks, the forbidden-role
check) so a removal is held to the same rules as the creation it undoes.
"""
import re

from .entities import entities_equal
from .policy import COLUMN_MASKS, ROLE_NAME_RE, ROW_FILTERS, apply_expression_name, grant_actions

KNOWN_REMOVE_KEYS = {"grants", "location_grants", "column_masks", "row_filters", "assignments", "roles"}
# An entry cut from a creation section can be pasted as is: the keys that only
# matter for a creation (expression, description) are accepted and ignored.
KNOWN_REMOVE_GRANT_KEYS = {"role", "effect", "action", "entity", "column_mask", "row_filter"}
KNOWN_REMOVE_LOCATION_GRANT_KEYS = {"role", "location", "grant_option"}
KNOWN_REMOVE_EXPRESSION_KEYS = {"name", "role", "entity", "delete_expression", "expression", "description"}
KNOWN_REMOVE_ASSIGNMENT_KEYS = {"role", "users", "groups"}


def _dicts(config, key):
    return [x for x in (config.get(key) or []) if isinstance(x, dict)]


class _RemoveChecks:
    def __init__(self, v):
        self.v = v
        self.config = v.config
        self.section = v.config.get("remove") or {}

    def error(self, message):
        self.v.errors.append(message)

    def run(self):
        if not isinstance(self.section, dict):
            return self.error("'remove' must be a mapping (grants, location_grants, column_masks, "
                              "row_filters, assignments, roles)")
        stray = set(self.section) - KNOWN_REMOVE_KEYS
        if stray:
            self.error(f"remove: unknown key(s) {sorted(stray)}")
        self.grants()
        self.location_grants()
        self.expression_entries(COLUMN_MASKS, self.v.check_mask_entity)
        self.expression_entries(ROW_FILTERS, self.v.check_row_filter_entity)
        self.assignments()
        self.roles()
        self.conflicts()

    def entries(self, key):
        """The entries of one remove section, dicts only (anything else is reported)."""
        value = self.section.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(f"remove.{key} must be a list")
            return []
        bad = [x for x in value if not isinstance(x, dict)]
        if bad and key != "roles":
            self.error(f"remove.{key}: every entry must be a mapping")
        return [x for x in value if isinstance(x, dict)]

    def role(self, role, context):
        if not isinstance(role, str) or not ROLE_NAME_RE.match(role):
            self.error(f"{context}: invalid role name {role!r} (must match ^[a-z0-9_]+$)")
        self.v.check_role_not_forbidden(role, context)

    def entity(self, entry, context, tables_only=False):
        entity = entry.get("entity")
        if not isinstance(entity, dict):
            self.error(f"{context}: missing or invalid 'entity'")
            return None
        self.v.check_entity(entity, context, tables_only=tables_only)
        return entity

    # --- sections ---

    def grants(self):
        for g in self.entries("grants"):
            context = f"remove.grants on role {g.get('role')!r}"
            self.v.check_unknown_keys(g, KNOWN_REMOVE_GRANT_KEYS, context)
            self.role(g.get("role"), context)
            # same effect / action matrix / APPLY_* key / entity rules as the creation; no admin opt-in:
            # a removal never widens anything
            self.v.check_grant_content(g, context)

    def location_grants(self):
        for lg in self.entries("location_grants"):
            context = f"remove.location_grants on role {lg.get('role')!r}"
            self.v.check_unknown_keys(lg, KNOWN_REMOVE_LOCATION_GRANT_KEYS, context)
            self.role(lg.get("role"), context)
            loc = lg.get("location")
            if not isinstance(loc, str) or not re.match(r"^[a-z0-9]+://[^/]+/", loc):
                self.error(f"{context}: 'location' must be a full URI with a bucket and a path, got {loc!r}")
            if not isinstance(lg.get("grant_option", False), bool):
                self.error(f"{context}: 'grant_option' must be true/false")

    def expression_entries(self, kind, check_entity_shape):
        for item in self.entries(kind.section):
            context = f"remove.{kind.section} {item.get('name')!r}"
            self.v.check_unknown_keys(item, KNOWN_REMOVE_EXPRESSION_KEYS, context)
            self.role(item.get("role"), context)
            if not isinstance(item.get("name"), str) or not item["name"]:
                self.error(f"{context}: missing 'name' (the expression to detach)")
            if not isinstance(item.get("delete_expression", False), bool):
                self.error(f"{context}: 'delete_expression' must be true/false")
            entity = self.entity(item, context, tables_only=True)
            if entity is not None:
                check_entity_shape(context, entity)

    def assignments(self):
        for a in self.entries("assignments"):
            role = a.get("role")
            context = f"remove.assignments on role {role!r}"
            self.v.check_unknown_keys(a, KNOWN_REMOVE_ASSIGNMENT_KEYS, context)
            self.role(role, context)
            self.v.check_assignment_subjects(a, role, "users", self.v.allowed_users, "allowed_users")
            self.v.check_assignment_subjects(a, role, "groups", self.v.allowed_groups, "allowed_groups")
            if not a.get("users") and not a.get("groups"):
                self.v.warnings.append(f"{context}: no users or groups listed (nothing to do here)")

    def role_names(self):
        value = self.section.get("roles")
        if value is None:
            return []
        if not isinstance(value, list):
            self.error("remove.roles must be a list of role names")
            return []
        return value

    def roles(self):
        for name in self.role_names():
            self.role(name, "remove.roles")

    # --- an object cannot be both created and removed ---

    def conflicts(self):
        self.grant_conflicts()
        self.location_conflicts()
        for kind in (COLUMN_MASKS, ROW_FILTERS):
            self.expression_conflicts(kind)
        self.assignment_conflicts()
        self.role_conflicts()

    def grant_conflicts(self):
        for r in self.entries("grants"):
            for c in _dicts(self.config, "grants"):
                same = (r.get("role") == c.get("role") and r.get("effect") == c.get("effect")
                        and set(grant_actions(r)) & set(grant_actions(c))
                        and apply_expression_name(r) == apply_expression_name(c)
                        and _same_entity(r, c))
                if same:
                    self.error(f"remove.grants on role {r.get('role')!r}: the same grant "
                               f"({r.get('effect')} {sorted(set(grant_actions(r)) & set(grant_actions(c)))}) is also "
                               f"declared in 'grants' — an object cannot be created and removed in one file")

    def location_conflicts(self):
        for r in self.entries("location_grants"):
            for c in _dicts(self.config, "location_grants"):
                if (r.get("role") == c.get("role") and r.get("location") == c.get("location")
                        and bool(r.get("grant_option")) == bool(c.get("grant_option"))):
                    self.error(f"remove.location_grants on role {r.get('role')!r}: {r.get('location')!r} is also "
                               f"declared in 'location_grants' — an object cannot be created and removed in one file")

    def expression_conflicts(self, kind):
        created = _dicts(self.config, kind.section)
        for r in self.entries(kind.section):
            for c in created:
                if (r.get("role") == c.get("role") and r.get("name") == c.get("name") and _same_entity(r, c)):
                    self.error(f"remove.{kind.section} {r.get('name')!r} on role {r.get('role')!r}: also declared "
                               f"in '{kind.section}' — an object cannot be created and removed in one file")
            if r.get("delete_expression") is True and any(r.get("name") == c.get("name") for c in created):
                self.error(f"remove.{kind.section} {r.get('name')!r}: delete_expression is refused, the expression "
                           f"is also declared in '{kind.section}' (it would be created and deleted in one file)")

    def assignment_conflicts(self):
        for r in self.entries("assignments"):
            for c in _dicts(self.config, "assignments"):
                if r.get("role") != c.get("role"):
                    continue
                for key in ("users", "groups"):
                    both = set(_names(r, key)) & set(_names(c, key))
                    if both:
                        self.error(f"remove.assignments on role {r.get('role')!r}: {key[:-1]}(s) {sorted(both)} "
                                   f"also assigned in 'assignments' — an object cannot be created and removed "
                                   f"in one file")

    def role_conflicts(self):
        used = {}
        for section in ("grants", "location_grants", "column_masks", "row_filters", "assignments"):
            for c in _dicts(self.config, section):
                used.setdefault(c.get("role"), section)
        for name in (n for n in self.role_names() if isinstance(n, str)):
            if name in self.v.role_names:
                self.error(f"remove.roles: role {name!r} is also declared in 'roles'")
            if name in used:
                self.error(f"remove.roles: role {name!r} is still referenced by '{used[name]}' "
                           f"— remove that entry, or keep the role")


def _names(entry, key):
    value = entry.get(key)
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def _same_entity(a, b):
    ea, eb = a.get("entity"), b.get("entity")
    return isinstance(ea, dict) and isinstance(eb, dict) and entities_equal(ea, eb)


def check_remove(validator):
    _RemoveChecks(validator).run()
