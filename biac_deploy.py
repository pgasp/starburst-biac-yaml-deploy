#!/usr/bin/env python3
"""
Deploy Starburst SEP BIAC entitlements (roles, grants, column masks, row
filters, assignments) declared in a YAML file, via the BIAC REST API.

Usage:
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --dry-run
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --apply
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --verify
    python3 biac_deploy.py --config environments/demo-lab/biac.yaml --validate   # offline, no env, no network

Reviewed (signed) plan, no interactive prompt — the plan that was shown and
validated is the only one that can be applied:
    python3 biac_deploy.py --env .env.lab --config f.biac.yaml --dry-run --plan-out plan.json
    python3 biac_deploy.py --env .env.lab --config f.biac.yaml --apply --plan plan.json

Each cluster/environment gets its own folder under environments/<name>/,
containing its biac.yaml (real catalog/schema/table names for that cluster)
and its views.sql (schema + view creation for that cluster). Catalog/schema/
table names are hardcoded per-environment — there is no cross-environment
templating; copy an environment folder and edit both files to add a new one.

Design:
- Idempotent: before creating any object, the existing cluster state is
  read via GET and compared. Matching objects are skipped, never recreated.
- Fail closed: config validation happens entirely before any network call.
  Any invalid or ambiguous entry aborts the whole run — nothing partial.
- No implicit destructive action: this script never deletes or revokes
  anything. Drift detection / pruning is explicitly out of scope for v1.
  This also means an existing grant/row filter/column mask can never be
  changed in place (e.g. ALLOW -> ALLOW_WITH_GRANT_OPTION on the same
  entity) — the BIAC API itself rejects a duplicate create in that case
  (409 ALREADY_EXISTS, keyed on action+entity, ignoring effect). To change
  an existing one, delete it on the cluster first (outside this tool), then
  re-run --apply.
- allEntities:true is never emitted for data entities — TABLES/FUNCTIONS
  are always scoped (catalog, catalog+schema, or catalog+schema+table/
  function), matching the BIAC API constraint that allEntities:true forbids
  any other attribute. Sole exception: AI_MODELS, where allEntities:true
  ("all AI models") is what the SEP UI itself emits.

Supported entity categories (grants):
  TABLES         {category: TABLES, catalog, [schema], [table]}
  FUNCTIONS      {category: FUNCTIONS, catalog, [schema], [function]}
  DATA_PRODUCTS  {category: DATA_PRODUCTS, domainName, [dataProductName]}
                 (domainName alone = every data product of the domain)
  AI_MODELS      {category: AI_MODELS, allEntities: true}
  USER_INTERFACE {category: USER_INTERFACE, uiFeature}
                 (e.g. AI_MODELS, DATA_PRODUCTS, QUERY_EDITOR, CATALOG_EXPLORER)
Formats read back from the BIAC API on the lab lab (2026-10-15).
Column masks and row filters only accept TABLES.
Location grants (top-level 'location_grants': role, location, grant_option)
use their own endpoint /api/v1/biac/roles/{id}/locationGrants.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(1)

ROLE_NAME_RE = re.compile(r"^[a-z0-9_]+$")

# Guardrails (fail closed): these roles can never be the target of a grant,
# location grant, column mask, row filter or assignment, nor be declared.
FORBIDDEN_ROLES = frozenset({"sysadmin", "public"})
# Effects that widen access; on a whole catalog they need an explicit opt-in
# through the root key 'allow_catalog_wide'.
WIDENING_EFFECTS = frozenset({"ALLOW", "ALLOW_WITH_GRANT_OPTION"})

PLAN_FILE_VERSION = 1
EXIT_VALIDATION = 2   # invalid YAML / guardrail violation / bad CLI usage
EXIT_PLAN_REFUSED = 3  # --apply --plan: signed plan does not match

# Non-data entity categories and the attributes each accepts besides
# category/allEntities (formats read back from the BIAC API, 2026-10-15).
NON_DATA_CATEGORIES_KEYS = {
    "DATA_PRODUCTS": ("domainName", "dataProductName"),
    "AI_MODELS": (),
    "USER_INTERFACE": ("uiFeature",),
}
NON_DATA_CATEGORIES = tuple(NON_DATA_CATEGORIES_KEYS)


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------

def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    for required in ("SB_HOST", "SB_USER", "SB_PASSWORD"):
        if required not in env:
            raise ValueError(f"{path}: missing required key {required}")
    env.setdefault("SB_PORT", "443")
    return env


def read_config_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def parse_config(raw):
    config = yaml.safe_load(raw) or {}
    if not isinstance(config, dict):
        raise ValueError("Config validation failed:\n  - the YAML root must be a mapping")
    validate_config(config)
    return config


def load_config(path):
    return parse_config(read_config_bytes(path))


MAX_DESCRIPTION_LENGTH = 250  # BIAC API limit, confirmed by testing against a real cluster


def grant_actions(g):
    """A grant's 'action' may be a single string or a YAML list of strings
    (one API call will be made per action). A comma-separated STRING is
    deliberately NOT supported: '{action: CREATE,DELETE,SELECT}' inside a
    YAML flow mapping does not mean what it looks like — the unquoted comma
    is parsed as a mapping separator, silently producing 'action: CREATE'
    plus bogus extra keys (DELETE, SELECT, ... each with value null), not a
    multi-action grant. This was hit for real and is now caught explicitly
    by validate_config's unknown-key check. Use a YAML list instead:
        action: [CREATE, DELETE, SELECT]
    """
    a = g.get("action")
    if isinstance(a, list):
        return a
    if isinstance(a, str):
        return [a]
    return []


def validate_config(config):
    """Structural validation. Aborts (raises) on anything malformed or
    ambiguous — never guesses a default for a missing security-relevant
    field. Non-blocking oddities are reported as warnings instead."""
    errors = []
    warnings = []

    known_top_level = {"roles", "grants", "location_grants", "column_masks", "row_filters", "assignments",
                       "allow_catalog_wide", "allowed_users", "allowed_groups"}
    unknown = set(config.keys()) - known_top_level
    if unknown:
        errors.append(f"unknown top-level key(s): {sorted(unknown)}")

    def declared_names(key):
        """Root guardrail lists: must be a list of non-empty strings. A
        missing key means an empty list (fail closed)."""
        value = config.get(key)
        if value is None:
            return set()
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            errors.append(f"'{key}' must be a list of non-empty strings")
            return set()
        return set(value)

    allow_catalog_wide = {c.lower() for c in declared_names("allow_catalog_wide")}
    allowed_users = declared_names("allowed_users")
    allowed_groups = declared_names("allowed_groups")

    def check_role_not_forbidden(role, context):
        if isinstance(role, str) and role.lower() in FORBIDDEN_ROLES:
            errors.append(f"{context}: role {role!r} is forbidden by this tool "
                           f"(never grant, mask, filter or assign anything on "
                           f"{' / '.join(sorted(FORBIDDEN_ROLES))})")

    role_names = set()
    for r in config.get("roles", []):
        name = r.get("name")
        if not name or not ROLE_NAME_RE.match(name):
            errors.append(f"invalid role name: {name!r} (must match ^[a-z0-9_]+$)")
        role_names.add(name)
        check_role_not_forbidden(name, "role declaration")

    def check_entity(entity, context, tables_only=False):
        category = entity.get("category")
        if not tables_only and category in NON_DATA_CATEGORIES:
            check_non_data_entity(entity, context)
            return
        if entity.get("allEntities") is True:
            errors.append(f"{context}: allEntities:true is forbidden by this tool "
                           f"— scope the entity explicitly (catalog, or catalog+schema, "
                           f"or catalog+schema+table/function)")
            return
        # A catalog-wide or schema-wide grant is expressed by OMITTING the
        # narrower field(s) entirely — 'catalog' alone means catalog.*,
        # 'catalog'+'schema' alone means catalog.schema.*. A literal '*'
        # string is NOT the mechanism for this (confirmed on staging,
        # 2026-10-01) — reject it explicitly so it's never confused with
        # omission.
        for field in ("schema", "table", "function"):
            if entity.get(field) == "*":
                errors.append(f"{context}: '*' is not a valid wildcard for '{field}' — "
                               f"omit '{field}' entirely instead for a catalog/schema-wide grant")
        allowed = ("TABLES",) if tables_only else ("TABLES", "FUNCTIONS") + NON_DATA_CATEGORIES
        if category not in allowed:
            errors.append(f"{context}: unsupported or missing entity category {category!r} "
                           f"(expected one of {', '.join(allowed)})")
            return
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

    def check_non_data_entity(entity, context):
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
            return
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

    known_grant_keys = {"role", "effect", "action", "entity"}
    for g in config.get("grants", []):
        role = g.get("role")
        unknown_keys = set(g.keys()) - known_grant_keys
        if unknown_keys:
            errors.append(f"grant on role {role!r}: unknown key(s) {sorted(unknown_keys)} — "
                           f"likely an unquoted comma inside a flow mapping (e.g. "
                           f"'action: CREATE,DELETE,SELECT' does NOT mean a multi-action grant, "
                           f"it's parsed as stray keys DELETE/SELECT with null values — "
                           f"use 'action: [CREATE, DELETE, SELECT]' instead)")
        if role not in role_names:
            errors.append(f"grant references undeclared role: {role!r}")
        if g.get("effect") not in ("ALLOW", "DENY", "ALLOW_WITH_GRANT_OPTION"):
            errors.append(f"grant on role {role!r}: invalid or missing 'effect'")
        if not grant_actions(g):
            errors.append(f"grant on role {role!r}: missing 'action' (string or list of strings)")
        check_role_not_forbidden(role, f"grant on role {role!r}")
        entity = g.get("entity", {})
        check_entity(entity, f"grant on role {role!r}")
        if (g.get("effect") in WIDENING_EFFECTS
                and entity.get("category") in ("TABLES", "FUNCTIONS")
                and entity.get("catalog") and not entity.get("schema")
                and str(entity["catalog"]).lower() not in allow_catalog_wide):
            errors.append(f"grant on role {role!r}: {g.get('effect')} on the whole catalog "
                           f"{entity['catalog']!r} (no schema) requires an explicit opt-in — add "
                           f"'allow_catalog_wide: [{entity['catalog']}]' at the root of the file, "
                           f"or scope the grant to a schema")

    for lg in config.get("location_grants", []):
        role = lg.get("role")
        stray = set(lg.keys()) - {"role", "location", "grant_option"}
        if stray:
            errors.append(f"location_grant on role {role!r}: unknown key(s) {sorted(stray)}")
        if role not in role_names:
            errors.append(f"location_grant references undeclared role: {role!r}")
        check_role_not_forbidden(role, f"location_grant on role {role!r}")
        loc = lg.get("location")
        if not isinstance(loc, str) or not re.match(r"^[a-z0-9]+://[^/]+/", loc):
            errors.append(f"location_grant on role {role!r}: 'location' must be a full URI "
                           f"with a bucket and a path (e.g. s3://bucket/prefix/*), got {loc!r}")
        if not isinstance(lg.get("grant_option", False), bool):
            errors.append(f"location_grant on role {role!r}: 'grant_option' must be true/false")

    known_mask_keys = {"name", "description", "expression", "role", "entity"}
    for m in config.get("column_masks", []):
        role = m.get("role")
        check_role_not_forbidden(role, f"column_mask {m.get('name')!r}")
        unknown_keys = set(m.keys()) - known_mask_keys
        if unknown_keys:
            errors.append(f"column_mask {m.get('name')!r}: unknown key(s) {sorted(unknown_keys)}")
        if role not in role_names:
            errors.append(f"column_mask {m.get('name')!r} references undeclared role: {role!r}")
        if not m.get("expression"):
            errors.append(f"column_mask {m.get('name')!r}: missing 'expression'")
        description = m.get("description", "")
        if len(description) > MAX_DESCRIPTION_LENGTH:
            errors.append(f"column_mask {m.get('name')!r}: description is {len(description)} "
                           f"chars, exceeds the {MAX_DESCRIPTION_LENGTH}-char BIAC API limit")
        entity = m.get("entity", {})
        if not entity.get("columns"):
            errors.append(f"column_mask {m.get('name')!r}: entity must list 'columns'")
        if not entity.get("table"):
            errors.append(f"column_mask {m.get('name')!r}: entity must specify a 'table' "
                           f"— a column mask always targets one specific table, never catalog/schema-wide")
        check_entity(entity, f"column_mask {m.get('name')!r}", tables_only=True)

    known_rf_keys = {"name", "description", "expression", "role", "entity"}
    for rf in config.get("row_filters", []):
        role = rf.get("role")
        check_role_not_forbidden(role, f"row_filter {rf.get('name')!r}")
        unknown_keys = set(rf.keys()) - known_rf_keys
        if unknown_keys:
            errors.append(f"row_filter {rf.get('name')!r}: unknown key(s) {sorted(unknown_keys)}")
        if role not in role_names:
            errors.append(f"row_filter {rf.get('name')!r} references undeclared role: {role!r}")
        if not rf.get("expression"):
            errors.append(f"row_filter {rf.get('name')!r}: missing 'expression'")
        description = rf.get("description", "")
        if len(description) > MAX_DESCRIPTION_LENGTH:
            errors.append(f"row_filter {rf.get('name')!r}: description is {len(description)} "
                           f"chars, exceeds the {MAX_DESCRIPTION_LENGTH}-char BIAC API limit")
        entity = rf.get("entity", {})
        if not entity.get("table"):
            errors.append(f"row_filter {rf.get('name')!r}: entity must specify a 'table' "
                           f"— a row filter always targets one specific table, never catalog/schema-wide")
        if entity.get("columns"):
            errors.append(f"row_filter {rf.get('name')!r}: entity must not specify 'columns' "
                           f"— row filters apply to whole rows, not specific columns (did you mean column_masks?)")
        check_entity(entity, f"row_filter {rf.get('name')!r}", tables_only=True)

    for a in config.get("assignments", []):
        role = a.get("role")
        check_role_not_forbidden(role, "assignment")
        if role not in role_names:
            errors.append(f"assignment references undeclared role: {role!r}")
        for key, allowed, declared_key in (("users", allowed_users, "allowed_users"),
                                           ("groups", allowed_groups, "allowed_groups")):
            listed = a.get(key) or []
            if not isinstance(listed, list) or not all(isinstance(x, str) and x for x in listed):
                errors.append(f"assignment on role {role!r}: '{key}' must be a list of non-empty strings")
                continue
            for name in listed:
                if name not in allowed:
                    errors.append(f"assignment on role {role!r}: {key[:-1]} {name!r} is not declared in "
                                   f"the root '{declared_key}' list of this file (fail closed)")
        if not a.get("users") and not a.get("groups"):
            warnings.append(f"assignment on role {role!r}: no users or groups listed "
                             f"(nothing to do here — check this isn't a mistake)")

    if warnings:
        print("Config warnings:", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)

    if errors:
        raise ValueError("Config validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


# --------------------------------------------------------------------------
# BIAC HTTP client
# --------------------------------------------------------------------------

class BiacClient:
    def __init__(self, env):
        self.host = env["SB_HOST"]
        self.port = env["SB_PORT"]
        self.auth = base64.b64encode(
            f"{env['SB_USER']}:{env['SB_PASSWORD']}".encode()
        ).decode()

    def __repr__(self):  # never expose the Authorization material
        return f"BiacClient({self.host}:{self.port})"

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"https://{self.host}:{self.port}{path}", data=data, method=method
        )
        req.add_header("Authorization", f"Basic {self.auth}")
        req.add_header("X-Trino-Role", "system=ROLE{sysadmin}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read().decode()
                return r.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                return e.code, json.loads(text)
            except json.JSONDecodeError:
                return e.code, text

    # --- roles ---
    def list_roles(self):
        status, body = self.call("GET", "/api/v1/biac/roles")
        if status != 200:
            raise RuntimeError(f"GET /roles failed: {status} {body}")
        return body["result"]

    def find_role(self, name):
        return next((r for r in self.list_roles() if r["name"] == name), None)

    def create_role(self, name):
        status, body = self.call("POST", "/api/v1/biac/roles", {"name": name})
        if status not in (200, 201):
            raise RuntimeError(f"POST /roles ({name}) failed: {status} {body}")
        return self.find_role(name)

    # --- grants ---
    def list_grants(self, role_id):
        status, body = self.call("GET", f"/api/v1/biac/roles/{role_id}/grants")
        if status != 200:
            raise RuntimeError(f"GET /roles/{role_id}/grants failed: {status} {body}")
        return body["result"]

    def grant_exists(self, role_id, effect, action, entity):
        for g in self.list_grants(role_id):
            if (g.get("effect") == effect and g.get("action") == action
                    and entities_equal(g.get("entity", {}), entity)):
                return True
        return False

    def create_grant(self, role_id, effect, action, entity):
        body = {"effect": effect, "action": action, "entity": entity}
        status, resp = self.call("POST", f"/api/v1/biac/roles/{role_id}/grants", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /roles/{role_id}/grants failed: {status} {resp}")
        return resp

    # --- location grants (separate endpoint from entity grants) ---
    def list_location_grants(self, role_id):
        status, body = self.call("GET", f"/api/v1/biac/roles/{role_id}/locationGrants")
        if status != 200:
            raise RuntimeError(f"GET /roles/{role_id}/locationGrants failed: {status} {body}")
        return body["result"]

    def location_grant_exists(self, role_id, location, grant_option):
        return any(g.get("location") == location and bool(g.get("grantOption")) == grant_option
                   for g in self.list_location_grants(role_id))

    def create_location_grant(self, role_id, location, grant_option):
        body = {"location": location, "grantOption": grant_option}
        status, resp = self.call("POST", f"/api/v1/biac/roles/{role_id}/locationGrants", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /roles/{role_id}/locationGrants failed: {status} {resp}")
        return resp

    # --- column mask expressions ---
    def list_column_mask_expressions(self):
        status, body = self.call("GET", "/api/v1/biac/expressions/columnMask")
        if status != 200:
            raise RuntimeError(f"GET /expressions/columnMask failed: {status} {body}")
        return body["result"]

    def find_column_mask_expression(self, name):
        return next((e for e in self.list_column_mask_expressions() if e["name"] == name), None)

    def create_column_mask_expression(self, name, expression, description):
        body = {"name": name, "expression": expression, "description": description}
        status, resp = self.call("POST", "/api/v1/biac/expressions/columnMask", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /expressions/columnMask ({name}) failed: {status} {resp}")
        return resp

    # --- column masks (attachment to role) ---
    def list_column_masks(self, role_id):
        status, body = self.call("GET", f"/api/v1/biac/roles/{role_id}/columnMasks")
        if status != 200:
            raise RuntimeError(f"GET /roles/{role_id}/columnMasks failed: {status} {body}")
        return body["result"]

    def column_mask_attached(self, role_id, entity, expression_id):
        for m in self.list_column_masks(role_id):
            if m.get("expressionId") == expression_id and entities_equal(m.get("entity", {}), entity):
                return True
        return False

    def attach_column_mask(self, role_id, entity, expression_id):
        body = {"entity": entity, "expressionId": expression_id, "forceNone": False}
        status, resp = self.call("POST", f"/api/v1/biac/roles/{role_id}/columnMasks", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /roles/{role_id}/columnMasks failed: {status} {resp}")
        return resp

    # --- row filter expressions ---
    def list_row_filter_expressions(self):
        status, body = self.call("GET", "/api/v1/biac/expressions/rowFilter")
        if status != 200:
            raise RuntimeError(f"GET /expressions/rowFilter failed: {status} {body}")
        return body["result"]

    def find_row_filter_expression(self, name):
        return next((e for e in self.list_row_filter_expressions() if e["name"] == name), None)

    def create_row_filter_expression(self, name, expression, description):
        body = {"name": name, "expression": expression, "description": description}
        status, resp = self.call("POST", "/api/v1/biac/expressions/rowFilter", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /expressions/rowFilter ({name}) failed: {status} {resp}")
        return resp

    # --- row filters (attachment to role) ---
    def list_row_filters(self, role_id):
        status, body = self.call("GET", f"/api/v1/biac/roles/{role_id}/rowFilters")
        if status != 200:
            raise RuntimeError(f"GET /roles/{role_id}/rowFilters failed: {status} {body}")
        return body["result"]

    def row_filter_attached(self, role_id, entity, expression_id):
        for f in self.list_row_filters(role_id):
            if f.get("expressionId") == expression_id and entities_equal(f.get("entity", {}), entity):
                return True
        return False

    def attach_row_filter(self, role_id, entity, expression_id):
        body = {"entity": entity, "expressionId": expression_id, "forceNone": False}
        status, resp = self.call("POST", f"/api/v1/biac/roles/{role_id}/rowFilters", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST /roles/{role_id}/rowFilters failed: {status} {resp}")
        return resp

    # --- assignments ---
    def list_user_assignments(self, user):
        status, body = self.call("GET", f"/api/v1/biac/subjects/users/{user}/assignments")
        if status != 200:
            raise RuntimeError(f"GET /subjects/users/{user}/assignments failed: {status} {body}")
        return body["result"]

    def user_assigned(self, user, role_id):
        return any(a.get("roleId") == role_id for a in self.list_user_assignments(user))

    def assign_user(self, user, role_id):
        body = {"roleId": role_id, "roleAdmin": False}
        status, resp = self.call("POST", f"/api/v1/biac/subjects/users/{user}/assignments", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST assign user {user} failed: {status} {resp}")
        return resp

    def list_group_assignments(self, group):
        status, body = self.call("GET", f"/api/v1/biac/subjects/groups/{group}/assignments")
        if status != 200:
            raise RuntimeError(f"GET /subjects/groups/{group}/assignments failed: {status} {body}")
        return body["result"]

    def group_assigned(self, group, role_id):
        return any(a.get("roleId") == role_id for a in self.list_group_assignments(group))

    def assign_group(self, group, role_id):
        body = {"roleId": role_id, "roleAdmin": False}
        status, resp = self.call("POST", f"/api/v1/biac/subjects/groups/{group}/assignments", body)
        if status not in (200, 201):
            raise RuntimeError(f"POST assign group {group} failed: {status} {resp}")
        return resp


def _norm(v):
    # The BIAC API normalizes catalog/schema/table/function names to
    # lowercase regardless of the case sent (confirmed on lab, 2026-10-01:
    # 'sales_5m' sent, 'sales_5m' stored) — compare case-insensitively so
    # idempotency checks don't false-negative into recreating the same
    # grant/mask on every run.
    return v.lower() if isinstance(v, str) else v


def entities_equal(a, b):
    keys = {"category", "catalog", "schema", "table", "function",
            "domainName", "dataProductName", "uiFeature"}
    if bool(a.get("allEntities")) != bool(b.get("allEntities")):
        return False
    a_cols = sorted(_norm(c) for c in (a.get("columns") or []))
    b_cols = sorted(_norm(c) for c in (b.get("columns") or []))
    return (all(_norm(a.get(k)) == _norm(b.get(k)) for k in keys) and a_cols == b_cols)


# --------------------------------------------------------------------------
# Planning (dry-run) and execution (apply)
# --------------------------------------------------------------------------

def plan(client, config):
    """Returns a list of (kind, description, action) where action is
    'CREATE' or 'SKIP (exists)'. Read-only — no writes."""
    actions = []
    role_ids = {}

    for r in config.get("roles", []):
        existing = client.find_role(r["name"])
        if existing:
            role_ids[r["name"]] = existing["id"]
            actions.append(("role", r["name"], "SKIP (exists)"))
        else:
            actions.append(("role", r["name"], "CREATE"))

    mask_expr_ids = {}
    for m in config.get("column_masks", []):
        existing = client.find_column_mask_expression(m["name"])
        if existing:
            mask_expr_ids[m["name"]] = existing["id"]
            actions.append(("column_mask_expression", m["name"], "SKIP (exists)"))
        else:
            actions.append(("column_mask_expression", m["name"], "CREATE"))

    for g in config.get("grants", []):
        role_id = role_ids.get(g["role"])
        for action in grant_actions(g):
            label = f"{g['role']} -> {g['effect']} {action} on {describe_entity(g['entity'])}"
            if role_id and client.grant_exists(role_id, g["effect"], action, g["entity"]):
                actions.append(("grant", label, "SKIP (exists)"))
            else:
                actions.append(("grant", label, "CREATE"))

    for lg in config.get("location_grants", []):
        role_id = role_ids.get(lg["role"])
        go = lg.get("grant_option", False)
        label = f"{lg['role']} -> location {lg['location']}" + (" (with grant option)" if go else "")
        if role_id and client.location_grant_exists(role_id, lg["location"], go):
            actions.append(("location_grant", label, "SKIP (exists)"))
        else:
            actions.append(("location_grant", label, "CREATE"))

    for m in config.get("column_masks", []):
        role_id = role_ids.get(m["role"])
        expr_id = mask_expr_ids.get(m["name"])
        label = f"{m['role']} -> mask {describe_entity(m['entity'])} := {m['expression']}"
        if role_id and expr_id and client.column_mask_attached(role_id, m["entity"], expr_id):
            actions.append(("column_mask_attach", label, "SKIP (exists)"))
        else:
            actions.append(("column_mask_attach", label, "CREATE"))

    rf_expr_ids = {}
    for rf in config.get("row_filters", []):
        existing = client.find_row_filter_expression(rf["name"])
        if existing:
            rf_expr_ids[rf["name"]] = existing["id"]
            actions.append(("row_filter_expression", rf["name"], "SKIP (exists)"))
        else:
            actions.append(("row_filter_expression", rf["name"], "CREATE"))

    for rf in config.get("row_filters", []):
        role_id = role_ids.get(rf["role"])
        expr_id = rf_expr_ids.get(rf["name"])
        label = f"{rf['role']} -> rowfilter {describe_entity(rf['entity'])} := {rf['expression']}"
        if role_id and expr_id and client.row_filter_attached(role_id, rf["entity"], expr_id):
            actions.append(("row_filter_attach", label, "SKIP (exists)"))
        else:
            actions.append(("row_filter_attach", label, "CREATE"))

    for a in config.get("assignments", []):
        role_id = role_ids.get(a["role"])
        for user in a.get("users", []):
            if role_id and client.user_assigned(user, role_id):
                actions.append(("assignment", f"user {user} -> {a['role']}", "SKIP (exists)"))
            else:
                actions.append(("assignment", f"user {user} -> {a['role']}", "CREATE"))
        for group in a.get("groups", []):
            if role_id and client.group_assigned(group, role_id):
                actions.append(("assignment", f"group {group} -> {a['role']}", "SKIP (exists)"))
            else:
                actions.append(("assignment", f"group {group} -> {a['role']}", "CREATE"))

    return actions


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
    narrow_field = "function" if entity.get("category") == "FUNCTIONS" else "table"
    parts = [entity.get("catalog"), entity.get("schema"), entity.get(narrow_field)]
    parts = [p for p in parts if p]  # catalog-only or catalog+schema grants omit the rest
    base = ".".join(parts) + (".*" if len(parts) < 3 else "")
    if entity.get("columns"):
        base += f".{','.join(entity['columns'])}"
    return base


def apply(client, config):
    role_ids = {}
    for r in config.get("roles", []):
        existing = client.find_role(r["name"])
        if existing:
            role_ids[r["name"]] = existing["id"]
            print(f"[role] {r['name']}: exists (id={existing['id']}), skipping")
        else:
            created = client.create_role(r["name"])
            role_ids[r["name"]] = created["id"]
            print(f"[role] {r['name']}: created (id={created['id']})")

    mask_expr_ids = {}
    for m in config.get("column_masks", []):
        existing = client.find_column_mask_expression(m["name"])
        if existing:
            mask_expr_ids[m["name"]] = existing["id"]
            print(f"[column_mask_expression] {m['name']}: exists (id={existing['id']}), skipping")
        else:
            created = client.create_column_mask_expression(
                m["name"], m["expression"], m.get("description", "")
            )
            mask_expr_ids[m["name"]] = created["id"]
            print(f"[column_mask_expression] {m['name']}: created (id={created['id']})")

    for g in config.get("grants", []):
        role_id = role_ids[g["role"]]
        for action in grant_actions(g):
            if client.grant_exists(role_id, g["effect"], action, g["entity"]):
                print(f"[grant] {g['role']} {g['effect']} {action} "
                      f"{describe_entity(g['entity'])}: exists, skipping")
            else:
                client.create_grant(role_id, g["effect"], action, g["entity"])
                print(f"[grant] {g['role']} {g['effect']} {action} "
                      f"{describe_entity(g['entity'])}: created")

    for lg in config.get("location_grants", []):
        role_id = role_ids[lg["role"]]
        go = lg.get("grant_option", False)
        if client.location_grant_exists(role_id, lg["location"], go):
            print(f"[location_grant] {lg['role']} {lg['location']}: exists, skipping")
        else:
            client.create_location_grant(role_id, lg["location"], go)
            print(f"[location_grant] {lg['role']} {lg['location']}: created")

    for m in config.get("column_masks", []):
        role_id = role_ids[m["role"]]
        expr_id = mask_expr_ids[m["name"]]
        if client.column_mask_attached(role_id, m["entity"], expr_id):
            print(f"[column_mask] {m['role']} -> {describe_entity(m['entity'])}: exists, skipping")
        else:
            client.attach_column_mask(role_id, m["entity"], expr_id)
            print(f"[column_mask] {m['role']} -> {describe_entity(m['entity'])}: attached")

    rf_expr_ids = {}
    for rf in config.get("row_filters", []):
        existing = client.find_row_filter_expression(rf["name"])
        if existing:
            rf_expr_ids[rf["name"]] = existing["id"]
            print(f"[row_filter_expression] {rf['name']}: exists (id={existing['id']}), skipping")
        else:
            created = client.create_row_filter_expression(
                rf["name"], rf["expression"], rf.get("description", "")
            )
            rf_expr_ids[rf["name"]] = created["id"]
            print(f"[row_filter_expression] {rf['name']}: created (id={created['id']})")

    for rf in config.get("row_filters", []):
        role_id = role_ids[rf["role"]]
        expr_id = rf_expr_ids[rf["name"]]
        if client.row_filter_attached(role_id, rf["entity"], expr_id):
            print(f"[row_filter] {rf['role']} -> {describe_entity(rf['entity'])}: exists, skipping")
        else:
            client.attach_row_filter(role_id, rf["entity"], expr_id)
            print(f"[row_filter] {rf['role']} -> {describe_entity(rf['entity'])}: attached")

    for a in config.get("assignments", []):
        role_id = role_ids[a["role"]]
        for user in a.get("users", []):
            if client.user_assigned(user, role_id):
                print(f"[assignment] user {user} -> {a['role']}: exists, skipping")
            else:
                client.assign_user(user, role_id)
                print(f"[assignment] user {user} -> {a['role']}: created")
        for group in a.get("groups", []):
            if client.group_assigned(group, role_id):
                print(f"[assignment] group {group} -> {a['role']}: exists, skipping")
            else:
                client.assign_group(group, role_id)
                print(f"[assignment] group {group} -> {a['role']}: created")


def verify(client, config):
    print("=== Verification (read-back) ===")
    for r in config.get("roles", []):
        existing = client.find_role(r["name"])
        if not existing:
            print(f"[role] {r['name']}: MISSING")
            continue
        role_id = existing["id"]
        print(f"[role] {r['name']} (id={role_id})")
        for g in client.list_grants(role_id):
            print(f"    grant: {g.get('effect')} {g.get('action')} "
                  f"{describe_entity(g.get('entity', {}))}  {json.dumps(g.get('entity', {}), sort_keys=True)}")
        for lg in client.list_location_grants(role_id):
            print(f"    location_grant: {lg.get('location')} (grantOption={lg.get('grantOption')})")
        for m in client.list_column_masks(role_id):
            print(f"    column_mask: {describe_entity(m.get('entity', {}))} "
                  f"(expressionId={m.get('expressionId')})")
        for f in client.list_row_filters(role_id):
            print(f"    row_filter: {describe_entity(f.get('entity', {}))} "
                  f"(expressionId={f.get('expressionId')})")


# --------------------------------------------------------------------------
# Signed plan: --dry-run --plan-out F  /  --apply --plan F
# --------------------------------------------------------------------------

def plan_records(actions):
    """Plan tuples -> JSON-friendly records (stable order = plan order)."""
    return [{"kind": k, "label": label, "action": a} for k, label, a in actions]


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def plan_fingerprint(records, config_sha256, cluster):
    """SHA-256 over the canonical plan, the exact bytes of the YAML file and
    the target cluster. Any change to one of the three changes the fingerprint."""
    return sha256_hex(canonical_json({"cluster": cluster, "config_sha256": config_sha256, "plan": records}))


def build_signed_plan(actions, config_bytes, cluster):
    records = plan_records(actions)
    config_sha = sha256_hex(config_bytes)
    return {
        "version": PLAN_FILE_VERSION,
        "cluster": cluster,
        "config_sha256": config_sha,
        "plan": records,
        "fingerprint": plan_fingerprint(records, config_sha, cluster),
    }


def write_plan_file(path, signed_plan):
    """Atomic write, mode 0600 (the plan holds no credential, but there is no
    reason for it to be world-readable)."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".plan-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(signed_plan, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_plan_file(path):
    with open(path) as f:
        data = json.load(f)
    required = {"version", "cluster", "config_sha256", "plan", "fingerprint"}
    if not isinstance(data, dict) or not required <= set(data) or data["version"] != PLAN_FILE_VERSION:
        raise ValueError(f"{path}: not a valid plan file (version {PLAN_FILE_VERSION})")
    if not isinstance(data["plan"], list):
        raise ValueError(f"{path}: not a valid plan file ('plan' must be a list)")
    return data


def plan_diff_lines(old_records, new_records):
    old = {canonical_json(r) for r in old_records}
    new = {canonical_json(r) for r in new_records}
    lines = [f"  - only in the signed plan: [{json.loads(r)['kind']}] {json.loads(r)['label']}: {json.loads(r)['action']}"
             for r in sorted(old - new)]
    lines += [f"  + only in the recomputed plan: [{json.loads(r)['kind']}] {json.loads(r)['label']}: {json.loads(r)['action']}"
              for r in sorted(new - old)]
    return lines


def check_signed_plan(signed, live_actions, config_bytes, cluster):
    """Returns a list of refusal reasons (empty = the signed plan is valid)."""
    reasons = []
    stored_records = signed["plan"]
    if plan_fingerprint(stored_records, signed["config_sha256"], signed["cluster"]) != signed["fingerprint"]:
        reasons.append("the plan file was altered (its fingerprint does not match its own content)")
    if signed["cluster"] != cluster:
        reasons.append(f"the plan was made for cluster {signed['cluster']!r}, not {cluster!r}")
    if signed["config_sha256"] != sha256_hex(config_bytes):
        reasons.append("the YAML file changed since the plan was signed")
    live_records = plan_records(live_actions)
    live_fp = plan_fingerprint(live_records, sha256_hex(config_bytes), cluster)
    if live_fp != signed["fingerprint"]:
        reasons.append("the recomputed plan differs from the signed plan (cluster state or YAML changed)")
        reasons.extend(plan_diff_lines(stored_records, live_records))
    return reasons


def print_plan(actions, title):
    print(title)
    for kind, label, action in actions:
        print(f"[{kind}] {label}: {action}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def redact(text, env, limit=None):
    """Strip credential material from any text about to be printed."""
    text = str(text)
    for secret in (env.get("SB_PASSWORD"),
                   base64.b64encode(f"{env.get('SB_USER')}:{env.get('SB_PASSWORD')}".encode()).decode()
                   if env.get("SB_PASSWORD") else None):
        if secret:
            text = text.replace(secret, "****")
    return text if limit is None else text[:limit]


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", help="Path to .env file (SB_HOST/SB_PORT/SB_USER/SB_PASSWORD); "
                                 "required except with --validate")
    p.add_argument("--config", required=True, help="Path to environments/<name>/biac.yaml")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Print the plan, no writes")
    mode.add_argument("--apply", action="store_true", help="Execute the plan")
    mode.add_argument("--verify", action="store_true", help="Read back and print current state")
    mode.add_argument("--validate", action="store_true",
                      help="Offline: run the validator (guardrails included) on --config only; "
                           "no env file, no network")
    p.add_argument("--plan-out", metavar="FILE",
                   help="With --dry-run: write the plan and its SHA-256 fingerprint to FILE (JSON)")
    p.add_argument("--plan", metavar="FILE",
                   help="With --apply: apply only if the recomputed plan matches FILE "
                        "(no interactive prompt; refuses with exit code 3 otherwise)")
    return p


def run(args, secrets):
    """Returns the process exit code. Raises on errors (handled by main).
    `secrets` receives the loaded env so main can redact error messages."""
    if args.validate:
        parse_config(read_config_bytes(args.config))
        print(f"OK: {args.config} passes validation (offline, no network).")
        return 0

    env = load_env(args.env)
    secrets.update(env)
    print(f"Cluster: {env['SB_HOST']}:{env['SB_PORT']}  User: {env['SB_USER']}  Password: ****")

    config_bytes = read_config_bytes(args.config)
    config = parse_config(config_bytes)
    client = BiacClient(env)
    cluster = f"{env['SB_HOST']}:{env['SB_PORT']}"

    if args.dry_run:
        actions = plan(client, config)
        print_plan(actions, "=== Plan (dry-run, no changes made) ===")
        if args.plan_out:
            signed = build_signed_plan(actions, config_bytes, cluster)
            write_plan_file(args.plan_out, signed)
            print(f"\nPlan written to {args.plan_out}")
            print(f"Fingerprint (SHA-256): {signed['fingerprint']}")
        return 0

    if args.apply:
        actions = plan(client, config)
        if args.plan:
            signed = load_plan_file(args.plan)
            reasons = check_signed_plan(signed, actions, config_bytes, cluster)
            if reasons:
                print("REFUSED: the signed plan does not match — nothing was applied.", file=sys.stderr)
                for r in reasons:
                    print(r if r.startswith("  ") else f"  * {r}", file=sys.stderr)
                print("Re-run --dry-run --plan-out and have the new plan validated.", file=sys.stderr)
                return EXIT_PLAN_REFUSED
            print_plan(actions, f"=== Plan (matches signed plan {signed['fingerprint'][:12]}…) ===")
            if not any(a[2] == "CREATE" for a in actions):
                print("\nNothing to do — cluster state already matches config.")
                return 0
            print("\n=== Applying (signed plan, no prompt) ===")
            apply(client, config)
            return 0

        print_plan(actions, "=== Plan ===")
        broadening = [a for a in actions if a[2] == "CREATE"]
        if broadening:
            print(f"\n{len(broadening)} new entitlement object(s) will be created (see plan above).")
            confirm = input("Type 'yes' to proceed: ")
            if confirm.strip().lower() != "yes":
                print("Aborted.")
                return 1
        else:
            print("\nNothing to do — cluster state already matches config.")
            return 0
        print("\n=== Applying ===")
        apply(client, config)
        return 0

    verify(client, config)
    return 0


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not args.validate and not args.env:
        p.error("--env is required (except with --validate)")
    if args.plan_out and not args.dry_run:
        p.error("--plan-out is only valid with --dry-run")
    if args.plan and not args.apply:
        p.error("--plan is only valid with --apply")
    secrets = {}
    try:
        return run(args, secrets)
    except (ValueError, yaml.YAMLError) as e:  # config / plan file validation (JSONDecodeError is a ValueError)
        print(redact(e, secrets), file=sys.stderr)
        return EXIT_VALIDATION
    except urllib.error.URLError as e:
        print(f"ERROR (network): {redact(getattr(e, 'reason', e), secrets, 500)}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError) as e:
        # Short message only: no traceback (a traceback or an HTTP error can
        # carry request headers / response bodies).
        print(f"ERROR ({type(e).__name__}): {redact(e, secrets, 500)}", file=sys.stderr)
        return 1
    except EOFError:
        print("Aborted (no interactive input).", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as e:  # last resort: never a raw traceback (could expose request data)
        print(f"ERROR ({type(e).__name__}): {redact(e, secrets, 500)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
