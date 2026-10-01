#!/usr/bin/env python3
"""
Deploy Starburst SEP BIAC entitlements (roles, grants, column masks, row
filters, assignments) declared in a YAML file, via the BIAC REST API.

Usage:
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --dry-run
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --apply
    python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --verify

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
- allEntities:true is never emitted — every entity is fully scoped
  (catalog/schema/table or catalog/schema/function), matching the BIAC API
  constraint that allEntities:true forbids any other attribute.
"""
import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.request

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(1)

ROLE_NAME_RE = re.compile(r"^[a-z0-9_]+$")


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


def load_config(path):
    with open(path) as f:
        config = yaml.safe_load(f) or {}
    validate_config(config)
    return config


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

    known_top_level = {"roles", "grants", "column_masks", "row_filters", "assignments"}
    unknown = set(config.keys()) - known_top_level
    if unknown:
        errors.append(f"unknown top-level key(s): {sorted(unknown)}")

    role_names = set()
    for r in config.get("roles", []):
        name = r.get("name")
        if not name or not ROLE_NAME_RE.match(name):
            errors.append(f"invalid role name: {name!r} (must match ^[a-z0-9_]+$)")
        role_names.add(name)

    def check_entity(entity, context):
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
        category = entity.get("category")
        if category not in ("TABLES", "FUNCTIONS"):
            errors.append(f"{context}: unsupported or missing entity category {category!r} "
                           f"(expected TABLES or FUNCTIONS)")
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
        check_entity(g.get("entity", {}), f"grant on role {role!r}")

    known_mask_keys = {"name", "description", "expression", "role", "entity"}
    for m in config.get("column_masks", []):
        role = m.get("role")
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
        check_entity(entity, f"column_mask {m.get('name')!r}")

    if config.get("row_filters"):
        errors.append("row_filters is not supported by this tool version (v1 scope: "
                       "roles, grants, column_masks, assignments only) — remove this section")

    for a in config.get("assignments", []):
        role = a.get("role")
        if role not in role_names:
            errors.append(f"assignment references undeclared role: {role!r}")
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
    keys = {"category", "catalog", "schema", "table", "function"}
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

    for m in config.get("column_masks", []):
        role_id = role_ids.get(m["role"])
        expr_id = mask_expr_ids.get(m["name"])
        label = f"{m['role']} -> mask {describe_entity(m['entity'])} := {m['expression']}"
        if role_id and expr_id and client.column_mask_attached(role_id, m["entity"], expr_id):
            actions.append(("column_mask_attach", label, "SKIP (exists)"))
        else:
            actions.append(("column_mask_attach", label, "CREATE"))

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

    for m in config.get("column_masks", []):
        role_id = role_ids[m["role"]]
        expr_id = mask_expr_ids[m["name"]]
        if client.column_mask_attached(role_id, m["entity"], expr_id):
            print(f"[column_mask] {m['role']} -> {describe_entity(m['entity'])}: exists, skipping")
        else:
            client.attach_column_mask(role_id, m["entity"], expr_id)
            print(f"[column_mask] {m['role']} -> {describe_entity(m['entity'])}: attached")

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
                  f"{describe_entity(g.get('entity', {}))}")
        for m in client.list_column_masks(role_id):
            print(f"    column_mask: {describe_entity(m.get('entity', {}))} "
                  f"(expressionId={m.get('expressionId')})")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--env", required=True, help="Path to .env file (SB_HOST/SB_PORT/SB_USER/SB_PASSWORD)")
    p.add_argument("--config", required=True, help="Path to environments/<name>/biac.yaml")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Print the plan, no writes")
    mode.add_argument("--apply", action="store_true", help="Execute the plan")
    mode.add_argument("--verify", action="store_true", help="Read back and print current state")
    args = p.parse_args()

    env = load_env(args.env)
    print(f"Cluster: {env['SB_HOST']}:{env['SB_PORT']}  User: {env['SB_USER']}  Password: ****")

    config = load_config(args.config)
    client = BiacClient(env)

    if args.dry_run:
        print("=== Plan (dry-run, no changes made) ===")
        for kind, label, action in plan(client, config):
            print(f"[{kind}] {label}: {action}")
    elif args.apply:
        actions = plan(client, config)
        print("=== Plan ===")
        for kind, label, action in actions:
            print(f"[{kind}] {label}: {action}")
        broadening = [a for a in actions if a[2] == "CREATE"]
        if broadening:
            print(f"\n{len(broadening)} new entitlement object(s) will be created (see plan above).")
            confirm = input("Type 'yes' to proceed: ")
            if confirm.strip().lower() != "yes":
                print("Aborted.")
                sys.exit(1)
        else:
            print("\nNothing to do — cluster state already matches config.")
            return
        print("\n=== Applying ===")
        apply(client, config)
    elif args.verify:
        verify(client, config)


if __name__ == "__main__":
    main()
