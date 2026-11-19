"""Applying a policy to the cluster, and reading it back (verify).

apply() follows the same stage order as planner.plan(): every creation first,
then the removals declared under `remove:` (see removal.py). Nothing is deleted,
revoked or overwritten unless it is declared there.
"""
import json

from .entities import describe_entity
from .planner import DRIFT_ACTION, expression_drifts
from .policy import COLUMN_MASKS, ROW_FILTERS, apply_kind, grant_actions
from .removal import apply_removals, plan_removals, verify_removals

EXPRESSION_KINDS = (COLUMN_MASKS, ROW_FILTERS)


def _ensure(tag, subject, exists, create, done="created"):
    """Create unless it exists; print one line either way. `create` is a
    callable run right away, so it may close over the loop variables."""
    if exists:
        print(f"[{tag}] {subject}: exists, skipping")
    else:
        create()
        print(f"[{tag}] {subject}: {done}")


def _ensure_with_id(tag, name, existing, create):
    """Like _ensure for objects we need the id of (roles, expressions). Returns the id."""
    if existing:
        print(f"[{tag}] {name}: exists (id={existing['id']}), skipping")
        return existing["id"]
    created = create()
    print(f"[{tag}] {name}: created (id={created['id']})")
    return created["id"]


def _refuse_drift(client, config):
    """Defence in depth: apply() never reuses an expression whose text differs."""
    for kind in EXPRESSION_KINDS:
        for item in config.get(kind.section, []):
            existing = kind.find(client, item["name"])
            if existing and expression_drifts(existing, item["expression"]):
                raise RuntimeError(f"[{kind.expression_kind}] {item['name']}: {DRIFT_ACTION} — refusing to apply")


class _Applier:
    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.role_ids = {}
        self.expr_ids = {}   # kind.name -> {expression name -> id}

    def roles(self):
        for r in self.config.get("roles", []):
            self.role_ids[r["name"]] = _ensure_with_id(
                "role", r["name"], self.client.find_role(r["name"]),
                lambda: self.client.create_role(r["name"]))

    def expressions(self, kind):
        ids = self.expr_ids.setdefault(kind.name, {})
        for item in self.config.get(kind.section, []):
            ids[item["name"]] = _ensure_with_id(
                kind.expression_kind, item["name"], kind.find(self.client, item["name"]),
                lambda: kind.create(self.client, item["name"], item["expression"],
                                              item.get("description", "")))

    def grants(self):
        for g in self.config.get("grants", []):
            if apply_kind(g):
                continue   # created after the expressions, see apply_grants
            role_id = self.role_ids[g["role"]]
            for action in grant_actions(g):
                _ensure("grant", f"{g['role']} {g['effect']} {action} {describe_entity(g['entity'])}",
                        self.client.grant_exists(role_id, g["effect"], action, g["entity"]),
                        lambda: self.client.create_grant(role_id, g["effect"], action, g["entity"]))

    def apply_grants(self):
        """APPLY_* grants: the expression is resolved by name to its id (created by this run, or already there)."""
        for g in self.config.get("grants", []):
            kind = apply_kind(g)
            if not kind:
                continue
            name = g[kind.name]
            existing = kind.find(self.client, name)
            expr_id = self.expr_ids.get(kind.name, {}).get(name) or (existing and existing["id"])
            if not expr_id:
                raise ValueError(f"grant on role {g['role']!r}: {kind.name} expression {name!r} does not exist "
                                 f"on the cluster and is not declared under '{kind.section}' in this file")
            role_id = self.role_ids[g["role"]]
            for action in grant_actions(g):
                _ensure("apply_grant", f"{g['role']} {g['effect']} {action} {describe_entity(g['entity'])} "
                                       f"({kind.name} {name})",
                        self.client.grant_exists(role_id, g["effect"], action, g["entity"], expression_id=expr_id),
                        lambda: self.client.create_grant(role_id, g["effect"], action, g["entity"],
                                                         expression_id=expr_id))

    def location_grants(self):
        for lg in self.config.get("location_grants", []):
            role_id = self.role_ids[lg["role"]]
            go = lg.get("grant_option", False)
            _ensure("location_grant", f"{lg['role']} {lg['location']}",
                    self.client.location_grant_exists(role_id, lg["location"], go),
                    lambda: self.client.create_location_grant(role_id, lg["location"], go))

    def attachments(self, kind):
        for item in self.config.get(kind.section, []):
            role_id = self.role_ids[item["role"]]
            expr_id = self.expr_ids[kind.name][item["name"]]
            _ensure(kind.name, f"{item['role']} -> {describe_entity(item['entity'])}",
                    kind.attached(self.client, role_id, item["entity"], expr_id),
                    lambda: kind.attach(self.client, role_id, item["entity"], expr_id),
                    done="attached")

    def assignments(self):
        for a in self.config.get("assignments", []):
            role_id = self.role_ids[a["role"]]
            for subject, key in (("user", "users"), ("group", "groups")):
                for name in a.get(key, []):
                    _ensure("assignment", f"{subject} {name} -> {a['role']}",
                            getattr(self.client, f"{subject}_assigned")(name, role_id),
                            lambda: getattr(self.client, f"assign_{subject}")(name, role_id))


def apply(client, config):
    _refuse_drift(client, config)
    removals = plan_removals(client, config)  # reads only; refuses before anything is written
    a = _Applier(client, config)
    a.roles()
    a.expressions(COLUMN_MASKS)
    a.grants()
    a.location_grants()
    a.attachments(COLUMN_MASKS)
    a.expressions(ROW_FILTERS)
    a.attachments(ROW_FILTERS)
    a.apply_grants()
    a.assignments()
    apply_removals(removals)


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
            expression = ""
            for key in ("columnMaskExpressionId", "rowFilterExpressionId"):
                if g.get(key) is not None:
                    expression = f" ({key}={g[key]})"
            print(f"    grant: {g.get('effect')} {g.get('action')} "
                  f"{describe_entity(g.get('entity', {}))}{expression}  "
                  f"{json.dumps(g.get('entity', {}), sort_keys=True)}")
        for lg in client.list_location_grants(role_id):
            print(f"    location_grant: {lg.get('location')} (grantOption={lg.get('grantOption')})")
        for kind in EXPRESSION_KINDS:
            for m in kind.list_attached(client, role_id):
                print(f"    {kind.name}: {describe_entity(m.get('entity', {}))} "
                      f"(expressionId={m.get('expressionId')})")
    verify_removals(client, config)
