"""Dry-run planning: compare the YAML with the cluster, read-only (no writes).

The order of the stages below is the order of the plan, and the same as in
executor.apply: roles, column-mask expressions, grants, location grants,
column-mask attachments, row-filter expressions, row-filter attachments,
assignments; then the removals of the `remove:` section (removal.py).
"""
import re

from .entities import describe_entity
from .policy import COLUMN_MASKS, ROW_FILTERS, grant_actions
from .removal import DELETE, plan_removals, removal_actions

CREATE = "CREATE"
SKIP = "SKIP (exists)"
DRIFT_ACTION = "DRIFT (expression differs)"


# --------------------------------------------------------------------------
# Expression drift
# --------------------------------------------------------------------------

def expression_text(s):
    """Whitespace-normalised expression text, used to detect drift."""
    return re.sub(r"\s+", " ", s or "").strip()


def expression_drifts(existing, wanted_text):
    """True when an expression found by name has another text than the YAML."""
    return expression_text(existing.get("expression")) != expression_text(wanted_text)


def drift_label(name, existing, wanted_text):
    return (f"{name} [cluster: {expression_text(existing.get('expression'))} "
            f"| yaml: {expression_text(wanted_text)}]")


def drift_actions(actions):
    return [a for a in actions if a[2] == DRIFT_ACTION]


def pending_changes(actions):
    """Actions that write: creations and deletions."""
    return [a for a in actions if a[2] in (CREATE, DELETE)]


def deletions(actions):
    return [a for a in actions if a[2] == DELETE]


def print_plan(actions, title):
    print(title)
    for kind, label, action in actions:
        print(f"[{kind}] {label}: {action}")


# --------------------------------------------------------------------------
# Plan
# --------------------------------------------------------------------------

class _Planner:
    def __init__(self, client, config):
        self.client = client
        self.config = config
        self.actions = []
        self.role_ids = {}    # role name -> id, for roles that already exist
        self.expr_ids = {}    # kind.name -> {expression name -> id}, for expressions that already exist

    def add(self, kind, label, exists):
        self.actions.append((kind, label, SKIP if exists else CREATE))

    def roles(self):
        for r in self.config.get("roles", []):
            existing = self.client.find_role(r["name"])
            if existing:
                self.role_ids[r["name"]] = existing["id"]
            self.add("role", r["name"], existing)

    def expressions(self, kind):
        ids = self.expr_ids.setdefault(kind.name, {})
        for item in self.config.get(kind.section, []):
            existing = kind.find(self.client, item["name"])
            if existing:
                ids[item["name"]] = existing["id"]
                if expression_drifts(existing, item["expression"]):
                    self.actions.append((kind.expression_kind,
                                         drift_label(item["name"], existing, item["expression"]), DRIFT_ACTION))
                    continue
            self.add(kind.expression_kind, item["name"], existing)

    def grants(self):
        for g in self.config.get("grants", []):
            role_id = self.role_ids.get(g["role"])
            for action in grant_actions(g):
                label = f"{g['role']} -> {g['effect']} {action} on {describe_entity(g['entity'])}"
                self.add("grant", label, role_id and self.client.grant_exists(role_id, g["effect"], action, g["entity"]))

    def location_grants(self):
        for lg in self.config.get("location_grants", []):
            role_id = self.role_ids.get(lg["role"])
            go = lg.get("grant_option", False)
            label = f"{lg['role']} -> location {lg['location']}" + (" (with grant option)" if go else "")
            self.add("location_grant", label,
                     role_id and self.client.location_grant_exists(role_id, lg["location"], go))

    def attachments(self, kind):
        for item in self.config.get(kind.section, []):
            role_id = self.role_ids.get(item["role"])
            expr_id = self.expr_ids[kind.name].get(item["name"])
            label = f"{item['role']} -> {kind.verb} {describe_entity(item['entity'])} := {item['expression']}"
            self.add(kind.attach_kind, label,
                     role_id and expr_id and kind.attached(self.client, role_id, item["entity"], expr_id))

    def assignments(self):
        for a in self.config.get("assignments", []):
            role_id = self.role_ids.get(a["role"])
            for subject, key in (("user", "users"), ("group", "groups")):
                for name in a.get(key, []):
                    assigned = role_id and getattr(self.client, f"{subject}_assigned")(name, role_id)
                    self.add("assignment", f"{subject} {name} -> {a['role']}", assigned)


def plan(client, config):
    """Returns a list of (kind, description, action) where action is
    'CREATE', 'SKIP (exists)' or, for row-filter / column-mask expressions
    whose text differs from the cluster's, 'DRIFT (expression differs)';
    then, for the `remove:` section, 'DELETE' or 'SKIP (absent)'.
    Raises ValueError if a removal is refused. Read-only — no writes."""
    p = _Planner(client, config)
    p.roles()
    p.expressions(COLUMN_MASKS)
    p.grants()
    p.location_grants()
    p.attachments(COLUMN_MASKS)
    p.expressions(ROW_FILTERS)
    p.attachments(ROW_FILTERS)
    p.assignments()
    return p.actions + removal_actions(plan_removals(client, config))
