"""The `remove:` section: declarative "ensure absent".

One function, `removal_steps`, turns the section into an ordered list of
steps; the planner prints them, the executor runs them, verify reads them
back. A step either carries a `delete` callable (the object exists) or not
(already absent). Nothing is deleted unless it is declared under `remove:`.

Order of the stages (plan output and apply, the same): assignments, column-mask
detaches, row-filter detaches, grants, location grants, orphan expressions
(masks, then filters), roles. Removals run AFTER every creation, so replacing a
grant (e.g. another column list) creates the new one before deleting the old
one: no gap in access.
"""
from collections import namedtuple
from functools import partial

from .entities import describe_entity
from .policy import COLUMN_MASKS, FORBIDDEN_ROLES, ROW_FILTERS, grant_actions

DELETE = "DELETE"
SKIP_ABSENT = "SKIP (absent)"

(STAGE_ASSIGNMENTS, STAGE_COLUMN_MASKS, STAGE_ROW_FILTERS, STAGE_GRANTS, STAGE_LOCATION_GRANTS,
 STAGE_COLUMN_MASK_EXPRESSIONS, STAGE_ROW_FILTER_EXPRESSIONS, STAGE_ROLES) = range(8)
_ATTACH_STAGE = {COLUMN_MASKS.name: STAGE_COLUMN_MASKS, ROW_FILTERS.name: STAGE_ROW_FILTERS}
_EXPRESSION_STAGE = {COLUMN_MASKS.name: STAGE_COLUMN_MASK_EXPRESSIONS, ROW_FILTERS.name: STAGE_ROW_FILTER_EXPRESSIONS}

Step = namedtuple("Step", "stage kind label delete")  # delete: callable, or None when already absent


class _Removals:
    def __init__(self, client, config):
        self.client = client
        self.section = config.get("remove") or {}
        self.steps = []
        self.refusals = []
        self._seen = set()
        self._role_ids = {}
        self._detached = set()   # (kind name, role id, attachment id) that will be gone

    # --- helpers ---

    def items(self, key):
        return self.section.get(key) or []

    def role_id(self, name):
        if name.lower() in FORBIDDEN_ROLES:  # defence in depth: the validator already refuses these
            raise ValueError(f"remove: role {name!r} is forbidden by this tool")
        if name not in self._role_ids:
            role = self.client.find_role(name)
            self._role_ids[name] = role["id"] if role else None
        return self._role_ids[name]

    def step(self, stage, kind, label, delete=None, key=None):
        """Record a step once: two entries (or an entry and a role cascade) that
        reach the same object must not delete it twice."""
        key = key or (stage, kind, label)
        if key not in self._seen:
            self._seen.add(key)
            self.steps.append(Step(stage, kind, label, delete))

    def found_step(self, stage, kind, label, found, delete, key):
        """`found` is the object's record or None; `delete(found)` removes it."""
        if found:
            self.step(stage, kind, label, partial(delete, found), (kind,) + key)
        else:
            self.step(stage, kind, label)

    # --- explicit entries ---

    def assignments(self):
        for a in self.items("assignments"):
            rid = self.role_id(a["role"])
            for subject, key in (("user", "users"), ("group", "groups")):
                for name in a.get(key) or []:
                    found = rid and getattr(self.client, f"find_{subject}_assignment")(name, rid)
                    delete = getattr(self.client, f"delete_{subject}_assignment")
                    self.found_step(STAGE_ASSIGNMENTS, "remove_assignment", f"REMOVE {subject} {name} -> {a['role']}",
                                    found, lambda f, d=delete, n=name: d(n, f["id"]), (subject, name, rid))

    def grants(self):
        for g in self.items("grants"):
            rid = self.role_id(g["role"])
            for action in grant_actions(g):
                label = f"REMOVE {g['role']} -> {g['effect']} {action} on {describe_entity(g['entity'])}"
                found = rid and self.client.find_grant(rid, g["effect"], action, g["entity"])
                self.found_step(STAGE_GRANTS, "remove_grant", label, found,
                                lambda f, r=rid: self.client.delete_grant(r, f["id"]), (rid, found and found["id"]))

    def location_grants(self):
        for lg in self.items("location_grants"):
            rid = self.role_id(lg["role"])
            go = lg.get("grant_option", False)
            label = f"REMOVE {lg['role']} -> location {lg['location']}" + (" (with grant option)" if go else "")
            found = rid and self.client.find_location_grant(rid, lg["location"], go)
            self.found_step(STAGE_LOCATION_GRANTS, "remove_location_grant", label, found,
                            lambda f, r=rid: self.client.delete_location_grant(r, f["id"]),
                            (rid, found and found["id"]))

    def detach(self, kind, stage, rid, attachment, label):
        """Plan the deletion of one mask/filter attachment of a role (absent if `attachment` is None)."""
        self.found_step(stage, kind.remove_kind, label, attachment,
                        lambda f, r=rid: kind.detach(self.client, r, f["id"]), (rid, attachment and attachment["id"]))
        if attachment:
            self._detached.add((kind.name, rid, attachment["id"]))

    def detaches(self, kind):
        for item in self.items(kind.section):
            rid = self.role_id(item["role"])
            expression = kind.find(self.client, item["name"])
            found = rid and expression and kind.find_attachment(self.client, rid, item["entity"], expression["id"])
            label = f"REMOVE {item['role']} -> {kind.verb} {describe_entity(item['entity'])} (expression {item['name']})"
            self.detach(kind, _ATTACH_STAGE[kind.name], rid, found, label)

    def orphan_expressions(self, kind):
        """`delete_expression: true`: delete the expression itself, but only if no role keeps it attached."""
        for item in self.items(kind.section):
            if not item.get("delete_expression"):
                continue
            label = f"REMOVE {kind.verb} expression {item['name']}"
            expression = kind.find(self.client, item["name"])
            if not expression:
                self.step(_EXPRESSION_STAGE[kind.name], kind.remove_expression_kind, label)
                continue
            holders = self.remaining_holders(kind, expression["id"])
            if holders:
                reason = (f"{kind.name} expression {item['name']!r} cannot be deleted: still attached "
                          f"on role(s) {', '.join(sorted(holders))} after the planned detaches")
                if reason not in self.refusals:
                    self.refusals.append(reason)
            self.step(_EXPRESSION_STAGE[kind.name], kind.remove_expression_kind, label,
                      partial(kind.delete_expression, self.client, expression["id"]),
                      (kind.name, "expression", expression["id"]))

    def remaining_holders(self, kind, expression_id):
        holders = set()
        for role in self.client.list_roles():
            for m in kind.list_attached(self.client, role["id"]):
                if (m.get("expressionId") == expression_id
                        and (kind.name, role["id"], m.get("id")) not in self._detached):
                    holders.add(role["name"])
        return holders

    # --- role cascade ---

    def roles(self):
        for name in self.items("roles"):
            rid = self.role_id(name)
            label = f"REMOVE role {name}"
            if not rid:
                self.step(STAGE_ROLES, "remove_role", label)
                continue
            self.cascade(name, rid)
            self.step(STAGE_ROLES, "remove_role", label, partial(self.client.delete_role, rid), ("role", rid))

    def cascade(self, name, rid):
        """Everything attached to the role is listed as its own step, then the role goes last."""
        client = self.client
        for a in client.list_role_assignments(rid):
            subject, sname = _subject(a)
            self.found_step(STAGE_ASSIGNMENTS, "remove_assignment", f"REMOVE {subject} {sname} -> {name}", a,
                            lambda f, d=getattr(client, f"delete_{subject}_assignment"), n=sname: d(n, f["id"]),
                            (subject, sname, rid))
        for kind in (COLUMN_MASKS, ROW_FILTERS):
            for m in kind.list_attached(client, rid):
                label = (f"REMOVE {name} -> {kind.verb} {describe_entity(m.get('entity', {}))} "
                         f"(expression id {m.get('expressionId')})")
                self.detach(kind, _ATTACH_STAGE[kind.name], rid, m, label)
        for g in client.list_grants(rid):
            label = f"REMOVE {name} -> {g.get('effect')} {g.get('action')} on {describe_entity(g.get('entity', {}))}"
            self.found_step(STAGE_GRANTS, "remove_grant", label, g,
                            lambda f: client.delete_grant(rid, f["id"]), (rid, g["id"]))
        for lg in client.list_location_grants(rid):
            go = " (with grant option)" if lg.get("grantOption") else ""
            self.found_step(STAGE_LOCATION_GRANTS, "remove_location_grant",
                            f"REMOVE {name} -> location {lg.get('location')}{go}", lg,
                            lambda f: client.delete_location_grant(rid, f["id"]), (rid, lg["id"]))


def _subject(assignment):
    """('user'|'group', name) of a role assignment read from the API. Keys verified on the
    lab: `username` (a user) and `groupName` (a group). Anything else: stop, never guess."""
    sub = assignment.get("subject") or {}
    if sub.get("type") == "GROUP" and sub.get("groupName"):
        return "group", sub["groupName"]
    if sub.get("type") == "USER" and (sub.get("username") or sub.get("userName")):
        return "user", sub.get("username") or sub.get("userName")
    raise RuntimeError(f"role assignment {assignment.get('id')}: unrecognised subject, refusing to guess")


def removal_steps(client, config):
    """Returns (steps in stage order, refusals). No call at all when there is no `remove:`."""
    if not config.get("remove"):
        return [], []
    r = _Removals(client, config)
    r.assignments()
    for kind in (COLUMN_MASKS, ROW_FILTERS):
        r.detaches(kind)
    r.grants()
    r.location_grants()
    r.roles()   # the role cascade, before the orphan check which must see every detach
    for kind in (COLUMN_MASKS, ROW_FILTERS):
        r.orphan_expressions(kind)
    return sorted(r.steps, key=lambda s: s.stage), r.refusals


def removal_actions(steps):
    """Steps -> plan tuples (kind, label, action)."""
    return [(s.kind, s.label, DELETE if s.delete else SKIP_ABSENT) for s in steps]


def plan_removals(client, config):
    """Steps to run; raises ValueError (exit code 2, nothing written) if a removal is refused."""
    steps, refusals = removal_steps(client, config)
    if refusals:
        raise ValueError("Removal refused (fail closed), nothing was changed:\n"
                         + "\n".join(f"  - {r}" for r in refusals))
    return steps


def apply_removals(steps):
    """Runs the steps of `plan_removals` in order; stops at the first failed call (RuntimeError from the client)."""
    done = 0
    for s in steps:
        if not s.delete:
            print(f"[{s.kind}] {s.label}: absent, skipping")
            continue
        try:
            s.delete()
        except RuntimeError as e:
            raise RuntimeError(f"{e} — stopped at '{s.label}' after {done} deletion(s), "
                               f"the ones printed above; nothing else was deleted") from None
        done += 1
        print(f"[{s.kind}] {s.label}: deleted")


def verify_removals(client, config):
    """Read-back of the `remove:` section: every declared object must be absent."""
    steps, _ = removal_steps(client, config)
    if not steps:
        return
    print("=== Removals (declared under remove:, must be absent) ===")
    for s in steps:
        print(f"[{s.kind}] {s.label}: {'STILL PRESENT' if s.delete else 'absent'}")
    present = sum(1 for s in steps if s.delete)
    print(f"{present} object(s) still present" if present else "All removed objects are absent.")
