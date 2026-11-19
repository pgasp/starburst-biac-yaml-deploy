"""Rules and vocabulary shared by validation, planning and execution."""
import re

ROLE_NAME_RE = re.compile(r"^[a-z0-9_]+$")

# Guardrails (fail closed): these roles can never be the target of a grant,
# location grant, column mask, row filter or assignment, nor be declared.
FORBIDDEN_ROLES = frozenset({"sysadmin", "public"})
# Effects that widen access: on a whole catalog they need an explicit opt-in through the root key
# 'allow_catalog_wide', and on an administrative category one through 'allow_admin_privileges'.
# APPLY_* (without grant option) attach a mask / filter, which narrows what a role sees: not widening.
WIDENING_EFFECTS = frozenset({"ALLOW", "ALLOW_WITH_GRANT_OPTION",
                              "APPLY_COLUMN_MASK_WITH_GRANT_OPTION", "APPLY_ROW_FILTER_WITH_GRANT_OPTION"})
PLAIN_EFFECTS = ("ALLOW", "DENY", "ALLOW_WITH_GRANT_OPTION")
APPLY_EFFECTS = ("APPLY_COLUMN_MASK", "APPLY_COLUMN_MASK_WITH_GRANT_OPTION",
                 "APPLY_ROW_FILTER", "APPLY_ROW_FILTER_WITH_GRANT_OPTION")
EFFECTS = PLAIN_EFFECTS + APPLY_EFFECTS

MAX_DESCRIPTION_LENGTH = 250  # BIAC API limit, confirmed by testing against a real cluster
# BIAC API limit on column-mask / row-filter expression names, observed on SEP 482-e:
# "name: value may not be more than 30 characters" (POST /expressions/{columnMask,rowFilter}).
MAX_EXPRESSION_NAME_LENGTH = 30


def grant_actions(g):
    """A grant's 'action' may be a single string or a YAML list of strings
    (one API call will be made per action). A comma-separated STRING is
    deliberately NOT supported: '{action: CREATE,DELETE,SELECT}' inside a
    YAML flow mapping does not mean what it looks like — the unquoted comma
    is parsed as a mapping separator, silently producing 'action: CREATE'
    plus bogus extra keys (DELETE, SELECT, ... each with value null), not a
    multi-action grant. This was hit for real and is now caught explicitly
    by the validator's unknown-key check. Use a YAML list instead:
        action: [CREATE, DELETE, SELECT]
    """
    a = g.get("action")
    if isinstance(a, list):
        return a
    if isinstance(a, str):
        return [a]
    return []


class ExpressionKind:
    """A policy object made of a named SQL expression plus its attachment to
    a role on one table: column masks and row filters are the two instances.

    Their client methods follow one naming scheme (find_<name>_expression,
    create_<name>_expression, <name>_attached, attach_<name>, list_<name>s,
    and for removals find_<name>_attachment, detach_<name>,
    delete_<name>_expression);
    this class is the single place that knows it, so planner, executor and
    verify handle both kinds with the same code.
    """

    def __init__(self, name, section, verb, admin_category):
        self.name = name          # 'column_mask' (also the client method infix)
        self.section = section    # root key of the YAML file: 'column_masks'
        self.verb = verb          # word used in plan labels: 'mask'
        self.admin_category = admin_category   # BIAC category of the expressions: guardrail opt-in name
        self.expression_kind = f"{name}_expression"   # plan / apply output tag
        self.attach_kind = f"{name}_attach"           # plan output tag
        self.remove_kind = f"remove_{name}_attach"                  # plan tag of a detach
        self.remove_expression_kind = f"remove_{name}_expression"   # plan tag of an expression deletion

    def find(self, client, name):
        return getattr(client, f"find_{self.name}_expression")(name)

    def create(self, client, name, expression, description):
        return getattr(client, f"create_{self.name}_expression")(name, expression, description)

    def attached(self, client, role_id, entity, expression_id):
        return getattr(client, f"{self.name}_attached")(role_id, entity, expression_id)

    def attach(self, client, role_id, entity, expression_id):
        return getattr(client, f"attach_{self.name}")(role_id, entity, expression_id)

    def list_attached(self, client, role_id):
        return getattr(client, f"list_{self.name}s")(role_id)

    def find_attachment(self, client, role_id, entity, expression_id):
        return getattr(client, f"find_{self.name}_attachment")(role_id, entity, expression_id)

    def detach(self, client, role_id, attachment_id):
        return getattr(client, f"detach_{self.name}")(role_id, attachment_id)

    def delete_expression(self, client, expression_id):
        return getattr(client, f"delete_{self.name}_expression")(expression_id)


COLUMN_MASKS = ExpressionKind("column_mask", "column_masks", "mask", "COLUMN_MASK_EXPRESSIONS")
ROW_FILTERS = ExpressionKind("row_filter", "row_filters", "rowfilter", "ROW_FILTER_EXPRESSIONS")


# An APPLY_* grant names the expression it applies by name, under the key `column_mask` / `row_filter`
# (the kind's `name`); it is resolved to the expression id at plan time.
APPLY_KIND = {"APPLY_COLUMN_MASK": COLUMN_MASKS, "APPLY_COLUMN_MASK_WITH_GRANT_OPTION": COLUMN_MASKS,
              "APPLY_ROW_FILTER": ROW_FILTERS, "APPLY_ROW_FILTER_WITH_GRANT_OPTION": ROW_FILTERS}


def apply_kind(grant):
    """The ExpressionKind an APPLY_* grant refers to, None for a plain grant."""
    return APPLY_KIND.get(grant.get("effect"))


def apply_expression_name(grant):
    """The expression name of an APPLY_* grant (None if absent or not an APPLY_* grant)."""
    kind = apply_kind(grant)
    return grant.get(kind.name) if kind else None
