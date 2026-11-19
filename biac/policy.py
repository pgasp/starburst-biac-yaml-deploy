"""Rules and vocabulary shared by validation, planning and execution."""
import re

ROLE_NAME_RE = re.compile(r"^[a-z0-9_]+$")

# Guardrails (fail closed): these roles can never be the target of a grant,
# location grant, column mask, row filter or assignment, nor be declared.
FORBIDDEN_ROLES = frozenset({"sysadmin", "public"})
# Effects that widen access; on a whole catalog they need an explicit opt-in
# through the root key 'allow_catalog_wide'.
WIDENING_EFFECTS = frozenset({"ALLOW", "ALLOW_WITH_GRANT_OPTION"})
EFFECTS = ("ALLOW", "DENY", "ALLOW_WITH_GRANT_OPTION")

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
    create_<name>_expression, <name>_attached, attach_<name>, list_<name>s);
    this class is the single place that knows it, so planner, executor and
    verify handle both kinds with the same code.
    """

    def __init__(self, name, section, verb):
        self.name = name          # 'column_mask' (also the client method infix)
        self.section = section    # root key of the YAML file: 'column_masks'
        self.verb = verb          # word used in plan labels: 'mask'
        self.expression_kind = f"{name}_expression"   # plan / apply output tag
        self.attach_kind = f"{name}_attach"           # plan output tag

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


COLUMN_MASKS = ExpressionKind("column_mask", "column_masks", "mask")
ROW_FILTERS = ExpressionKind("row_filter", "row_filters", "rowfilter")
