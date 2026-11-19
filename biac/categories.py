"""The BIAC entity categories this tool supports: attributes, actions, admin guardrails.

One table (`CATEGORIES`) is the single place that knows, per category, which
attributes an entity accepts, how "all entities" is expressed and which actions
a grant may carry. Validation, comparison (idempotency), labels and the wire
format all read it.

Sources (2026-11): the SEP privileges page (docs.starburst.io, "Built-in access
control privileges") and the SEP REST API reference (schemas EntityModel,
TableEntityData, TableBranchEntityData, SingleKeyEntityData, CatalogKeyEntityData,
GlobalEntityData, PropertyEntityData, FunctionEntityData, ProcedureEntityData,
DataProductEntityData, UiEntityData). Where the two disagree the matrix is
strict, unless a grant applied on a lab cluster proves otherwise; the points
still to be confirmed on a cluster are listed in the README ("To confirm on a lab").
The cluster itself answers authoritatively: GET /api/v1/biac/entityCategories/{category}/actions.
"""
from collections import namedtuple

# How an entity of the category says "all":
#   SCOPED  catalog-rooted, narrowed by adding attributes; "all" = omitting them. allEntities is forbidden,
#           and the catalog is always required (no "all catalogs" form).
#   KEYED   one optional `entityKey` (SingleKeyEntityData). Omitting it is ambiguous in the API reference
#           ("if empty it applies to all"), so this tool refuses it: name the key, or write `allEntities: true`.
#   GLOBAL  no attribute at all (QUERIES, AUDIT_LOGS, SYSTEM_INFORMATION); `allEntities: true` is accepted
#           and sent (see GLOBAL_SENDS_ALL_ENTITIES), it may also be omitted.
#   OMIT    DATA_PRODUCTS / USER_INTERFACE: "all" = omitting the narrower attribute(s); allEntities forbidden.
SCOPED, KEYED, GLOBAL, OMIT = "scoped", "keyed", "global", "omit"

# Payload of an entity of a GLOBAL category: {category, allEntities: true}. Not proven on a cluster yet
# (README, "To confirm on a lab"): set to False to send {category} alone.
GLOBAL_SENDS_ALL_ENTITIES = True

Category = namedtuple("Category", "shape attrs chain actions")
# attrs:  attribute names accepted besides `category` / `allEntities` (in label order)
# chain:  (narrow, wider) pairs: `narrow` needs `wider` to be set ("a table always needs its schema")

TABLE_ACTIONS = ("ALTER", "CREATE", "DELETE", "DROP", "INSERT", "REFRESH", "SELECT", "SHOW", "UPDATE")

CATEGORIES = {
    "TABLES": Category(SCOPED, ("catalog", "schema", "table", "tableBranch", "tableType", "columns"),
                       (("schema", "catalog"), ("table", "schema"), ("tableBranch", "table"), ("columns", "table")),
                       TABLE_ACTIONS),
    "TABLE_BRANCHES": Category(SCOPED, ("catalog", "schema", "table", "branch"),
                               (("schema", "catalog"), ("table", "schema"), ("branch", "table")),
                               ("ALTER", "CREATE", "DROP", "SHOW")),
    "FUNCTIONS": Category(SCOPED, ("catalog", "schema", "function"),
                          (("schema", "catalog"), ("function", "schema")),
                          ("CREATE", "DROP", "EXECUTE", "SHOW")),
    "PROCEDURES": Category(SCOPED, ("catalog", "schema", "procedure"),
                           (("schema", "catalog"), ("procedure", "schema")),
                           ("EXECUTE",)),
    "SCHEMA_PROPERTIES": Category(SCOPED, ("catalog", "schema", "property", "value"),
                                  (("schema", "catalog"), ("value", "property")),
                                  ("SET",)),
    "TABLE_PROPERTIES": Category(SCOPED, ("catalog", "schema", "table", "property", "value"),
                                 (("schema", "catalog"), ("table", "schema"), ("value", "property")),
                                 ("SET",)),
    "CATALOG_SESSION_PROPERTIES": Category(SCOPED, ("catalog", "entityKey"), (), ("SET",)),
    "SYSTEM_SESSION_PROPERTIES": Category(KEYED, ("entityKey",), (), ("SET",)),
    "ROLES": Category(KEYED, ("entityKey",), (), ("CREATE", "DROP", "SHOW")),
    "USERS": Category(KEYED, ("entityKey",), (), ("IMPERSONATE",)),
    "COLUMN_MASK_EXPRESSIONS": Category(KEYED, ("entityKey",), (), ("ALTER", "CREATE", "DROP", "SHOW")),
    "ROW_FILTER_EXPRESSIONS": Category(KEYED, ("entityKey",), (), ("ALTER", "CREATE", "DROP", "SHOW")),
    "AI_MODELS": Category(KEYED, ("entityKey",), (), ("CREATE", "DROP", "EXECUTE", "UPDATE")),
    "AGENT_SKILLS": Category(KEYED, ("entityKey",), (), ("CREATE", "DROP", "UPDATE", "USE")),
    "EXTERNAL_MCP_SERVERS": Category(KEYED, ("entityKey",), (), ("USE",)),
    "QUERIES": Category(GLOBAL, (), (), ("EXECUTE", "KILL", "SHOW")),
    # AUDIT_LOGS: no action list on the privileges page nor in the API reference; READ (as SYSTEM_INFORMATION)
    # is the only guess, UNVERIFIED (check with GET .../entityCategories/AUDIT_LOGS/actions).
    "AUDIT_LOGS": Category(GLOBAL, (), (), ("READ",)),
    "SYSTEM_INFORMATION": Category(GLOBAL, (), (), ("READ", "WRITE")),
    "DATA_PRODUCTS": Category(OMIT, ("domainName", "dataProductName"), (("dataProductName", "domainName"),),
                              ("ALTER", "CREATE", "DROP", "PUBLISH", "SHOW")),
    "USER_INTERFACE": Category(OMIT, ("uiFeature",), (), ("SHOW",)),
}

# Known to the BIAC API but outside the scope of this tool (Spark / notebooks / S3 governance products).
OUT_OF_SCOPE_CATEGORIES = frozenset({
    "SPARK_RESOURCE_POOLS", "SPARK_SECRETS", "SPARK_INSTANCE_IMAGES", "SPARK_JOBS", "SPARK_CONNECT_SERVERS",
    "SPARK_UPLOADS", "SPARK_SECRET_PROVIDERS", "SPARK_SYSTEM", "JUPYTER_NOTEBOOKS", "S3_GOVERNANCE"})

TABLE_TYPES = ("TABLE", "VIEW", "MATERIALIZED_VIEW")
UI_FEATURES = ("QUERY_EDITOR", "EXPORT_DATA", "DATA_PRODUCTS", "DATA_PRODUCTS_SHARING", "DATA_PRODUCTS_AS_CODE",
               "CATALOG_EXPLORER", "OVERVIEW", "QUERIES", "CLUSTER_HISTORY", "USAGE_METRICS", "SPARK_RUNTIME",
               "SPARK_MANAGEMENT", "SQL_JOBS", "AI_MODELS", "SETTINGS", "SETTINGS_LICENSE", "SETTINGS_LOGIN",
               "SCHEMA_DISCOVERY", "S3_GOVERNANCE", "OBJECT_STORES", "EMULATED_CREDENTIALS")
ENUM_ATTRS = {"tableType": TABLE_TYPES, "uiFeature": UI_FEATURES}

# Attributes compared as exact text (everything else is compared case-insensitively, the API lowercases
# catalog/schema/table/function names). A user name must match the authentication system's case (privileges page).
CASE_SENSITIVE = {("USERS", "entityKey")}

# --------------------------------------------------------------------------
# Admin guardrail: root key `allow_admin_privileges: [CATEGORY or CATEGORY:ACTION, ...]`
# --------------------------------------------------------------------------

# Widening grants (ALLOW / ALLOW_WITH_GRANT_OPTION / APPLY_*_WITH_GRANT_OPTION) on these need an explicit opt-in:
# the category as a whole, or one of the listed actions only (None = every action of the category).
ADMIN_CATEGORIES = {
    "ROLES": None,
    "USERS": None,
    "SYSTEM_INFORMATION": None,
    "AUDIT_LOGS": None,
    "COLUMN_MASK_EXPRESSIONS": None,
    "ROW_FILTER_EXPRESSIONS": None,
    "QUERIES": ("KILL",),
}
# "All" forms that need the same opt-in (the category name): `allEntities: true` on a KEYED category, except
# AI_MODELS (kept open for backward compatibility: it is the form the SEP UI itself emits), and an OMIT category
# without its narrowing attribute (DATA_PRODUCTS without domainName, USER_INTERFACE without uiFeature).
ALL_FORM_EXEMPT = frozenset({"AI_MODELS"})


def valid_admin_token(token):
    """'CATEGORY' or 'CATEGORY:ACTION' naming a supported category (and one of its actions)."""
    category, _, action = token.partition(":")
    spec = CATEGORIES.get(category)
    return bool(spec) and (not action or action in spec.actions) and token.count(":") <= 1


def is_all_form(entity):
    """True for an entity that stands for every entity of a category that has a narrower form."""
    spec = CATEGORIES.get(entity.get("category"))
    if not spec:
        return False
    if spec.shape == KEYED:
        return entity.get("allEntities") is True
    if spec.shape == OMIT:
        first = spec.attrs[0]   # domainName / uiFeature
        return not entity.get(first)
    return False


def admin_opt_ins_needed(category, actions, entity):
    """The opt-in tokens a widening grant lacks unless the file lists them (any one of the pair satisfies it).

    Returns a list of (category-token, action-token or None) pairs: each pair is satisfied by listing either
    `category` or `category:action`. An empty list means the grant needs no opt-in."""
    needed = []
    if category in ADMIN_CATEGORIES:
        restricted = ADMIN_CATEGORIES[category]
        for action in actions:
            if restricted is None or action in restricted:
                needed.append((category, action))
    elif category not in ALL_FORM_EXEMPT and is_all_form(entity):
        needed.extend((category, action) for action in actions)
    return needed
