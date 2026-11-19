"""Offline tests of the full BIAC category coverage: every supported entity category, the per-category
action matrix, the `allow_admin_privileges` guardrail, APPLY_* effects, and `remove:` on every category.
Same simulated client as the main tests.

Run:  python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import unittest

import yaml

try:
    import test_biac_deploy as base  # run with `-s tests`
except ImportError:
    from . import test_biac_deploy as base  # run as a package

bd = base.bd
from biac.categories import CATEGORIES, OUT_OF_SCOPE_CATEGORIES  # noqa: E402
from biac.entities import entities_equal, wire_entity  # noqa: E402

TABLE = {"category": "TABLES", "catalog": "tpch", "schema": "tiny", "table": "nation"}

# category -> (a valid entity, an action valid for it, the opt-in token(s) a widening grant needs or None)
CASES = {
    "TABLES": ({**TABLE, "tableType": "VIEW", "columns": ["name", "regionkey"]}, "SELECT", None),
    "TABLE_BRANCHES": ({"category": "TABLE_BRANCHES", "catalog": "ice", "schema": "s", "table": "t", "branch": "dev"},
                       "CREATE", None),
    "SCHEMA_PROPERTIES": ({"category": "SCHEMA_PROPERTIES", "catalog": "ice", "schema": "s", "property": "location"},
                          "SET", None),
    "TABLE_PROPERTIES": ({"category": "TABLE_PROPERTIES", "catalog": "ice", "schema": "s", "table": "t",
                          "property": "format", "value": "ORC"}, "SET", None),
    "SYSTEM_SESSION_PROPERTIES": ({"category": "SYSTEM_SESSION_PROPERTIES", "entityKey": "query_max_run_time"},
                                  "SET", None),
    "CATALOG_SESSION_PROPERTIES": ({"category": "CATALOG_SESSION_PROPERTIES", "catalog": "hive",
                                    "entityKey": "insert_existing_partitions_behavior"}, "SET", None),
    "FUNCTIONS": ({"category": "FUNCTIONS", "catalog": "udf", "schema": "s", "function": "f"}, "EXECUTE", None),
    "PROCEDURES": ({"category": "PROCEDURES", "catalog": "ice", "schema": "system", "procedure": "rollback"},
                   "EXECUTE", None),
    "COLUMN_MASK_EXPRESSIONS": ({"category": "COLUMN_MASK_EXPRESSIONS", "entityKey": "mask_a"}, "SHOW",
                                "COLUMN_MASK_EXPRESSIONS"),
    "ROW_FILTER_EXPRESSIONS": ({"category": "ROW_FILTER_EXPRESSIONS", "entityKey": "filter_a"}, "CREATE",
                               "ROW_FILTER_EXPRESSIONS"),
    "QUERIES": ({"category": "QUERIES", "allEntities": True}, "KILL", "QUERIES"),
    "ROLES": ({"category": "ROLES", "entityKey": "zz_other"}, "SHOW", "ROLES"),
    "USERS": ({"category": "USERS", "entityKey": "demo"}, "IMPERSONATE", "USERS"),
    "DATA_PRODUCTS": ({"category": "DATA_PRODUCTS", "domainName": "Sales"}, "SHOW", None),
    "AUDIT_LOGS": ({"category": "AUDIT_LOGS", "allEntities": True}, "SHOW", "AUDIT_LOGS"),
    "USER_INTERFACE": ({"category": "USER_INTERFACE", "uiFeature": "SETTINGS"}, "SHOW", None),
    "SYSTEM_INFORMATION": ({"category": "SYSTEM_INFORMATION", "allEntities": True}, "READ", "SYSTEM_INFORMATION"),
    "AI_MODELS": ({"category": "AI_MODELS", "entityKey": "gpt_x"}, "EXECUTE", None),
    "AGENT_SKILLS": ({"category": "AGENT_SKILLS", "entityKey": "skill_a"}, "USE", None),
    "EXTERNAL_MCP_SERVERS": ({"category": "EXTERNAL_MCP_SERVERS", "entityKey": "mcp_a"}, "USE", None),
}
# QUERIES:EXECUTE is not an admin privilege, only QUERIES:KILL is
ADMIN_ACTION = {"QUERIES": "KILL"}


def policy(entity, action="ALLOW_PLACEHOLDER", effect="ALLOW", role="zz_cov", section="grants", extra="", **grant_keys):
    """YAML text with one grant on one declared role (JSON flow style is valid YAML)."""
    grant = {"role": role, "effect": effect, "action": action, "entity": entity, **grant_keys}
    root = {"roles": [{"name": role}], "allowed_users": ["demo"]}
    if section == "grants":
        root["grants"] = [grant]
    else:
        root["remove"] = {"grants": [grant]}
    root.update(yaml.safe_load(extra) or {})   # `extra`: more root keys, as YAML text
    return json.dumps(root)


def errors_of(*args, **kwargs):
    return base.validation_errors(policy(*args, **kwargs))


class CoverageClient(base.FakeClient):
    """FakeClient that also knows APPLY_* grants (identity includes the expression id) and compares grants
    through entities_equal like the real client, so case / key order differences are idempotent."""

    def __init__(self):
        super().__init__()
        self.applied = set()  # (role_id, effect, action, entity-json, expression id)

    def create_grant(self, role_id, effect, action, entity, expression_id=None):
        self.writes += 1
        entity = json.dumps(wire_entity(entity), sort_keys=True)
        if expression_id is None:
            self.grants.add((role_id, effect, action, entity))
        else:
            self.applied.add((role_id, effect, action, entity, expression_id))

    def list_grants(self, role_id):
        plain = super().list_grants(role_id)
        applied = []
        for k in sorted(self.applied):
            if k[0] == role_id:
                key = "columnMaskExpressionId" if "COLUMN_MASK" in k[1] else "rowFilterExpressionId"
                applied.append({"id": k, "effect": k[1], "action": k[2], "entity": json.loads(k[3]), key: k[4]})
        return plain + applied

    def find_grant(self, role_id, effect, action, entity, expression_id=None):
        return next((g for g in self.list_grants(role_id)
                     if g["effect"] == effect and g["action"] == action and bd.entities_equal(g["entity"], entity)
                     and (expression_id is None
                          or expression_id in (g.get("columnMaskExpressionId"), g.get("rowFilterExpressionId")))),
                    None)

    def grant_exists(self, role_id, effect, action, entity, expression_id=None):
        return self.find_grant(role_id, effect, action, entity, expression_id) is not None

    def delete_grant(self, role_id, grant_id):
        self._delete(self.applied if len(grant_id) == 5 else self.grants, grant_id, f"grant {grant_id[2]}")

    def seed(self, role, effect, action, entity, expression_id=None):
        self.create_grant(self.roles[role], effect, action, entity, expression_id)
        self.writes = 0


def quiet_apply(client, config):
    with contextlib.redirect_stdout(io.StringIO()):
        bd.apply(client, config)


class CategoryTableTests(unittest.TestCase):
    def test_every_supported_category_is_covered_by_a_case(self):
        self.assertEqual(set(CASES), set(CATEGORIES))

    def test_out_of_scope_categories_are_known(self):
        self.assertTrue({"SPARK_JOBS", "JUPYTER_NOTEBOOKS", "S3_GOVERNANCE"} <= OUT_OF_SCOPE_CATEGORIES)


class PerCategoryValidationTests(unittest.TestCase):
    def test_valid_entry(self):
        for category, (entity, action, optin) in CASES.items():
            extra = ""
            if optin:
                extra += f"allow_admin_privileges: [{optin}]\n"
            with self.subTest(category=category):
                base.validate(policy(entity, action, extra=extra))
                base.validate(policy(entity, [action], effect="DENY"))

    def test_all_actions_of_the_matrix_are_accepted(self):
        for category, (entity, _, optin) in CASES.items():
            spec = CATEGORIES[category]
            with self.subTest(category=category):
                base.validate(policy(entity, list(spec.actions), effect="DENY"))

    def test_invalid_action_is_refused_with_the_allowed_list(self):
        for category, (entity, _, _) in CASES.items():
            with self.subTest(category=category):
                errors = errors_of(entity, "MANAGE", effect="DENY")
                self.assertIn("action 'MANAGE' is not valid for category", errors)
                self.assertIn(f"(allowed: {', '.join(CATEGORIES[category].actions)})", errors)

    def test_invalid_action_exits_2_from_the_command_line(self):
        d = base.WorkDir()
        d.setUp()
        self.addCleanup(d._tmp.cleanup)
        path = d.write("p.biac.yaml", policy(CASES["PROCEDURES"][0], "SELECT"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = bd.main(["--config", path, "--validate"])
        self.assertEqual(rc, 2)
        self.assertIn("allowed: EXECUTE", err.getvalue())

    def test_unknown_attribute_is_refused(self):
        for category, (entity, action, _) in CASES.items():
            with self.subTest(category=category):
                errors = errors_of({**entity, "bogus": "x"}, action, effect="DENY")
                self.assertIn("does not accept ['bogus']", errors)

    def test_attribute_of_another_category_is_refused(self):
        self.assertIn("does not accept ['function']", errors_of({**TABLE, "function": "f"}, "SELECT"))
        self.assertIn("does not accept ['table']",
                      errors_of({"category": "SCHEMA_PROPERTIES", "catalog": "c", "schema": "s", "table": "t"}, "SET"))
        self.assertIn("does not accept ['catalog']", errors_of({"category": "ROLES", "catalog": "c",
                                                                 "entityKey": "r"}, "SHOW", effect="DENY"))

    def test_wildcard_star_is_refused_for_every_attribute(self):
        for category, (entity, action, _) in CASES.items():
            for attr, value in entity.items():
                if attr in ("category", "allEntities", "columns"):
                    continue
                with self.subTest(category=category, attr=attr):
                    self.assertIn("'*' is not a valid wildcard", errors_of({**entity, attr: "*"}, action, effect="DENY"))

    def test_empty_string_attribute_is_refused(self):
        self.assertIn("must be a non-empty string", errors_of({**TABLE, "schema": ""}, "SELECT"))

    def test_enums(self):
        self.assertIn("invalid tableType 'BASE'", errors_of({**TABLE, "tableType": "BASE"}, "SELECT"))
        self.assertIn("invalid uiFeature 'NOPE'",
                      errors_of({"category": "USER_INTERFACE", "uiFeature": "NOPE"}, "SHOW"))
        for feature in ("QUERY_EDITOR", "EMULATED_CREDENTIALS", "SETTINGS_LOGIN"):
            base.validate(policy({"category": "USER_INTERFACE", "uiFeature": feature}, "SHOW"))
        for table_type in ("TABLE", "VIEW", "MATERIALIZED_VIEW"):
            base.validate(policy({**TABLE, "tableType": table_type}, "CREATE"))

    def test_narrow_attribute_needs_its_parent(self):
        cases = [({"category": "TABLES", "catalog": "c", "table": "t"}, "'table' given without 'schema'"),
                 ({"category": "TABLES", "catalog": "c", "schema": "s", "tableBranch": "b"},
                  "'tableBranch' given without 'table'"),
                 ({"category": "TABLES", "catalog": "c", "schema": "s", "columns": ["a"]}, "'columns' given without 'table'"),
                 ({"category": "TABLE_BRANCHES", "catalog": "c", "branch": "b"}, "'branch' given without 'table'"),
                 ({"category": "TABLE_PROPERTIES", "catalog": "c", "value": "v"}, "'value' given without 'property'"),
                 ({"category": "PROCEDURES", "catalog": "c", "procedure": "p"}, "'procedure' given without 'schema'"),
                 ({"category": "DATA_PRODUCTS", "dataProductName": "dp"}, "'dataProductName' given without 'domainName'")]
        for entity, message in cases:
            with self.subTest(entity=entity):
                self.assertIn(message, errors_of(entity, "SHOW", effect="DENY"))

    def test_scoped_categories_need_a_catalog_and_refuse_allentities(self):
        for category in ("TABLES", "TABLE_BRANCHES", "FUNCTIONS", "PROCEDURES", "SCHEMA_PROPERTIES",
                         "TABLE_PROPERTIES", "CATALOG_SESSION_PROPERTIES"):
            with self.subTest(category=category):
                self.assertIn("entity missing 'catalog'", errors_of({"category": category}, "SET", effect="DENY"))
                self.assertIn("allEntities:true is forbidden",
                              errors_of({"category": category, "allEntities": True}, "SET", effect="DENY"))

    def test_keyed_categories_need_a_key_or_allentities(self):
        for category in ("ROLES", "USERS", "SYSTEM_SESSION_PROPERTIES", "AI_MODELS", "AGENT_SKILLS",
                         "EXTERNAL_MCP_SERVERS", "COLUMN_MASK_EXPRESSIONS", "ROW_FILTER_EXPRESSIONS"):
            with self.subTest(category=category):
                self.assertIn("omitting both is ambiguous",
                              errors_of({"category": category}, CATEGORIES[category].actions[0], effect="DENY"))
                self.assertIn("pick one", errors_of({"category": category, "entityKey": "k", "allEntities": True},
                                                    CATEGORIES[category].actions[0], effect="DENY"))
                base.validate(policy({"category": category, "allEntities": True},
                                     CATEGORIES[category].actions[0], effect="DENY"))

    def test_global_categories_accept_both_forms_and_no_attribute(self):
        for category in ("QUERIES", "AUDIT_LOGS", "SYSTEM_INFORMATION"):
            action = CATEGORIES[category].actions[0]
            with self.subTest(category=category):
                base.validate(policy({"category": category}, action, effect="DENY"))
                base.validate(policy({"category": category, "allEntities": True}, action, effect="DENY"))
                self.assertIn("does not accept", errors_of({"category": category, "entityKey": "x"}, action,
                                                           effect="DENY"))

    def test_allentities_on_omit_categories_is_refused(self):
        for category in ("DATA_PRODUCTS", "USER_INTERFACE"):
            self.assertIn("allEntities:true is forbidden for", errors_of({"category": category, "allEntities": True},
                                                                         "SHOW", effect="DENY"))

    def test_out_of_scope_and_unknown_categories(self):
        for category in ("SPARK_JOBS", "JUPYTER_NOTEBOOKS", "S3_GOVERNANCE"):
            self.assertIn("out of scope for this tool", errors_of({"category": category, "allEntities": True},
                                                                   "SHOW", effect="DENY"))
        self.assertIn("unsupported or missing entity category 'NOPE'",
                      errors_of({"category": "NOPE"}, "SHOW", effect="DENY"))

    def test_masks_and_filters_still_accept_tables_only(self):
        text = ("roles:\n  - name: zz_cov\nrow_filters:\n  - name: f1\n    expression: \"true\"\n    role: zz_cov\n"
                "    entity: {category: ROLES, entityKey: x}\n")
        self.assertIn("expected one of TABLES", base.validation_errors(text))


class AdminOptInTests(unittest.TestCase):
    def test_widening_grants_on_admin_categories_need_the_opt_in(self):
        for category, (entity, action, optin) in CASES.items():
            if not optin:
                continue
            for effect in ("ALLOW", "ALLOW_WITH_GRANT_OPTION"):
                with self.subTest(category=category, effect=effect):
                    errors = errors_of(entity, ADMIN_ACTION.get(category, action), effect=effect)
                    self.assertIn("requires an explicit opt-in", errors)
                    self.assertIn("allow_admin_privileges", errors)

    def test_category_token_or_category_action_token_accepts(self):
        for category, (entity, action, optin) in CASES.items():
            if not optin:
                continue
            action = ADMIN_ACTION.get(category, action)
            with self.subTest(category=category):
                base.validate(policy(entity, action, extra=f"allow_admin_privileges: [{category}]\n"))
                base.validate(policy(entity, action, extra=f"allow_admin_privileges: [\"{category}:{action}\"]\n"))

    def test_an_opt_in_for_one_action_does_not_cover_another(self):
        entity = {"category": "ROLES", "entityKey": "zz_other"}
        errors = errors_of(entity, ["SHOW", "DROP"], extra="allow_admin_privileges: [\"ROLES:SHOW\"]\n")
        self.assertIn("DROP on ROLES", errors)
        self.assertNotIn("SHOW on ROLES", errors)

    def test_an_opt_in_for_another_category_does_not_cover(self):
        errors = errors_of({"category": "ROLES", "entityKey": "zz_other"}, "SHOW",
                           extra="allow_admin_privileges: [USERS]\n")
        self.assertIn("requires an explicit opt-in", errors)

    def test_deny_never_needs_the_opt_in(self):
        for category, (entity, action, optin) in CASES.items():
            with self.subTest(category=category):
                base.validate(policy(entity, action, effect="DENY"))

    def test_queries_only_kill_is_an_admin_privilege(self):
        entity = {"category": "QUERIES", "allEntities": True}
        base.validate(policy(entity, ["EXECUTE", "SHOW"]))
        self.assertIn("QUERIES", errors_of(entity, ["EXECUTE", "KILL"]))

    def test_all_forms_need_the_opt_in(self):
        cases = [({"category": "DATA_PRODUCTS"}, "SHOW", "DATA_PRODUCTS"),
                 ({"category": "USER_INTERFACE"}, "SHOW", "USER_INTERFACE"),
                 ({"category": "AGENT_SKILLS", "allEntities": True}, "CREATE", "AGENT_SKILLS"),
                 ({"category": "EXTERNAL_MCP_SERVERS", "allEntities": True}, "USE", "EXTERNAL_MCP_SERVERS"),
                 ({"category": "SYSTEM_SESSION_PROPERTIES", "allEntities": True}, "SET", "SYSTEM_SESSION_PROPERTIES")]
        for entity, action, token in cases:
            with self.subTest(entity=entity):
                errors = errors_of(entity, action)
                self.assertIn("all entities", errors)
                self.assertIn("allow_admin_privileges", errors)
                base.validate(policy(entity, action, extra=f"allow_admin_privileges: [{token}]\n"))

    def test_specific_forms_need_no_opt_in(self):
        base.validate(policy({"category": "DATA_PRODUCTS", "domainName": "Sales"}, "SHOW"))
        base.validate(policy({"category": "DATA_PRODUCTS", "domainName": "Sales", "dataProductName": "dp"}, "ALTER"))
        base.validate(policy({"category": "USER_INTERFACE", "uiFeature": "QUERY_EDITOR"}, "SHOW"))
        base.validate(policy({"category": "AGENT_SKILLS", "entityKey": "s"}, ["CREATE", "DROP", "UPDATE", "USE"]))

    def test_ai_models_all_entities_stays_open_for_backward_compatibility(self):
        base.validate(policy({"category": "AI_MODELS", "allEntities": True}, "EXECUTE"))

    def test_impersonate_needs_the_user_in_allowed_users(self):
        entity = {"category": "USERS", "entityKey": "intruder"}
        errors = errors_of(entity, "IMPERSONATE", extra="allow_admin_privileges: [USERS]\n")
        self.assertIn("'intruder', which is not declared in the root 'allowed_users'", errors)
        base.validate(policy({"category": "USERS", "entityKey": "demo"}, "IMPERSONATE",
                             extra="allow_admin_privileges: [USERS]\n"))
        # DENY is a restriction: no allowed_users needed
        base.validate(policy(entity, "IMPERSONATE", effect="DENY"))

    def test_impersonate_all_users_needs_only_the_opt_in(self):
        entity = {"category": "USERS", "allEntities": True}
        self.assertIn("requires an explicit opt-in", errors_of(entity, "IMPERSONATE"))
        base.validate(policy(entity, "IMPERSONATE", extra="allow_admin_privileges: [USERS]\n"))

    def test_grants_on_the_sysadmin_or_public_role_entities_are_refused(self):
        for key in ("sysadmin", "PUBLIC"):
            errors = errors_of({"category": "ROLES", "entityKey": key}, "SHOW",
                               extra="allow_admin_privileges: [ROLES]\n")
            self.assertIn("is forbidden by this tool", errors)

    def test_catalog_wide_opt_in_applies_to_the_new_scoped_categories(self):
        for entity, action in [({"category": "PROCEDURES", "catalog": "ice"}, "EXECUTE"),
                               ({"category": "TABLE_BRANCHES", "catalog": "ice"}, "SHOW"),
                               ({"category": "SCHEMA_PROPERTIES", "catalog": "ice"}, "SET"),
                               ({"category": "CATALOG_SESSION_PROPERTIES", "catalog": "ice"}, "SET")]:
            with self.subTest(entity=entity):
                self.assertIn("allow_catalog_wide", errors_of(entity, action))
                base.validate(policy(entity, action, extra="allow_catalog_wide: [ice]\n"))
                base.validate(policy(entity, action, effect="DENY"))

    def test_malformed_allow_admin_privileges_is_refused(self):
        entity = {"category": "ROLES", "entityKey": "zz_other"}
        self.assertIn("allow_admin_privileges", base.validation_errors("allow_admin_privileges: ROLES\n"))
        for token in ("roles", "NOPE", "ROLES:IMPERSONATE", "ROLES:SHOW:DROP", "*"):
            with self.subTest(token=token):
                errors = errors_of(entity, "SHOW", extra=f"allow_admin_privileges: [\"{token}\"]\n")
                self.assertIn("is not 'CATEGORY' or 'CATEGORY:ACTION'", errors)

    def test_removals_never_need_the_opt_in(self):
        for category, (entity, action, optin) in CASES.items():
            if optin:
                with self.subTest(category=category):
                    base.validate(policy(entity, ADMIN_ACTION.get(category, action), section="remove"))


class IdempotencyTests(unittest.TestCase):
    def shout(self, entity):
        """The same entity as the API could read it back: other case, other key order."""
        out = {}
        for key in sorted(entity, reverse=True):
            value = entity[key]
            if key in ("category", "allEntities", "tableType", "uiFeature"):
                out[key] = value
            elif isinstance(value, list):
                out[key] = [v.upper() for v in reversed(value)]
            elif isinstance(value, str) and (entity["category"], key) != ("USERS", "entityKey"):
                out[key] = value.upper()
            else:
                out[key] = value
        return out

    def test_plan_skips_a_grant_stored_with_other_case_and_key_order(self):
        for category, (entity, action, optin) in CASES.items():
            extra = f"allow_admin_privileges: [{optin}]\n" if optin else ""
            config = base.validate(policy(entity, ADMIN_ACTION.get(category, action), extra=extra))
            client = CoverageClient()
            client.create_role("zz_cov")
            client.seed("zz_cov", "ALLOW", ADMIN_ACTION.get(category, action), self.shout(entity))
            with self.subTest(category=category):
                kinds = {(k, a) for k, _, a in bd.plan(client, config) if k == "grant"}
                self.assertEqual(kinds, {("grant", "SKIP (exists)")})

    def test_plan_creates_then_skips_on_the_second_run(self):
        for category, (entity, action, optin) in CASES.items():
            extra = f"allow_admin_privileges: [{optin}]\n" if optin else ""
            config = base.validate(policy(entity, ADMIN_ACTION.get(category, action), extra=extra))
            client = CoverageClient()
            with self.subTest(category=category):
                self.assertIn(("grant", "CREATE"), {(k, a) for k, _, a in bd.plan(client, config)})
                quiet_apply(client, config)
                self.assertEqual({a for k, _, a in bd.plan(client, config) if k == "grant"}, {"SKIP (exists)"})
                writes = client.writes
                quiet_apply(client, config)
                self.assertEqual(client.writes, writes)

    def test_a_different_value_is_a_different_grant(self):
        base_entity = {"category": "TABLE_PROPERTIES", "catalog": "ice", "schema": "s", "table": "t",
                       "property": "format", "value": "ORC"}
        for attr, other in [("value", "PARQUET"), ("property", "location"), ("table", "u")]:
            self.assertFalse(bd.entities_equal(base_entity, {**base_entity, attr: other}), attr)
        self.assertFalse(bd.entities_equal({**TABLE, "tableType": "VIEW"}, {**TABLE, "tableType": "TABLE"}))
        self.assertFalse(bd.entities_equal({**TABLE, "tableBranch": "a"}, {**TABLE, "tableBranch": "b"}))
        self.assertFalse(bd.entities_equal({"category": "ROLES", "entityKey": "a"}, {"category": "ROLES", "allEntities": True}))

    def test_user_names_are_compared_with_their_case(self):
        self.assertFalse(bd.entities_equal({"category": "USERS", "entityKey": "Bob"},
                                           {"category": "USERS", "entityKey": "bob"}))
        self.assertTrue(bd.entities_equal({"category": "ROLES", "entityKey": "Bob"},
                                          {"category": "ROLES", "entityKey": "bob"}))

    def test_global_categories_have_a_single_form(self):
        self.assertTrue(bd.entities_equal({"category": "QUERIES"}, {"category": "QUERIES", "allEntities": True}))
        self.assertEqual(wire_entity({"category": "QUERIES"}), {"category": "QUERIES", "allEntities": True})
        self.assertEqual(wire_entity({"category": "ROLES", "entityKey": "r"}), {"category": "ROLES", "entityKey": "r"})

    def test_labels(self):
        label = bd.describe_entity
        self.assertEqual(label(TABLE), "tpch.tiny.nation")
        self.assertEqual(label({**TABLE, "tableBranch": "dev", "tableType": "VIEW", "columns": ["a"]}),
                         "tpch.tiny.nation@dev[VIEW].a")
        self.assertEqual(label({"category": "ROLES", "entityKey": "r"}), "ROLES:r")
        self.assertEqual(label({"category": "ROLES", "allEntities": True}), "ROLES:*")
        self.assertEqual(label({"category": "QUERIES", "allEntities": True}), "QUERIES")
        self.assertEqual(label({"category": "TABLE_BRANCHES", "catalog": "c", "schema": "s", "table": "t",
                                "branch": "b"}), "TABLE_BRANCHES:c.s.t@b")
        self.assertEqual(label({"category": "TABLE_PROPERTIES", "catalog": "c", "property": "p", "value": "v"}),
                         "TABLE_PROPERTIES:c.*#p=v")
        self.assertEqual(label({"category": "PROCEDURES", "catalog": "c"}), "PROCEDURES:c.*")
        self.assertEqual(label({"category": "CATALOG_SESSION_PROPERTIES", "catalog": "c"}),
                         "CATALOG_SESSION_PROPERTIES:c.*")
        self.assertEqual(label({"category": "DATA_PRODUCTS"}), "DATA_PRODUCTS:*")
        self.assertEqual(label({"category": "USER_INTERFACE"}), "UI:*")


class ApplyEffectsTests(unittest.TestCase):
    MASK_ENTITY = {**TABLE, "columns": ["name"]}
    EXPRESSIONS = ("column_masks:\n  - {name: m_name, expression: \"'x'\", role: zz_cov, "
                   "entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation, columns: [name]}}\n"
                   "row_filters:\n  - {name: f_all, expression: \"true\", role: zz_cov, "
                   "entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}}\n")

    def mask_grant(self, **kw):
        return policy(self.MASK_ENTITY, "SELECT", effect=kw.pop("effect", "APPLY_COLUMN_MASK"),
                      **{"column_mask": "m_name", **kw})

    def filter_grant(self, **kw):
        return policy(TABLE, "SELECT", effect=kw.pop("effect", "APPLY_ROW_FILTER"),
                      **{"row_filter": "f_all", **kw})

    def test_valid_forms_validate(self):
        base.validate(self.mask_grant())            # a plain APPLY grant narrows what a role sees: no opt-in
        base.validate(self.filter_grant())
        base.validate(self.mask_grant(effect="APPLY_COLUMN_MASK_WITH_GRANT_OPTION",
                                      extra="allow_admin_privileges: [COLUMN_MASK_EXPRESSIONS]\n"))
        base.validate(self.filter_grant(effect="APPLY_ROW_FILTER_WITH_GRANT_OPTION",
                                        extra="allow_admin_privileges: [ROW_FILTER_EXPRESSIONS]\n"))

    def test_delegating_the_right_to_apply_needs_the_admin_opt_in(self):
        for text, token in ((self.mask_grant(effect="APPLY_COLUMN_MASK_WITH_GRANT_OPTION"), "COLUMN_MASK_EXPRESSIONS"),
                            (self.filter_grant(effect="APPLY_ROW_FILTER_WITH_GRANT_OPTION"), "ROW_FILTER_EXPRESSIONS")):
            errors = base.validation_errors(text)
            self.assertIn("delegating a", errors)
            self.assertIn(f"allow_admin_privileges: [{token}]", errors)
        # the other kind's opt-in does not cover it
        self.assertIn("delegating a", base.validation_errors(
            self.mask_grant(effect="APPLY_COLUMN_MASK_WITH_GRANT_OPTION",
                            extra="allow_admin_privileges: [ROW_FILTER_EXPRESSIONS]\n")))

    def test_with_grant_option_is_a_widening_effect_apply_is_not(self):
        self.assertIn("APPLY_COLUMN_MASK_WITH_GRANT_OPTION", bd.WIDENING_EFFECTS)
        self.assertNotIn("APPLY_COLUMN_MASK", bd.WIDENING_EFFECTS)
        # on a whole catalog it would need allow_catalog_wide, but APPLY_* needs a table: refused anyway
        self.assertIn("'table'", base.validation_errors(policy({"category": "TABLES", "catalog": "tpch"}, "SELECT",
                                                               effect="APPLY_ROW_FILTER", row_filter="f")))

    def test_expression_key_rules(self):
        self.assertIn("needs 'column_mask: <expression name>'",
                      base.validation_errors(policy(self.MASK_ENTITY, "SELECT", effect="APPLY_COLUMN_MASK")))
        self.assertIn("takes 'row_filter', not 'column_mask'",
                      base.validation_errors(policy(TABLE, "SELECT", effect="APPLY_ROW_FILTER", row_filter="f",
                                                    column_mask="m")))
        self.assertIn("'column_mask' is only for the APPLY_* effects",
                      base.validation_errors(policy(TABLE, "SELECT", effect="ALLOW", column_mask="m")))
        self.assertIn("31 chars", base.validation_errors(self.mask_grant(column_mask="m" * 31)))

    def test_tables_and_select_only(self):
        self.assertIn("applies to a TABLES entity only",
                      base.validation_errors(policy({"category": "ROLES", "entityKey": "r"}, "SHOW",
                                                    effect="APPLY_ROW_FILTER", row_filter="f")))
        self.assertIn("single action SELECT", base.validation_errors(policy(TABLE, ["SELECT", "SHOW"],
                                                                            effect="APPLY_ROW_FILTER", row_filter="f")))
        self.assertIn("single action SELECT", base.validation_errors(policy(TABLE, "INSERT", effect="APPLY_ROW_FILTER",
                                                                            row_filter="f")))

    def test_mask_needs_columns_and_filter_must_not_have_them(self):
        self.assertIn("must list 'columns'", base.validation_errors(policy(TABLE, "SELECT", effect="APPLY_COLUMN_MASK",
                                                                           column_mask="m")))
        self.assertIn("must not specify 'columns'", base.validation_errors(policy(self.MASK_ENTITY, "SELECT",
                                                                                  effect="APPLY_ROW_FILTER",
                                                                                  row_filter="f")))

    def apply_config(self, text):
        return base.validate(text)

    def test_existing_expression_is_resolved_to_its_id(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        client.create_column_mask_expression("m_name", "'x'", "")
        mask_id = client.mask_expr["m_name"]
        config = self.apply_config(self.mask_grant())
        self.assertEqual([a for k, _, a in bd.plan(client, config) if k == "apply_grant"], ["CREATE"])
        quiet_apply(client, config)
        self.assertEqual({(g[1], g[2], g[4]) for g in client.applied}, {("APPLY_COLUMN_MASK", "SELECT", mask_id)})
        self.assertEqual([a for k, _, a in bd.plan(client, config) if k == "apply_grant"], ["SKIP (exists)"])

    def test_expression_created_in_the_same_file_is_resolved(self):
        root = json.loads(self.mask_grant())
        root.update({"column_masks": [{"name": "m_name", "expression": "'x'", "role": "zz_cov",
                                       "entity": self.MASK_ENTITY}]})
        config = self.apply_config(json.dumps(root))
        client = CoverageClient()
        actions = bd.plan(client, config)
        self.assertEqual([a for k, _, a in actions if k == "apply_grant"], ["CREATE"])   # no error: created above
        quiet_apply(client, config)
        self.assertEqual({g[4] for g in client.applied}, {client.mask_expr["m_name"]})

    def test_row_filter_created_in_the_same_file_is_applied_after_it_exists(self):
        root = json.loads(self.filter_grant())
        root["row_filters"] = [{"name": "f_all", "expression": "true", "role": "zz_cov", "entity": TABLE}]
        config = self.apply_config(json.dumps(root))
        client = CoverageClient()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.apply(client, config)
        lines = out.getvalue().splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith("[row_filter_expression]"))
        applied = next(i for i, line in enumerate(lines) if line.startswith("[apply_grant]"))
        self.assertLess(first, applied)
        self.assertEqual({g[4] for g in client.applied}, {client.rf_expr["f_all"]})

    def test_missing_expression_is_a_plan_error(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        writes = client.writes
        for text, name in ((self.mask_grant(), "m_name"), (self.filter_grant(), "f_all")):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as ctx:
                    bd.plan(client, self.apply_config(text))
                self.assertIn(f"expression {name!r} does not exist on the cluster", str(ctx.exception))
                self.assertEqual(client.writes, writes)

    def test_missing_expression_exits_2_and_writes_nothing(self):
        d = base.WorkDir()
        d.setUp()
        self.addCleanup(d._tmp.cleanup)
        client = CoverageClient()
        rc, _, err = d.run_main(["--env", d.env_file(), "--config", d.write("p.biac.yaml", self.mask_grant()),
                                 "--dry-run"], client)
        self.assertEqual(rc, 2)
        self.assertIn("does not exist on the cluster", err)
        self.assertEqual(client.writes, 0)

    def test_identity_includes_the_expression_id(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        client.create_column_mask_expression("m_name", "'x'", "")
        client.create_column_mask_expression("m_other", "'y'", "")
        other = client.mask_expr["m_other"]
        client.seed("zz_cov", "APPLY_COLUMN_MASK", "SELECT", self.MASK_ENTITY, other)
        config = self.apply_config(self.mask_grant())
        self.assertEqual([a for k, _, a in bd.plan(client, config) if k == "apply_grant"], ["CREATE"])
        quiet_apply(client, config)
        self.assertEqual(len(client.applied), 2)   # the grant of the other expression is untouched

    def test_remove_apply_grant(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        client.create_row_filter_expression("f_all", "true", "")
        fid = client.rf_expr["f_all"]
        client.seed("zz_cov", "APPLY_ROW_FILTER", "SELECT", TABLE, fid)
        client.seed("zz_cov", "APPLY_ROW_FILTER", "SELECT", TABLE, fid + 1)   # same entity, another expression
        config = self.apply_config(policy(TABLE, "SELECT", effect="APPLY_ROW_FILTER", section="remove",
                                          row_filter="f_all"))
        actions = [a for a in bd.plan(client, config) if a[0] == "remove_grant"]
        self.assertEqual([a[2] for a in actions], ["DELETE"])
        self.assertIn("(row_filter f_all)", actions[0][1])
        quiet_apply(client, config)
        self.assertEqual({g[4] for g in client.applied}, {fid + 1})
        self.assertEqual([a[2] for a in bd.plan(client, config) if a[0] == "remove_grant"], ["SKIP (absent)"])

    def test_remove_apply_grant_of_an_unknown_expression_is_absent(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        config = self.apply_config(policy(TABLE, "SELECT", effect="APPLY_ROW_FILTER", section="remove",
                                          row_filter="nope"))
        self.assertEqual([a[2] for a in bd.plan(client, config) if a[0] == "remove_grant"], ["SKIP (absent)"])

    def test_remove_and_create_of_the_same_apply_grant_conflict_but_not_for_another_expression(self):
        both = json.loads(self.filter_grant())
        both["remove"] = {"grants": [dict(both["grants"][0])]}
        self.assertIn("cannot be created and removed in one file", base.validation_errors(json.dumps(both)))
        both["remove"]["grants"][0]["row_filter"] = "f_other"
        base.validate(json.dumps(both))

    def test_role_cascade_lists_apply_grants(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        client.create_row_filter_expression("f_all", "true", "")
        client.seed("zz_cov", "APPLY_ROW_FILTER", "SELECT", TABLE, client.rf_expr["f_all"])
        config = base.validate('{"remove": {"roles": ["zz_cov"]}}')
        labels = [label for k, label, _ in bd.plan(client, config) if k == "remove_grant"]
        self.assertEqual(len(labels), 1)
        self.assertIn("rowFilterExpressionId=", labels[0])
        quiet_apply(client, config)
        self.assertEqual(client.applied, set())

    def test_create_grant_payload_carries_the_expression_id(self):
        sent = []

        class Spy(bd.BiacClient):
            def __init__(self):
                pass

            def _post(self, path, body, what=None):
                sent.append((path, body))

        spy = Spy()
        spy.create_grant(7, "APPLY_COLUMN_MASK", "SELECT", self.MASK_ENTITY, expression_id=42)
        spy.create_grant(7, "APPLY_ROW_FILTER_WITH_GRANT_OPTION", "SELECT", TABLE, expression_id=43)
        spy.create_grant(7, "ALLOW", "SELECT", TABLE)
        spy.create_grant(7, "ALLOW", "READ", {"category": "SYSTEM_INFORMATION"})
        self.assertEqual(sent[0][1]["columnMaskExpressionId"], 42)
        self.assertEqual(sent[1][1]["rowFilterExpressionId"], 43)
        self.assertNotIn("columnMaskExpressionId", sent[2][1])
        self.assertNotIn("rowFilterExpressionId", sent[2][1])
        self.assertEqual(sent[3][1]["entity"], {"category": "SYSTEM_INFORMATION", "allEntities": True})
        self.assertEqual(sent[0][0], "/roles/7/grants")


class ExampleTests(unittest.TestCase):
    def test_admin_example_plans_applies_and_is_idempotent(self):
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "examples", "admin-and-other.biac.yaml")
        config = bd.load_config(path)
        client = CoverageClient()
        self.assertTrue(all(a == "CREATE" for k, _, a in bd.plan(client, config) if k in ("grant", "apply_grant")))
        quiet_apply(client, config)
        self.assertEqual({a for k, _, a in bd.plan(client, config) if k in ("grant", "apply_grant")}, {"SKIP (exists)"})
        categories = {json.loads(g[3])["category"] for g in client.grants}
        self.assertTrue({"ROLES", "USERS", "QUERIES", "SYSTEM_INFORMATION", "AUDIT_LOGS", "PROCEDURES",
                         "TABLE_BRANCHES", "AGENT_SKILLS", "EXTERNAL_MCP_SERVERS", "TABLE_PROPERTIES",
                         "SCHEMA_PROPERTIES", "SYSTEM_SESSION_PROPERTIES", "CATALOG_SESSION_PROPERTIES",
                         "COLUMN_MASK_EXPRESSIONS", "ROW_FILTER_EXPRESSIONS"} <= categories)
        self.assertEqual(len(client.applied), 3)


class RemoveEveryCategoryTests(unittest.TestCase):
    def test_remove_grants_on_every_category(self):
        for category, (entity, action, _) in CASES.items():
            action = ADMIN_ACTION.get(category, action)
            client = CoverageClient()
            client.create_role("zz_cov")
            client.seed("zz_cov", "ALLOW", action, entity)
            client.seed("zz_cov", "ALLOW", action, {"category": "TABLES", "catalog": "keep", "schema": "s"}
                        if category != "TABLES" else {**TABLE, "table": "keep"})
            config = base.validate(policy(entity, action, section="remove"))
            with self.subTest(category=category):
                steps = [a for a in bd.plan(client, config) if a[0] == "remove_grant"]
                self.assertEqual([a[2] for a in steps], ["DELETE"])
                quiet_apply(client, config)
                self.assertEqual(len(client.list_grants(client.roles["zz_cov"])), 1)   # the other grant is untouched
                self.assertEqual([a[2] for a in bd.plan(client, config) if a[0] == "remove_grant"],
                                 ["SKIP (absent)"])

    def test_remove_matches_other_case_and_global_forms(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        client.seed("zz_cov", "ALLOW", "READ", {"category": "SYSTEM_INFORMATION", "allEntities": True})
        config = base.validate(policy({"category": "SYSTEM_INFORMATION"}, "READ", section="remove"))
        self.assertEqual([a[2] for a in bd.plan(client, config) if a[0] == "remove_grant"], ["DELETE"])

    def test_remove_entries_are_validated_like_creations(self):
        errors = base.validation_errors(policy(CASES["ROLES"][0], "SELECT", section="remove"))
        self.assertIn("remove.grants", errors)
        self.assertIn("action 'SELECT' is not valid for category ROLES", errors)
        self.assertIn("does not accept ['bogus']", base.validation_errors(
            policy({**CASES["PROCEDURES"][0], "bogus": 1}, "EXECUTE", section="remove")))

    def test_verify_prints_every_category(self):
        client = CoverageClient()
        client.create_role("zz_cov")
        for category, (entity, action, _) in CASES.items():
            client.seed("zz_cov", "ALLOW", ADMIN_ACTION.get(category, action), entity)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.verify(client, base.validate('{"roles": [{"name": "zz_cov"}]}'))
        text = out.getvalue()
        for needle in ("ROLES:zz_other", "USERS:demo", "QUERIES", "AUDIT_LOGS", "SYSTEM_INFORMATION",
                       "AGENT_SKILLS:skill_a", "EXTERNAL_MCP_SERVERS:mcp_a", "AI_MODELS:gpt_x",
                       "TABLE_BRANCHES:ice.s.t@dev", "PROCEDURES:ice.system.rollback", "UI:SETTINGS",
                       "TABLE_PROPERTIES:ice.s.t#format=ORC"):
            self.assertIn(needle, text)


class BareEntityWireTests(unittest.TestCase):
    """SEP 482-e refuses an entity without attributes unless allEntities is true (400 'must define some
    attributes if all entities is false', lab 2026-11-19) and stores it with allEntities: true."""

    def test_all_form_of_omit_categories_is_sent_with_all_entities(self):
        for cat in ("DATA_PRODUCTS", "USER_INTERFACE"):
            with self.subTest(category=cat):
                self.assertIs(wire_entity({"category": cat}).get("allEntities"), True)

    def test_narrowed_omit_entity_is_sent_as_written(self):
        e = {"category": "USER_INTERFACE", "uiFeature": "QUERY_EDITOR"}
        self.assertEqual(wire_entity(e), e)

    def test_stored_all_form_matches_the_yaml_form(self):
        for cat in ("DATA_PRODUCTS", "USER_INTERFACE", "QUERIES"):
            with self.subTest(category=cat):
                self.assertTrue(entities_equal({"category": cat}, {"category": cat, "allEntities": True}))


class ApplyGrantReadBackTests(unittest.TestCase):
    """SEP 482-e returns APPLY_* grants without an `action` field (lab, 2026-11-19)."""

    def client(self, grants):
        from biac.client import BiacClient
        c = object.__new__(BiacClient)
        c.list_grants = lambda role_id: grants
        return c

    def test_apply_grant_without_action_is_found(self):
        entity = {"category": "TABLES", "catalog": "tpch", "schema": "tiny", "table": "nation"}
        stored = [{"id": 856, "effect": "APPLY_ROW_FILTER", "rowFilterExpressionId": 42,
                   "entity": dict(entity, allEntities=False)}]
        c = self.client(stored)
        self.assertTrue(c.grant_exists(51, "APPLY_ROW_FILTER", "SELECT", entity, expression_id=42))
        self.assertFalse(c.grant_exists(51, "APPLY_ROW_FILTER", "SELECT", entity, expression_id=43))

    def test_plain_grant_still_compares_the_action(self):
        entity = {"category": "TABLES", "catalog": "tpch", "schema": "tiny"}
        c = self.client([{"id": 1, "effect": "ALLOW", "action": "SHOW", "entity": entity}])
        self.assertFalse(c.grant_exists(1, "ALLOW", "SELECT", entity))


if __name__ == "__main__":
    unittest.main()
