"""Offline unit tests for biac_deploy.py — simulated BIAC client, no network.

Run:  python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import biac_deploy as bd  # noqa: E402

FAKE_PASSWORD = "S3cr3t-Pa55word-do-not-leak"

GOOD_YAML = """\
roles:
  - name: zz_test_reader
grants:
  - {role: zz_test_reader, effect: ALLOW, action: SELECT, entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}}
allowed_users: [demo]
assignments:
  - {role: zz_test_reader, users: [demo]}
"""


class FakeClient:
    """In-memory stand-in for BiacClient (same method surface used by plan/apply/verify)."""

    def __init__(self):
        self.roles = {}      # name -> id
        self.grants = set()  # (role_id, effect, action, entity-json)
        self.assign = set()  # (kind, subject, role_id)
        self.writes = 0
        self.mask_expr, self.rf_expr = {}, {}
        self.mask_text, self.rf_text = {}, {}  # name -> expression text
        self.mask_att, self.rf_att, self.loc = set(), set(), set()

    def __repr__(self):
        return "FakeClient()"

    # roles
    def find_role(self, name):
        return {"id": self.roles[name], "name": name} if name in self.roles else None

    def create_role(self, name):
        self.writes += 1
        self.roles[name] = len(self.roles) + 1
        return self.find_role(name)

    # grants
    def grant_exists(self, role_id, effect, action, entity):
        return (role_id, effect, action, json.dumps(entity, sort_keys=True)) in self.grants

    def create_grant(self, role_id, effect, action, entity):
        self.writes += 1
        self.grants.add((role_id, effect, action, json.dumps(entity, sort_keys=True)))

    def location_grant_exists(self, role_id, location, go):
        return (role_id, location, go) in self.loc

    def create_location_grant(self, role_id, location, go):
        self.writes += 1
        self.loc.add((role_id, location, go))

    # expressions / masks / filters
    def find_column_mask_expression(self, name):
        return ({"id": self.mask_expr[name], "name": name, "expression": self.mask_text[name]}
                if name in self.mask_expr else None)

    def create_column_mask_expression(self, name, expression, description):
        self.writes += 1
        self.mask_expr[name] = 100 + len(self.mask_expr)
        self.mask_text[name] = expression
        return {"id": self.mask_expr[name]}

    def column_mask_attached(self, role_id, entity, expr_id):
        return (role_id, json.dumps(entity, sort_keys=True), expr_id) in self.mask_att

    def attach_column_mask(self, role_id, entity, expr_id):
        self.writes += 1
        self.mask_att.add((role_id, json.dumps(entity, sort_keys=True), expr_id))

    def find_row_filter_expression(self, name):
        return ({"id": self.rf_expr[name], "name": name, "expression": self.rf_text[name]}
                if name in self.rf_expr else None)

    def create_row_filter_expression(self, name, expression, description):
        self.writes += 1
        self.rf_expr[name] = 200 + len(self.rf_expr)
        self.rf_text[name] = expression
        return {"id": self.rf_expr[name]}

    def row_filter_attached(self, role_id, entity, expr_id):
        return (role_id, json.dumps(entity, sort_keys=True), expr_id) in self.rf_att

    def attach_row_filter(self, role_id, entity, expr_id):
        self.writes += 1
        self.rf_att.add((role_id, json.dumps(entity, sort_keys=True), expr_id))

    # assignments
    def user_assigned(self, user, role_id):
        return ("u", user, role_id) in self.assign

    def assign_user(self, user, role_id):
        self.writes += 1
        self.assign.add(("u", user, role_id))

    def group_assigned(self, group, role_id):
        return ("g", group, role_id) in self.assign

    def assign_group(self, group, role_id):
        self.writes += 1
        self.assign.add(("g", group, role_id))


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


def read_text(path):
    with open(path) as f:
        return f.read()


def validate(yaml_text):
    return bd.parse_config(yaml_text.encode())


def validation_errors(yaml_text):
    """Returns the error text of a failed validation ('' if it passed)."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        try:
            validate(yaml_text)
        except ValueError as e:
            return str(e)
    return ""


class WorkDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, content):
        with open(self.path(name), "w") as f:
            f.write(content)
        return self.path(name)

    def env_file(self):
        return self.write("test.env", f"SB_HOST=sep.example.test\nSB_PORT=443\nSB_USER=admin\nSB_PASSWORD={FAKE_PASSWORD}\n")

    def run_main(self, argv, client):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(bd, "BiacClient", lambda env: client), \
                mock.patch("builtins.input", side_effect=AssertionError("interactive prompt used")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = bd.main(argv)
        return rc, out.getvalue(), err.getvalue()


class FingerprintTests(unittest.TestCase):
    ACTIONS = [("role", "r", "CREATE"), ("grant", "r -> ALLOW SELECT on tpch.tiny.nation", "CREATE")]
    CLUSTER = "sep.example.test:443"

    def test_stable_for_same_input(self):
        a = bd.build_signed_plan(self.ACTIONS, b"yaml-content", self.CLUSTER)
        b = bd.build_signed_plan(list(self.ACTIONS), b"yaml-content", self.CLUSTER)
        self.assertEqual(a["fingerprint"], b["fingerprint"])
        self.assertRegex(a["fingerprint"], r"^[0-9a-f]{64}$")

    def test_independent_of_key_order(self):
        r1 = [{"kind": "role", "label": "r", "action": "CREATE"}]
        r2 = [{"action": "CREATE", "label": "r", "kind": "role"}]
        self.assertEqual(bd.plan_fingerprint(r1, "x", "c"), bd.plan_fingerprint(r2, "x", "c"))

    def test_changes_with_plan_yaml_or_cluster(self):
        base = bd.build_signed_plan(self.ACTIONS, b"yaml-content", self.CLUSTER)["fingerprint"]
        self.assertNotEqual(base, bd.build_signed_plan(self.ACTIONS[:1], b"yaml-content", self.CLUSTER)["fingerprint"])
        self.assertNotEqual(base, bd.build_signed_plan(self.ACTIONS, b"yaml-content2", self.CLUSTER)["fingerprint"])
        self.assertNotEqual(base, bd.build_signed_plan(self.ACTIONS, b"yaml-content", "other:443")["fingerprint"])


class SignedPlanFlowTests(WorkDir):
    def setUp(self):
        super().setUp()
        self.cfg = self.write("t.biac.yaml", GOOD_YAML)
        self.env = self.env_file()
        self.plan = self.path("plan.json")

    def dry(self, client):
        return self.run_main(["--env", self.env, "--config", self.cfg, "--dry-run", "--plan-out", self.plan], client)

    def apply_signed(self, client):
        return self.run_main(["--env", self.env, "--config", self.cfg, "--apply", "--plan", self.plan], client)

    def test_dry_run_writes_plan_and_fingerprint_without_writes(self):
        c = FakeClient()
        rc, out, _ = self.dry(c)
        self.assertEqual(rc, 0)
        self.assertEqual(c.writes, 0)
        signed = read_json(self.plan)
        self.assertIn(signed["fingerprint"], out)
        self.assertEqual(signed["cluster"], "sep.example.test:443")
        self.assertEqual({r["action"] for r in signed["plan"]}, {"CREATE"})

    def test_apply_with_matching_plan_runs_without_prompt(self):
        c = FakeClient()
        self.dry(c)
        rc, out, _ = self.apply_signed(c)
        self.assertEqual(rc, 0)
        self.assertIn("zz_test_reader", c.roles)
        self.assertGreater(c.writes, 0)
        self.assertIn("no prompt", out)

    def test_apply_twice_is_noop_after_state_matches(self):
        c = FakeClient()
        self.dry(c)
        self.apply_signed(c)
        writes = c.writes
        self.dry(c)  # new plan: everything SKIP
        rc, out, _ = self.apply_signed(c)
        self.assertEqual(rc, 0)
        self.assertEqual(c.writes, writes)
        self.assertIn("Nothing to do", out)

    def test_refused_when_plan_file_modified(self):
        c = FakeClient()
        self.dry(c)
        signed = read_json(self.plan)
        signed["plan"][0]["label"] = "something_else"  # fingerprint left untouched
        write_json(self.plan, signed)
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, 0)
        self.assertIn("REFUSED", err)
        self.assertIn("altered", err)

    def test_refused_when_plan_and_fingerprint_both_forged(self):
        c = FakeClient()
        self.dry(c)
        signed = read_json(self.plan)
        signed["plan"] = signed["plan"][:1]
        signed["fingerprint"] = bd.plan_fingerprint(signed["plan"], signed["config_sha256"], signed["cluster"])
        write_json(self.plan, signed)
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, 0)
        self.assertIn("differs", err)

    def test_refused_when_yaml_changed_after_signing(self):
        c = FakeClient()
        self.dry(c)
        self.write("t.biac.yaml", GOOD_YAML.replace("nation", "region"))
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, 0)
        self.assertIn("YAML file changed", err)

    def test_refused_when_yaml_changed_even_by_a_comment(self):
        c = FakeClient()
        self.dry(c)
        self.write("t.biac.yaml", GOOD_YAML + "# harmless comment\n")
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, 0)
        self.assertIn("YAML file changed", err)

    def test_refused_when_cluster_state_changed(self):
        c = FakeClient()
        self.dry(c)
        c.create_role("zz_test_reader")  # someone created the role in between
        writes = c.writes
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, writes)
        self.assertIn("recomputed plan differs", err)

    def test_refused_for_another_cluster(self):
        c = FakeClient()
        self.dry(c)
        other = self.write("other.env", f"SB_HOST=other.example.test\nSB_USER=a\nSB_PASSWORD={FAKE_PASSWORD}\n")
        rc, _, err = self.run_main(["--env", other, "--config", self.cfg, "--apply", "--plan", self.plan], c)
        self.assertEqual(rc, bd.EXIT_PLAN_REFUSED)
        self.assertEqual(c.writes, 0)

    def test_manual_apply_without_plan_keeps_interactive_prompt(self):
        c = FakeClient()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(bd, "BiacClient", lambda env: c), \
                mock.patch("builtins.input", return_value="no") as prompt, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = bd.main(["--env", self.env, "--config", self.cfg, "--apply"])
        prompt.assert_called_once()
        self.assertEqual(rc, 1)
        self.assertEqual(c.writes, 0)

    def test_manual_apply_with_yes_applies(self):
        c = FakeClient()
        with mock.patch.object(bd, "BiacClient", lambda env: c), \
                mock.patch("builtins.input", return_value="yes"), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = bd.main(["--env", self.env, "--config", self.cfg, "--apply"])
        self.assertEqual(rc, 0)
        self.assertIn("zz_test_reader", c.roles)

    def test_plan_flags_are_mode_specific(self):
        for argv in (["--verify", "--plan-out", self.plan], ["--dry-run", "--plan", self.plan],
                     ["--apply", "--plan-out", self.plan]):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                bd.main(["--env", self.env, "--config", self.cfg] + argv)

    def test_no_credential_in_any_output(self):
        c = FakeClient()
        rc1, o1, e1 = self.dry(c)
        rc2, o2, e2 = self.apply_signed(c)
        plan_text = read_text(self.plan)
        for text in (o1, e1, o2, e2, plan_text):
            self.assertNotIn(FAKE_PASSWORD, text)

    def test_api_error_is_redacted_and_has_no_traceback(self):
        class Boom(FakeClient):
            def find_role(self, name):
                raise RuntimeError(f"GET /roles failed: 401 echo of Authorization with {FAKE_PASSWORD}")

        rc, out, err = self.run_main(["--env", self.env, "--config", self.cfg, "--dry-run"], Boom())
        self.assertEqual(rc, 1)
        self.assertNotIn(FAKE_PASSWORD, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertIn("****", err)

    def test_unexpected_exception_has_no_traceback_nor_secret(self):
        class Boom(FakeClient):
            def find_role(self, name):
                raise KeyError(FAKE_PASSWORD)

        rc, out, err = self.run_main(["--env", self.env, "--config", self.cfg, "--dry-run"], Boom())
        self.assertEqual(rc, 1)
        self.assertNotIn(FAKE_PASSWORD, out + err)
        self.assertNotIn("Traceback", out + err)

    def test_client_repr_hides_credentials(self):
        client = bd.BiacClient({"SB_HOST": "h", "SB_PORT": "443", "SB_USER": "u", "SB_PASSWORD": FAKE_PASSWORD})
        self.assertNotIn(FAKE_PASSWORD, repr(client))
        self.assertNotIn(client.auth, repr(client))

    def test_validate_mode_is_offline(self):
        with mock.patch.object(bd, "BiacClient", side_effect=AssertionError("network client built")), \
                mock.patch.object(bd, "load_env", side_effect=AssertionError("env read")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bd.main(["--config", self.cfg, "--validate"]), 0)


EXPR_YAML = """\
roles:
  - name: zz_test_reader
column_masks:
  - name: zz_mask
    expression: "'****'"
    role: zz_test_reader
    entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation, columns: [comment]}
row_filters:
  - name: zz_filter
    expression: "regionkey IN (SELECT perimetre FROM postgres.security.user_perimeter WHERE upn=current_user)"
    role: zz_test_reader
    entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}
"""


class DriftTests(WorkDir):
    def setUp(self):
        super().setUp()
        self.cfg = self.write("t.biac.yaml", EXPR_YAML)
        self.env = self.env_file()
        self.plan_path = self.path("plan.json")

    def dry(self, client):
        return self.run_main(["--env", self.env, "--config", self.cfg, "--dry-run",
                              "--plan-out", self.plan_path], client)

    def apply_signed(self, client):
        return self.run_main(["--env", self.env, "--config", self.cfg, "--apply",
                              "--plan", self.plan_path], client)

    def seeded(self, rf_text=None, mask_text=None):
        c = FakeClient()
        self.dry(c)
        self.apply_signed(c)  # create everything with the YAML text
        if rf_text is not None:
            c.rf_text["zz_filter"] = rf_text
        if mask_text is not None:
            c.mask_text["zz_mask"] = mask_text
        c.writes = 0
        return c

    def actions(self, kind):
        return [(r["label"], r["action"]) for r in read_json(self.plan_path)["plan"] if r["kind"] == kind]

    def test_identical_text_is_skip(self):
        c = self.seeded()
        self.dry(c)
        self.assertEqual({a for _, a in self.actions("row_filter_expression")}, {"SKIP (exists)"})
        self.assertEqual({a for _, a in self.actions("column_mask_expression")}, {"SKIP (exists)"})

    def test_whitespace_only_difference_is_skip(self):
        c = self.seeded(rf_text="regionkey   IN (SELECT perimetre FROM postgres.security.user_perimeter\n"
                                "  WHERE upn=current_user) ")
        self.dry(c)
        self.assertEqual({a for _, a in self.actions("row_filter_expression")}, {"SKIP (exists)"})

    def test_row_filter_text_difference_is_drift_with_both_texts(self):
        c = self.seeded(rf_text="regionkey IN (SELECT perimetre FROM iceberg.ref.user_perimeter_v2 WHERE upn=current_user)")
        rc, out, err = self.dry(c)
        self.assertEqual(rc, 0)
        (label, action), = self.actions("row_filter_expression")
        self.assertEqual(action, bd.DRIFT_ACTION)
        self.assertIn("zz_filter", label)
        self.assertIn("iceberg.ref.user_perimeter_v2", label)
        self.assertIn("postgres.security.user_perimeter", label)
        self.assertIn("DRIFT", err)  # warning on stderr, plan still written
        self.assertEqual(c.writes, 0)

    def test_column_mask_text_difference_is_drift(self):
        c = self.seeded(mask_text="'XXXX'")
        self.dry(c)
        (label, action), = self.actions("column_mask_expression")
        self.assertEqual(action, bd.DRIFT_ACTION)
        self.assertIn("'XXXX'", label)
        self.assertIn("'****'", label)

    def test_apply_refuses_on_row_filter_drift_even_with_matching_signed_plan(self):
        c = self.seeded(rf_text="other_col IN (1)")
        self.dry(c)  # signed plan that contains the DRIFT
        rc, _, err = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_DRIFT)
        self.assertNotEqual(rc, 0)
        self.assertIn("DRIFT", err)
        self.assertEqual(c.writes, 0)

    def test_apply_refuses_on_column_mask_drift(self):
        c = self.seeded(mask_text="'XXXX'")
        self.dry(c)
        rc, _, _ = self.apply_signed(c)
        self.assertEqual(rc, bd.EXIT_DRIFT)
        self.assertEqual(c.writes, 0)

    def test_manual_apply_refuses_on_drift_without_prompt(self):
        c = self.seeded(rf_text="other_col IN (1)")
        rc, _, _ = self.run_main(["--env", self.env, "--config", self.cfg, "--apply"], c)
        self.assertEqual(rc, bd.EXIT_DRIFT)
        self.assertEqual(c.writes, 0)

    def test_apply_function_itself_refuses_drift(self):
        c = self.seeded(rf_text="other_col IN (1)")
        with self.assertRaises(RuntimeError):
            bd.apply(c, validate(EXPR_YAML))
        self.assertEqual(c.writes, 0)

    def test_new_expression_is_still_create(self):
        c = FakeClient()
        self.dry(c)
        self.assertEqual({a for _, a in self.actions("row_filter_expression")}, {"CREATE"})
        self.assertEqual({a for _, a in self.actions("column_mask_expression")}, {"CREATE"})


class GuardrailTests(unittest.TestCase):
    def test_good_yaml_passes(self):
        validate(GOOD_YAML)

    def test_declaring_forbidden_roles_is_refused(self):
        for role in ("sysadmin", "public"):
            self.assertIn("forbidden", validation_errors(f"roles:\n  - name: {role}\n"), role)

    def test_grant_to_forbidden_roles_is_refused(self):
        for role in ("sysadmin", "public"):
            text = (f"roles:\n  - name: {role}\ngrants:\n"
                    f"  - {{role: {role}, effect: ALLOW, action: SELECT, "
                    f"entity: {{category: TABLES, catalog: tpch, schema: tiny, table: nation}}}}\n")
            errors = validation_errors(text)
            self.assertIn(f"grant on role '{role}': role '{role}' is forbidden", errors)

    def test_grant_to_forbidden_role_refused_even_if_undeclared(self):
        errors = validation_errors(
            "grants:\n  - {role: sysadmin, effect: ALLOW, action: SELECT, "
            "entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}}\n")
        self.assertIn("forbidden", errors)

    def test_assignment_mask_filter_location_on_forbidden_roles_refused(self):
        base = "roles:\n  - name: zz_ok\nallowed_users: [demo]\n"
        ent = "{category: TABLES, catalog: tpch, schema: tiny, table: nation}"
        cases = {
            "assignment": "assignments:\n  - {role: public, users: [demo]}\n",
            "column_mask": ("column_masks:\n  - name: m1\n    expression: \"'x'\"\n    role: sysadmin\n"
                            "    entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation, columns: [name]}\n"),
            "row_filter": f"row_filters:\n  - name: f1\n    expression: \"true\"\n    role: public\n    entity: {ent}\n",
            "location_grant": "location_grants:\n  - {role: sysadmin, location: 's3://bucket/prefix/*'}\n",
        }
        for kind, extra in cases.items():
            self.assertIn("forbidden", validation_errors(base + extra), kind)

    def test_forbidden_role_check_is_case_insensitive(self):
        errors = validation_errors("grants:\n  - {role: SysAdmin, effect: ALLOW, action: SELECT, "
                                   "entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}}\n")
        self.assertIn("forbidden", errors)

    CATALOG_WIDE = ("roles:\n  - name: zz_ok\ngrants:\n"
                    "  - {role: zz_ok, effect: %s, action: SELECT, entity: {category: TABLES, catalog: tpch}}\n")

    def test_catalog_wide_allow_without_key_is_refused(self):
        for effect in ("ALLOW", "ALLOW_WITH_GRANT_OPTION"):
            errors = validation_errors(self.CATALOG_WIDE % effect)
            self.assertIn("allow_catalog_wide", errors, effect)
            self.assertIn("whole catalog", errors, effect)

    def test_catalog_wide_function_allow_without_key_is_refused(self):
        errors = validation_errors("roles:\n  - name: zz_ok\ngrants:\n"
                                   "  - {role: zz_ok, effect: ALLOW, action: EXECUTE, entity: {category: FUNCTIONS, catalog: tpch}}\n")
        self.assertIn("allow_catalog_wide", errors)

    def test_catalog_wide_allowed_with_explicit_key(self):
        validate(self.CATALOG_WIDE % "ALLOW" + "allow_catalog_wide: [tpch]\n")
        validate(self.CATALOG_WIDE % "ALLOW" + "allow_catalog_wide: [TPCH]\n")  # case-insensitive, like the API

    def test_catalog_wide_key_is_per_catalog(self):
        errors = validation_errors(self.CATALOG_WIDE % "ALLOW" + "allow_catalog_wide: [other]\n")
        self.assertIn("allow_catalog_wide", errors)

    def test_catalog_wide_deny_and_schema_scoped_allow_are_not_blocked(self):
        validate(self.CATALOG_WIDE % "DENY")
        validate("roles:\n  - name: zz_ok\ngrants:\n"
                 "  - {role: zz_ok, effect: ALLOW, action: SELECT, entity: {category: TABLES, catalog: tpch, schema: tiny}}\n")

    def test_malformed_allow_catalog_wide_is_refused(self):
        self.assertIn("allow_catalog_wide", validation_errors(self.CATALOG_WIDE % "ALLOW" + "allow_catalog_wide: tpch\n"))

    def test_undeclared_user_is_refused(self):
        errors = validation_errors("roles:\n  - name: zz_ok\nallowed_users: [demo]\n"
                                   "assignments:\n  - {role: zz_ok, users: [demo, intruder]}\n")
        self.assertIn("user 'intruder' is not declared", errors)
        self.assertNotIn("'demo' is not declared", errors)

    def test_user_refused_when_allowed_users_missing(self):
        errors = validation_errors("roles:\n  - name: zz_ok\nassignments:\n  - {role: zz_ok, users: [demo]}\n")
        self.assertIn("allowed_users", errors)

    def test_undeclared_group_is_refused(self):
        errors = validation_errors("roles:\n  - name: zz_ok\nallowed_users: [demo]\n"
                                   "assignments:\n  - {role: zz_ok, groups: [some_group]}\n")
        self.assertIn("group 'some_group' is not declared", errors)
        self.assertIn("allowed_groups", errors)

    def test_declared_group_is_accepted_and_users_are_not_groups(self):
        validate("roles:\n  - name: zz_ok\nallowed_groups: [g1]\nassignments:\n  - {role: zz_ok, groups: [g1]}\n")
        errors = validation_errors("roles:\n  - name: zz_ok\nallowed_users: [g1]\n"
                                   "assignments:\n  - {role: zz_ok, groups: [g1]}\n")
        self.assertIn("group 'g1' is not declared", errors)

    def test_malformed_allowed_lists_are_refused(self):
        self.assertIn("allowed_users", validation_errors("allowed_users: demo\n"))
        self.assertIn("allowed_groups", validation_errors("allowed_groups: [1, 2]\n"))

    def test_unknown_root_key_still_refused(self):
        self.assertIn("unknown top-level", validation_errors("allowed_user: [demo]\n"))


class ExpressionNameLengthTests(unittest.TestCase):
    ENT = "{category: TABLES, catalog: tpch, schema: tiny, table: nation}"

    def _mask(self, name):
        return ("roles:\n  - name: zz_ok\ncolumn_masks:\n"
                f"  - name: {name}\n    expression: \"'x'\"\n    role: zz_ok\n"
                "    entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation, columns: [name]}\n")

    def _filter(self, name):
        return ("roles:\n  - name: zz_ok\nrow_filters:\n"
                f"  - name: {name}\n    expression: \"true\"\n    role: zz_ok\n    entity: {self.ENT}\n")

    def test_names_of_exactly_30_chars_are_accepted(self):
        name = "n" * 30
        validate(self._mask(name))
        validate(self._filter(name))

    def test_column_mask_name_over_30_chars_is_refused(self):
        name = "m" * 31
        errors = validation_errors(self._mask(name))
        self.assertIn(f"column_mask '{name}'", errors)
        self.assertIn("31 chars", errors)
        self.assertIn("30-char", errors)

    def test_row_filter_name_over_30_chars_is_refused(self):
        name = "sales_orders_by_region_rowfilter"  # 32 chars
        errors = validation_errors(self._filter(name))
        self.assertIn(f"row_filter '{name}'", errors)
        self.assertIn(f"{len(name)} chars", errors)


class ExampleFilesTests(unittest.TestCase):
    """Every documented example must pass the validator and guardrails."""

    EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")

    def test_examples_validate(self):
        files = sorted(f for f in os.listdir(self.EXAMPLES) if f.endswith(".biac.yaml"))
        self.assertGreaterEqual(len(files), 6)
        for f in files:
            with self.subTest(example=f), contextlib.redirect_stderr(io.StringIO()):
                bd.validate_config(bd.load_config(os.path.join(self.EXAMPLES, f)))


if __name__ == "__main__":
    unittest.main()
