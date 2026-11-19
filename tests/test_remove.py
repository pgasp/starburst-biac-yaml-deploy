"""Offline tests of the `remove:` section (declarative "ensure absent"). Same simulated client as the main tests.

Run:  python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import unittest
from unittest import mock

try:
    import test_biac_deploy as base  # run with `-s tests`
except ImportError:
    from . import test_biac_deploy as base  # run as a package

bd = base.bd
FakeClient, WorkDir = base.FakeClient, base.WorkDir

TABLE = "{category: TABLES, catalog: tpch, schema: tiny, table: customer%s}"


def entity(columns=None):
    return TABLE % (f", columns: [{', '.join(columns)}]" if columns else "")


def entity_dict(columns=None):
    e = {"category": "TABLES", "catalog": "tpch", "schema": "tiny", "table": "customer"}
    if columns:
        e["columns"] = columns
    return e


def seed_grant(client, role, effect="ALLOW", action="SELECT", columns=None):
    client.grants.add((client.roles[role], effect, action, json.dumps(entity_dict(columns), sort_keys=True)))


def actions_by_kind(actions):
    return {(k, a) for k, _, a in actions}


class PlanTests(WorkDir):
    YAML = f"""\
remove:
  grants:
    - {{role: old_role, effect: ALLOW, action: SELECT, entity: {entity()}}}
    - {{role: old_role, effect: ALLOW, action: INSERT, entity: {entity()}}}
  location_grants:
    - {{role: old_role, location: "s3://b/p/*"}}
  assignments:
    - {{role: old_role, users: [demo]}}
allowed_users: [demo]
"""

    def client(self):
        c = FakeClient()
        c.create_role("old_role")
        seed_grant(c, "old_role")
        c.loc.add((c.roles["old_role"], "s3://b/p/*", False))
        c.assign.add(("u", "demo", c.roles["old_role"]))
        return c

    def test_delete_when_present_skip_when_absent(self):
        actions = bd.plan(self.client(), base.validate(self.YAML))
        by_label = {(k, a) for k, _, a in actions}
        self.assertEqual(by_label, {("remove_assignment", "DELETE"), ("remove_grant", "DELETE"),
                                    ("remove_grant", "SKIP (absent)"), ("remove_location_grant", "DELETE")})
        self.assertTrue(all(label.startswith("REMOVE ") for _, label, _ in actions))
        insert = next(a for k, label, a in actions if "INSERT" in label)
        self.assertEqual(insert, "SKIP (absent)")

    def test_role_absent_everything_is_skip(self):
        actions = bd.plan(FakeClient(), base.validate(self.YAML))
        self.assertEqual({a for _, _, a in actions}, {"SKIP (absent)"})

    def test_plan_is_read_only_and_stage_ordered(self):
        c = self.client()
        actions = bd.plan(c, base.validate(self.YAML))
        writes_before = c.writes
        bd.plan(c, base.validate(self.YAML))
        self.assertEqual(c.writes, writes_before)
        kinds = [k for k, _, _ in actions]
        self.assertEqual(kinds, ["remove_assignment", "remove_grant", "remove_grant", "remove_location_grant"])

    def test_no_remove_section_means_no_extra_call_and_no_removal_action(self):
        calls = []

        class Spy(FakeClient):
            def list_roles(self):
                calls.append("list_roles")
                return super().list_roles()

        actions = bd.plan(Spy(), base.validate(base.GOOD_YAML))
        self.assertEqual(calls, [])
        self.assertFalse([a for a in actions if a[0].startswith("remove_")])

    def test_masks_and_filters_detach_and_orphan_expression(self):
        c = FakeClient()
        c.create_role("old_role")
        rid = c.roles["old_role"]
        c.create_column_mask_expression("old_mask", "'x'", "")
        c.create_row_filter_expression("old_filter", "true", "")
        c.attach_column_mask(rid, entity_dict(["phone"]), c.mask_expr["old_mask"])
        c.attach_row_filter(rid, entity_dict(), c.rf_expr["old_filter"])
        text = f"""\
remove:
  column_masks:
    - {{name: old_mask, role: old_role, delete_expression: true, entity: {entity(['phone'])}}}
  row_filters:
    - {{name: old_filter, role: old_role, entity: {entity()}}}
"""
        actions = bd.plan(c, base.validate(text))
        self.assertEqual([(k, a) for k, _, a in actions],
                         [("remove_column_mask_attach", "DELETE"), ("remove_row_filter_attach", "DELETE"),
                          ("remove_column_mask_expression", "DELETE")])
        # delete_expression defaults to false: the filter expression is kept
        self.assertFalse([a for a in actions if a[0] == "remove_row_filter_expression"])

    def test_orphan_expression_already_gone_is_skip(self):
        c = FakeClient()
        c.create_role("old_role")
        text = f"remove:\n  row_filters:\n    - {{name: gone, role: old_role, delete_expression: true, entity: {entity()}}}\n"
        self.assertEqual([(k, a) for k, _, a in bd.plan(c, base.validate(text))],
                         [("remove_row_filter_attach", "SKIP (absent)"), ("remove_row_filter_expression", "SKIP (absent)")])


class ColumnListChangeTests(WorkDir):
    """Replace a column-level grant: the new one is created first, the old one deleted after (no gap)."""
    YAML = f"""\
roles:
  - name: reader
grants:
  - {{role: reader, effect: ALLOW, action: SELECT, entity: {entity(['custkey', 'name', 'phone'])}}}
remove:
  grants:
    - {{role: reader, effect: ALLOW, action: SELECT, entity: {entity(['custkey', 'name'])}}}
"""

    def setUp(self):
        super().setUp()
        self.client = FakeClient()
        self.client.create_role("reader")
        seed_grant(self.client, "reader", columns=["custkey", "name"])
        self.config = base.validate(self.YAML)

    def test_plan_creates_then_deletes(self):
        actions = bd.plan(self.client, self.config)
        self.assertEqual([(k, a) for k, _, a in actions],
                         [("role", "SKIP (exists)"), ("grant", "CREATE"), ("remove_grant", "DELETE")])

    def test_apply_creates_first_and_leaves_only_the_new_grant(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.apply(self.client, self.config)
        text = out.getvalue()
        self.assertLess(text.index("[grant]"), text.index("[remove_grant]"))
        columns = [json.loads(k[3]).get("columns") for k in self.client.grants]
        self.assertEqual(columns, [["custkey", "name", "phone"]])

    def test_second_run_is_a_noop(self):
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(self.client, self.config)
        actions = bd.plan(self.client, self.config)
        self.assertEqual({a for _, _, a in actions}, {"SKIP (exists)", "SKIP (absent)"})

    def test_column_order_does_not_matter_for_the_match(self):
        config = base.validate(self.YAML.replace("[custkey, name]", "[name, CustKey]"))
        self.assertEqual(bd.plan(self.client, config)[-1][2], "DELETE")


class DeleteExpressionTests(WorkDir):
    def setUp(self):
        super().setUp()
        self.client = FakeClient()
        for r in ("role_a", "role_b"):
            self.client.create_role(r)
        self.client.create_row_filter_expression("shared_filter", "true", "")
        self.expr = self.client.rf_expr["shared_filter"]
        for r in ("role_a", "role_b"):
            self.client.attach_row_filter(self.client.roles[r], entity_dict(), self.expr)
        self.client.writes = 0

    def yaml(self, roles):
        entries = "".join(f"    - {{name: shared_filter, role: {r}, delete_expression: true, entity: {entity()}}}\n"
                          for r in roles)
        return f"remove:\n  row_filters:\n{entries}"

    def test_refused_when_still_attached_elsewhere(self):
        with self.assertRaises(ValueError) as ctx:
            bd.plan(self.client, base.validate(self.yaml(["role_a"])))
        self.assertIn("role_b", str(ctx.exception))
        self.assertIn("shared_filter", str(ctx.exception))

    def test_refused_is_exit_2_and_nothing_written_even_with_apply(self):
        path = self.write("f.biac.yaml", self.yaml(["role_a"]))
        for mode in (["--dry-run"], ["--apply"]):
            rc, _, err = self.run_main(["--env", self.env_file(), "--config", path] + mode, self.client)
            self.assertEqual(rc, 2, mode)
            self.assertIn("Removal refused", err)
        self.assertEqual(self.client.writes, 0)
        self.assertIn("shared_filter", self.client.rf_expr)

    def test_accepted_when_every_attachment_is_detached(self):
        actions = bd.plan(self.client, base.validate(self.yaml(["role_a", "role_b"])))
        self.assertEqual([(k, a) for k, _, a in actions],
                         [("remove_row_filter_attach", "DELETE")] * 2 + [("remove_row_filter_expression", "DELETE")])
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(self.client, base.validate(self.yaml(["role_a", "role_b"])))
        self.assertEqual(self.client.rf_expr, {})
        self.assertEqual(self.client.rf_att, set())
        self.assertEqual(self.client.deletes[-1], "filter-expression shared_filter")

    def test_accepted_when_the_other_holder_role_is_deleted_too(self):
        text = self.yaml(["role_a"]) + "  roles: [role_b]\n"
        actions = bd.plan(self.client, base.validate(text))
        self.assertIn(("remove_row_filter_expression", "DELETE"), [(k, a) for k, _, a in actions])
        self.assertEqual(actions[-1][:3:2], ("remove_role", "DELETE"))

    def test_refused_when_a_creation_section_still_uses_the_expression(self):
        text = (self.yaml(["role_a"]) + "roles:\n  - name: role_c\nrow_filters:\n"
                f"  - {{name: shared_filter, expression: 'true', role: role_c, entity: {entity()}}}\n")
        self.assertIn("delete_expression is refused", base.validation_errors(text))


class RoleCascadeTests(WorkDir):
    def setUp(self):
        super().setUp()
        c = self.client = FakeClient()
        c.create_role("legacy")
        c.create_role("keeper")
        rid = c.roles["legacy"]
        seed_grant(c, "legacy")
        seed_grant(c, "keeper")
        c.loc.add((rid, "s3://b/p/*", False))
        c.create_column_mask_expression("m", "'x'", "")
        c.create_row_filter_expression("f", "true", "")
        c.attach_column_mask(rid, entity_dict(["phone"]), c.mask_expr["m"])
        c.attach_row_filter(rid, entity_dict(), c.rf_expr["f"])
        c.assign.add(("u", "demo", rid))
        c.assign.add(("g", "grp", rid))
        c.writes = 0
        self.config = base.validate("remove:\n  roles: [legacy, never_existed]\n")

    def test_plan_lists_every_attached_item_then_the_role(self):
        actions = bd.plan(self.client, self.config)
        self.assertEqual([k for k, _, _ in actions],
                         ["remove_assignment", "remove_assignment", "remove_column_mask_attach",
                          "remove_row_filter_attach", "remove_grant", "remove_location_grant",
                          "remove_role", "remove_role"])
        self.assertEqual(actions[-2][1:], ("REMOVE role legacy", "DELETE"))
        self.assertEqual(actions[-1][1:], ("REMOVE role never_existed", "SKIP (absent)"))
        self.assertEqual({a[1] for a in actions[:2]},
                         {"REMOVE user demo -> legacy", "REMOVE group grp -> legacy"})

    def test_apply_deletes_everything_of_that_role_and_nothing_else(self):
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(self.client, self.config)
        self.assertNotIn("legacy", self.client.roles)
        self.assertIn("keeper", self.client.roles)
        self.assertEqual(len(self.client.grants), 1)  # keeper's own grant
        self.assertEqual((self.client.loc, self.client.assign, self.client.mask_att, self.client.rf_att),
                         (set(), set(), set(), set()))
        self.assertEqual(self.client.deletes[-1], "role 1")
        self.assertEqual(len(self.client.deletes), 7)

    def test_explicit_entry_and_cascade_do_not_delete_twice(self):
        text = (f"remove:\n  roles: [legacy]\n  grants:\n"
                f"    - {{role: legacy, effect: ALLOW, action: SELECT, entity: {entity()}}}\n")
        actions = bd.plan(self.client, base.validate(text))
        self.assertEqual([k for k, _, _ in actions].count("remove_grant"), 1)
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(self.client, base.validate(text))
        self.assertNotIn("legacy", self.client.roles)

    def test_unrecognised_assignment_subject_stops_the_plan(self):
        self.client.list_role_assignments = lambda rid: [{"id": 1, "subject": {"type": "USER"}}]
        with self.assertRaises(RuntimeError):
            bd.plan(self.client, self.config)


class GuardrailTests(unittest.TestCase):
    def errors(self, remove_yaml, extra=""):
        return base.validation_errors(extra + "remove:\n" + remove_yaml)

    def test_valid_remove_passes_and_pasted_creation_entry_is_accepted(self):
        self.assertEqual(self.errors(
            f"  column_masks:\n    - name: m\n      description: pasted\n      expression: \"'x'\"\n"
            f"      role: not_declared_legacy\n      entity: {entity(['phone'])}\n"), "")

    def test_never_sysadmin_or_public(self):
        for role in ("sysadmin", "public", "SysAdmin"):
            for body in (f"  roles: [{role}]\n",
                         f"  grants:\n    - {{role: {role}, effect: ALLOW, action: SELECT, entity: {entity()}}}\n",
                         f"  location_grants:\n    - {{role: {role}, location: \"s3://b/p/*\"}}\n",
                         f"  row_filters:\n    - {{name: f, role: {role}, entity: {entity()}}}\n"):
                with self.subTest(role=role, body=body):
                    self.assertIn("forbidden", self.errors(body))
        self.assertIn("forbidden", self.errors(f"  assignments:\n    - {{role: sysadmin, users: [u]}}\n",
                                               "allowed_users: [u]\n"))

    def test_role_name_format(self):
        self.assertIn("invalid role name", self.errors("  roles: [Bad-Role]\n"))
        self.assertIn("invalid role name", self.errors(
            f"  grants:\n    - {{role: 'a b', effect: ALLOW, action: SELECT, entity: {entity()}}}\n"))

    def test_unknown_keys_are_refused_at_every_level(self):
        self.assertIn("unknown key(s) ['prune']", self.errors("  grants: []\n  prune: true\n"))
        self.assertIn("unknown key(s) ['oops']", self.errors(
            f"  grants:\n    - {{role: r, effect: ALLOW, action: SELECT, entity: {entity()}, oops: 1}}\n"))
        self.assertIn("unknown key(s) ['oops']", self.errors(
            f"  row_filters:\n    - {{name: f, role: r, entity: {entity()}, oops: 1}}\n"))
        self.assertIn("unknown key(s) ['oops']", self.errors("  assignments:\n    - {role: r, oops: 1}\n"))

    def test_comma_in_flow_action_is_caught_like_in_grants(self):
        self.assertIn("unknown key(s)", self.errors(
            f"  grants:\n    - {{role: r, effect: ALLOW, action: SELECT,INSERT, entity: {entity()}}}\n"))

    def test_conflict_with_a_creation_section(self):
        grant = f"{{role: r, effect: ALLOW, action: SELECT, entity: {entity()}}}"
        self.assertIn("created and removed", self.errors(
            f"  grants:\n    - {grant}\n", f"roles:\n  - name: r\ngrants:\n  - {grant}\n"))
        # a different column list is another object: no conflict (this is the column-list change case)
        other = f"{{role: r, effect: ALLOW, action: SELECT, entity: {entity(['a'])}}}"
        self.assertEqual(self.errors(f"  grants:\n    - {other}\n", f"roles:\n  - name: r\ngrants:\n  - {grant}\n"), "")
        # same grant, but another effect: another object too
        deny = f"{{role: r, effect: DENY, action: SELECT, entity: {entity()}}}"
        self.assertEqual(self.errors(f"  grants:\n    - {deny}\n", f"roles:\n  - name: r\ngrants:\n  - {grant}\n"), "")
        # overlap on one action of a list
        multi = f"{{role: r, effect: ALLOW, action: [SELECT, INSERT], entity: {entity()}}}"
        self.assertIn("created and removed", self.errors(
            f"  grants:\n    - {multi}\n", f"roles:\n  - name: r\ngrants:\n  - {grant}\n"))

    def test_conflict_for_location_mask_filter_assignment(self):
        pre = "roles:\n  - name: r\nallowed_users: [u]\n"
        loc = '{role: r, location: "s3://b/p/*"}'
        self.assertIn("created and removed", self.errors(f"  location_grants:\n    - {loc}\n",
                                                         pre + f"location_grants:\n  - {loc}\n"))
        row = f"{{name: f, role: r, entity: {entity()}}}"
        created_row = f"{{name: f, expression: 'true', role: r, entity: {entity()}}}"
        self.assertIn("created and removed", self.errors(f"  row_filters:\n    - {row}\n",
                                                         pre + f"row_filters:\n  - {created_row}\n"))
        mask = f"{{name: m, role: r, entity: {entity(['c'])}}}"
        created_mask = f"{{name: m, expression: 'x', role: r, entity: {entity(['c'])}}}"
        self.assertIn("created and removed", self.errors(f"  column_masks:\n    - {mask}\n",
                                                         pre + f"column_masks:\n  - {created_mask}\n"))
        asg = "{role: r, users: [u]}"
        self.assertIn("created and removed", self.errors(f"  assignments:\n    - {asg}\n",
                                                         pre + f"assignments:\n  - {asg}\n"))

    def test_remove_roles_conflicts(self):
        self.assertIn("also declared in 'roles'", self.errors("  roles: [r]\n", "roles:\n  - name: r\n"))
        self.assertIn("still referenced by 'grants'", self.errors(
            "  roles: [r]\n", f"grants:\n  - {{role: r, effect: ALLOW, action: SELECT, entity: {entity()}}}\n"))

    def test_undeclared_user_or_group_is_refused(self):
        self.assertIn("not declared in the root 'allowed_users'", self.errors("  assignments:\n    - {role: r, users: [u]}\n"))
        self.assertIn("not declared in the root 'allowed_groups'", self.errors("  assignments:\n    - {role: r, groups: [g]}\n"))
        self.assertEqual(self.errors("  assignments:\n    - {role: r, users: [u], groups: [g]}\n",
                                     "allowed_users: [u]\nallowed_groups: [g]\n"), "")

    def test_entity_rules_are_the_creation_ones(self):
        self.assertIn("'*' is not a valid wildcard", self.errors(
            "  grants:\n    - {role: r, effect: ALLOW, action: SELECT, entity: {category: TABLES, catalog: c, table: '*', schema: s}}\n"))
        self.assertIn("allEntities:true is forbidden", self.errors(
            "  grants:\n    - {role: r, effect: ALLOW, action: SELECT, entity: {category: TABLES, allEntities: true}}\n"))
        self.assertIn("must specify a 'table'", self.errors(
            "  row_filters:\n    - {name: f, role: r, entity: {category: TABLES, catalog: c, schema: s}}\n"))
        self.assertIn("must list 'columns'", self.errors(
            f"  column_masks:\n    - {{name: m, role: r, entity: {entity()}}}\n"))

    def test_shapes_are_checked(self):
        self.assertIn("'remove' must be a mapping", base.validation_errors("remove: [grants]\n"))
        self.assertIn("remove.grants must be a list", self.errors("  grants: nope\n"))
        self.assertIn("'delete_expression' must be true/false", self.errors(
            f"  row_filters:\n    - {{name: f, role: r, delete_expression: 'yes', entity: {entity()}}}\n"))

    def test_empty_remove_is_fine(self):
        self.assertEqual(base.validation_errors("remove:\n"), "")
        self.assertEqual(base.validation_errors("remove: {}\n"), "")


class ApplyTests(WorkDir):
    YAML = f"""\
remove:
  grants:
    - {{role: legacy, effect: ALLOW, action: [SELECT, INSERT, DELETE], entity: {entity()}}}
"""

    def client(self):
        c = FakeClient()
        c.create_role("legacy")
        for a in ("SELECT", "INSERT", "DELETE"):
            seed_grant(c, "legacy", action=a)
        c.writes = 0
        return c

    def test_interactive_prompt_shows_the_deletion_count(self):
        path = self.write("f.biac.yaml", self.YAML)
        out = io.StringIO()
        c = self.client()
        with mock.patch.object(bd, "BiacClient", lambda env: c), mock.patch("builtins.input", return_value="no"), \
                contextlib.redirect_stdout(out):
            rc = bd.main(["--env", self.env_file(), "--config", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("3 object(s) will be DELETED", out.getvalue())
        self.assertEqual(c.writes, 0)

    def test_dry_run_only_removals_is_not_nothing_to_do(self):
        path = self.write("f.biac.yaml", self.YAML)
        rc, out, _ = self.run_main(["--env", self.env_file(), "--config", path, "--dry-run"], self.client())
        self.assertEqual(rc, 0)
        self.assertEqual(out.count(": DELETE"), 3)

    def test_apply_stops_on_the_first_failed_deletion(self):
        c = self.client()
        c.fail_after = 1
        path = self.write("f.biac.yaml", self.YAML)
        with mock.patch.object(bd, "BiacClient", lambda env: c), mock.patch("builtins.input", return_value="yes"):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = bd.main(["--env", self.env_file(), "--config", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertEqual(len(c.deletes), 1)       # the second DELETE failed, the third was never tried
        self.assertEqual(len(c.grants), 2)
        self.assertEqual(out.getvalue().count(": deleted"), 1)
        self.assertIn("stopped at", err.getvalue())
        self.assertIn("after 1 deletion(s)", err.getvalue())

    def test_second_apply_is_a_noop(self):
        c = self.client()
        path = self.write("f.biac.yaml", self.YAML)
        for _ in range(2):
            with mock.patch.object(bd, "BiacClient", lambda env: c), mock.patch("builtins.input", return_value="yes"), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(bd.main(["--env", self.env_file(), "--config", path, "--apply"]), 0)
        self.assertIn("Nothing to do", out.getvalue())
        self.assertEqual(c.grants, set())

    def test_order_assignments_detaches_grants_locations_expressions_roles(self):
        c = FakeClient()
        c.create_role("legacy")
        rid = c.roles["legacy"]
        seed_grant(c, "legacy")
        c.loc.add((rid, "s3://b/p/*", False))
        c.assign.add(("u", "demo", rid))
        c.create_column_mask_expression("m", "'x'", "")
        c.create_row_filter_expression("f", "true", "")
        c.attach_column_mask(rid, entity_dict(["phone"]), c.mask_expr["m"])
        c.attach_row_filter(rid, entity_dict(), c.rf_expr["f"])
        text = f"""\
allowed_users: [demo]
remove:
  roles: [legacy]
  row_filters:
    - {{name: f, role: legacy, delete_expression: true, entity: {entity()}}}
  column_masks:
    - {{name: m, role: legacy, delete_expression: true, entity: {entity(['phone'])}}}
  location_grants:
    - {{role: legacy, location: "s3://b/p/*"}}
  grants:
    - {{role: legacy, effect: ALLOW, action: SELECT, entity: {entity()}}}
  assignments:
    - {{role: legacy, users: [demo]}}
"""
        actions = bd.plan(c, base.validate(text))
        self.assertEqual([k for k, _, _ in actions],
                         ["remove_assignment", "remove_column_mask_attach", "remove_row_filter_attach",
                          "remove_grant", "remove_location_grant", "remove_column_mask_expression",
                          "remove_row_filter_expression", "remove_role"])
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(c, base.validate(text))
        self.assertEqual(c.deletes, ["assignment user demo", "mask-attach 100", "filter-attach 200", f"grant SELECT {json.dumps(entity_dict(), sort_keys=True)}",
                                     "location s3://b/p/*", "mask-expression m", "filter-expression f", "role 1"])


class SignedPlanTests(WorkDir):
    YAML = f"remove:\n  grants:\n    - {{role: legacy, effect: ALLOW, action: SELECT, entity: {entity()}}}\n"

    def client(self):
        c = FakeClient()
        c.create_role("legacy")
        seed_grant(c, "legacy")
        seed_grant(c, "legacy", action="INSERT")
        c.writes = 0
        return c

    def dry_run(self, c, yaml_text):
        path = self.write("f.biac.yaml", yaml_text)
        plan = self.path("plan.json")
        rc, out, _ = self.run_main(["--env", self.env_file(), "--config", path, "--dry-run", "--plan-out", plan], c)
        self.assertEqual(rc, 0)
        return path, plan

    def apply(self, c, path, plan):
        return self.run_main(["--env", self.env_file(), "--config", path, "--apply", "--plan", plan], c)

    def test_deletions_are_part_of_the_signed_plan_and_apply_without_prompt(self):
        c = self.client()
        path, plan = self.dry_run(c, self.YAML)
        records = base.read_json(plan)["plan"]
        self.assertEqual([(r["kind"], r["action"]) for r in records], [("remove_grant", "DELETE")])
        rc, out, _ = self.apply(c, path, plan)
        self.assertEqual(rc, 0)
        self.assertIn("1 object(s) will be DELETED", out)
        self.assertEqual(len(c.grants), 1)

    def test_an_added_remove_entry_is_refused_and_nothing_is_deleted(self):
        c = self.client()
        _, plan = self.dry_run(c, self.YAML)
        extra = self.YAML + f"    - {{role: legacy, effect: ALLOW, action: INSERT, entity: {entity()}}}\n"
        path = self.write("f.biac.yaml", extra)
        rc, _, err = self.apply(c, path, plan)
        self.assertEqual(rc, 3)
        self.assertIn("YAML file changed", err)
        self.assertIn("recomputed plan differs", err)
        self.assertEqual(len(c.grants), 2)
        self.assertEqual(c.deletes, [])

    def test_a_forged_plan_without_the_added_entry_is_refused_on_the_plan_diff(self):
        c = self.client()
        _, plan = self.dry_run(c, self.YAML)
        extra = self.YAML + f"    - {{role: legacy, effect: ALLOW, action: INSERT, entity: {entity()}}}\n"
        path = self.write("f.biac.yaml", extra)
        signed = base.read_json(plan)
        signed["config_sha256"] = bd.sha256_hex(extra.encode())   # forge the YAML hash, keep the old records
        signed["fingerprint"] = bd.plan_fingerprint(signed["plan"], signed["config_sha256"], signed["cluster"])
        base.write_json(plan, signed)
        rc, _, err = self.apply(c, path, plan)
        self.assertEqual(rc, 3)
        self.assertIn("only in the recomputed plan: [remove_grant] REMOVE legacy -> ALLOW INSERT", err)
        self.assertEqual(c.deletes, [])

    def test_refused_when_the_object_was_deleted_meanwhile(self):
        c = self.client()
        path, plan = self.dry_run(c, self.YAML)
        c.grants.clear()
        rc, _, err = self.apply(c, path, plan)
        self.assertEqual(rc, 3)
        self.assertIn("SKIP (absent)", err)


class VerifyTests(WorkDir):
    def test_reports_absent_and_still_present(self):
        c = FakeClient()
        c.create_role("legacy")
        seed_grant(c, "legacy")
        text = (f"remove:\n  grants:\n    - {{role: legacy, effect: ALLOW, action: [SELECT, INSERT], entity: {entity()}}}\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.verify(c, base.validate(text))
        self.assertIn("REMOVE legacy -> ALLOW SELECT on tpch.tiny.customer: STILL PRESENT", out.getvalue())
        self.assertIn("REMOVE legacy -> ALLOW INSERT on tpch.tiny.customer: absent", out.getvalue())
        self.assertIn("1 object(s) still present", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            bd.apply(c, base.validate(text))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.verify(c, base.validate(text))
        self.assertIn("All removed objects are absent.", out.getvalue())

    def test_verify_does_not_raise_on_a_refused_expression(self):
        c = FakeClient()
        c.create_role("a")
        c.create_role("b")
        c.create_row_filter_expression("f", "true", "")
        for r in ("a", "b"):
            c.attach_row_filter(c.roles[r], entity_dict(), c.rf_expr["f"])
        text = f"remove:\n  row_filters:\n    - {{name: f, role: a, delete_expression: true, entity: {entity()}}}\n"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bd.verify(c, base.validate(text))
        self.assertIn("STILL PRESENT", out.getvalue())


class ClientRouteTests(unittest.TestCase):
    """Real BiacClient, the HTTP layer replaced: routes and status handling of the DELETE calls."""

    def client(self, status):
        c = bd.BiacClient({"SB_HOST": "h", "SB_PORT": "1", "SB_USER": "u", "SB_PASSWORD": "p"})
        calls = []
        c.call = lambda method, path, body=None: (calls.append((method, path)) or (status, None))
        return c, calls

    def test_routes(self):
        c, calls = self.client(204)
        c.delete_grant(5, 11)
        c.detach_row_filter(5, 12)
        c.detach_column_mask(5, 13)
        c.delete_location_grant(5, 14)
        c.delete_user_assignment("demo", 15)
        c.delete_group_assignment("grp", 16)
        c.delete_role(5)
        c.delete_row_filter_expression(17)
        c.delete_column_mask_expression(18)
        self.assertEqual(calls, [("DELETE", p) for p in (
            "/api/v1/biac/roles/5/grants/11", "/api/v1/biac/roles/5/rowFilters/12",
            "/api/v1/biac/roles/5/columnMasks/13", "/api/v1/biac/roles/5/locationGrants/14",
            "/api/v1/biac/subjects/users/demo/assignments/15", "/api/v1/biac/subjects/groups/grp/assignments/16",
            "/api/v1/biac/roles/5", "/api/v1/biac/expressions/rowFilter/17",
            "/api/v1/biac/expressions/columnMask/18")])

    def test_200_202_204_are_success_anything_else_raises(self):
        for status in (200, 202, 204):
            self.client(status)[0].delete_role(1)
        for status in (201, 301, 400, 403, 404, 409, 500):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.client(status)[0].delete_role(1)

    def test_user_name_is_one_path_segment(self):
        c, calls = self.client(204)
        c.delete_user_assignment("../roles/1", 3)
        self.assertEqual(calls, [("DELETE", "/api/v1/biac/subjects/users/..%2Froles%2F1/assignments/3")])

    def test_finders_match_the_cluster_records(self):
        c = bd.BiacClient({"SB_HOST": "h", "SB_PORT": "1", "SB_USER": "u", "SB_PASSWORD": "p"})
        data = {
            "/roles/1/grants": [{"id": 9, "effect": "ALLOW", "action": "SELECT",
                                 "entity": entity_dict(["Name", "custkey"])}],
            "/roles/1/locationGrants": [{"id": 8, "location": "s3://b/p/*", "grantOption": False}],
            "/roles/1/rowFilters": [{"id": 7, "expressionId": 3, "entity": entity_dict()}],
            "/subjects/users/demo/assignments": [{"id": 6, "roleId": 1}],
            "/subjects/groups/grp/assignments": [{"id": 5, "roleId": 2}],
        }
        c._list = lambda path: data[path]
        self.assertEqual(c.find_grant(1, "ALLOW", "SELECT", entity_dict(["custkey", "name"]))["id"], 9)
        self.assertIsNone(c.find_grant(1, "DENY", "SELECT", entity_dict(["custkey", "name"])))
        self.assertEqual(c.find_location_grant(1, "s3://b/p/*", False)["id"], 8)
        self.assertIsNone(c.find_location_grant(1, "s3://b/p/*", True))
        self.assertEqual(c.find_row_filter_attachment(1, entity_dict(), 3)["id"], 7)
        self.assertIsNone(c.find_row_filter_attachment(1, entity_dict(), 4))
        self.assertEqual(c.find_user_assignment("demo", 1)["id"], 6)
        self.assertIsNone(c.find_group_assignment("grp", 1))


if __name__ == "__main__":
    unittest.main()
