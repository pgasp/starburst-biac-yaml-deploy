"""BIAC REST client (standard library only).

One generic layer (`call`, `_list`, `_post`) and thin public methods per
object kind. The public method names are the surface the planner, executor
and external scripts rely on (and that tests fake): keep them stable.
"""
import base64
import json
import urllib.error
import urllib.request

from .entities import entities_equal

API = "/api/v1/biac"


class BiacClient:
    def __init__(self, env):
        self.host = env["SB_HOST"]
        self.port = env["SB_PORT"]
        self.auth = base64.b64encode(
            f"{env['SB_USER']}:{env['SB_PASSWORD']}".encode()
        ).decode()

    def __repr__(self):  # never expose the Authorization material
        return f"BiacClient({self.host}:{self.port})"

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

    # --- generic layer. `path` is relative to API; error messages quote it. ---

    def _list(self, path):
        status, body = self.call("GET", f"{API}{path}")
        if status != 200:
            raise RuntimeError(f"GET {path} failed: {status} {body}")
        return body["result"]

    def _post(self, path, body, what=None):
        """POST; `what` overrides the 'POST <path>' start of the error message."""
        status, resp = self.call("POST", f"{API}{path}", body)
        if status not in (200, 201):
            raise RuntimeError(f"{what or f'POST {path}'} failed: {status} {resp}")
        return resp

    @staticmethod
    def _by_name(items, name):
        return next((i for i in items if i["name"] == name), None)

    def _attached(self, path, entity, expression_id):
        return any(m.get("expressionId") == expression_id and entities_equal(m.get("entity", {}), entity)
                   for m in self._list(path))

    # --- roles ---
    def list_roles(self):
        return self._list("/roles")

    def find_role(self, name):
        return self._by_name(self.list_roles(), name)

    def create_role(self, name):
        self._post("/roles", {"name": name}, what=f"POST /roles ({name})")
        return self.find_role(name)

    # --- grants ---
    def list_grants(self, role_id):
        return self._list(f"/roles/{role_id}/grants")

    def grant_exists(self, role_id, effect, action, entity):
        return any(g.get("effect") == effect and g.get("action") == action
                   and entities_equal(g.get("entity", {}), entity)
                   for g in self.list_grants(role_id))

    def create_grant(self, role_id, effect, action, entity):
        return self._post(f"/roles/{role_id}/grants", {"effect": effect, "action": action, "entity": entity})

    # --- location grants (separate endpoint from entity grants) ---
    def list_location_grants(self, role_id):
        return self._list(f"/roles/{role_id}/locationGrants")

    def location_grant_exists(self, role_id, location, grant_option):
        return any(g.get("location") == location and bool(g.get("grantOption")) == grant_option
                   for g in self.list_location_grants(role_id))

    def create_location_grant(self, role_id, location, grant_option):
        return self._post(f"/roles/{role_id}/locationGrants", {"location": location, "grantOption": grant_option})

    # --- column masks: expression, then attachment to a role ---
    def list_column_mask_expressions(self):
        return self._list("/expressions/columnMask")

    def find_column_mask_expression(self, name):
        return self._by_name(self.list_column_mask_expressions(), name)

    def create_column_mask_expression(self, name, expression, description):
        return self._post("/expressions/columnMask",
                          {"name": name, "expression": expression, "description": description},
                          what=f"POST /expressions/columnMask ({name})")

    def list_column_masks(self, role_id):
        return self._list(f"/roles/{role_id}/columnMasks")

    def column_mask_attached(self, role_id, entity, expression_id):
        return self._attached(f"/roles/{role_id}/columnMasks", entity, expression_id)

    def attach_column_mask(self, role_id, entity, expression_id):
        return self._post(f"/roles/{role_id}/columnMasks",
                          {"entity": entity, "expressionId": expression_id, "forceNone": False})

    # --- row filters: expression, then attachment to a role ---
    def list_row_filter_expressions(self):
        return self._list("/expressions/rowFilter")

    def find_row_filter_expression(self, name):
        return self._by_name(self.list_row_filter_expressions(), name)

    def create_row_filter_expression(self, name, expression, description):
        return self._post("/expressions/rowFilter",
                          {"name": name, "expression": expression, "description": description},
                          what=f"POST /expressions/rowFilter ({name})")

    def list_row_filters(self, role_id):
        return self._list(f"/roles/{role_id}/rowFilters")

    def row_filter_attached(self, role_id, entity, expression_id):
        return self._attached(f"/roles/{role_id}/rowFilters", entity, expression_id)

    def attach_row_filter(self, role_id, entity, expression_id):
        return self._post(f"/roles/{role_id}/rowFilters",
                          {"entity": entity, "expressionId": expression_id, "forceNone": False})

    # --- assignments (user or group -> role) ---
    def _list_assignments(self, subjects, name):
        return self._list(f"/subjects/{subjects}/{name}/assignments")

    def _assign(self, subjects, singular, name, role_id):
        return self._post(f"/subjects/{subjects}/{name}/assignments", {"roleId": role_id, "roleAdmin": False},
                          what=f"POST assign {singular} {name}")

    def list_user_assignments(self, user):
        return self._list_assignments("users", user)

    def user_assigned(self, user, role_id):
        return any(a.get("roleId") == role_id for a in self.list_user_assignments(user))

    def assign_user(self, user, role_id):
        return self._assign("users", "user", user, role_id)

    def list_group_assignments(self, group):
        return self._list_assignments("groups", group)

    def group_assigned(self, group, role_id):
        return any(a.get("roleId") == role_id for a in self.list_group_assignments(group))

    def assign_group(self, group, role_id):
        return self._assign("groups", "group", group, role_id)
