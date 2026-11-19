# starburst-biac-yaml-deploy

Deploy Starburst SEP BIAC (Built-in Access Control) entitlements — roles,
privilege grants, column masks, row filters, and role assignments — from a
declarative YAML file, via the BIAC REST API.

## Structure

```
biac_deploy.py   # command-line entry point; also re-exports the package (`import biac_deploy`)
biac/            # the library (stdlib + PyYAML only), one concern per module:
  policy.py        #   rules and vocabulary: forbidden roles, limits, grant actions, mask/filter kinds
  entities.py      #   entity comparison (case-insensitive) and display
  validation.py    #   structural validation and guardrails, one method per file section
  remove_validation.py #  the same for the `remove:` section (incl. create/remove conflicts)
  config.py        #   --env and --config loading
  client.py        #   BIAC REST client (one generic layer, thin per-object methods)
  planner.py       #   dry-run plan, expression drift detection
  removal.py       #   the `remove:` section: ordered DELETE / SKIP (absent) steps, apply, verify
  executor.py      #   apply (creations, then removals) and verify (read-back)
  signed_plan.py   #   --plan-out / --plan: fingerprint, plan file, refusal reasons
  cli.py           #   arguments, the four modes, exit codes, error display
examples/        # generic, commented policies, one per feature (see "Examples")
tests/           # offline unit tests (simulated BIAC client); they also validate every example
```

Where to change what: a new guardrail goes in `validation.py`; a new kind of
object needs `validation.py`, `client.py`, and a stage in both `planner.py`
and `executor.py` (the two walk the kinds in the same order; a test checks it);
removals live in `removal.py` (one list of steps read by plan, apply and verify).
Column masks and row filters share one code path (`ExpressionKind` in
`policy.py`).

**This repository holds no customer policy.** Real policy files live with the
project they belong to (one `<name>.biac.yaml` per cluster and use case, next to
the SQL that creates the views they target) and are passed with `--config`.
Several policy files can target the same cluster: each is planned and applied
on its own.

Catalog/schema/table names are hardcoded in each policy file — there is no
templating. To reproduce a policy on another cluster, copy the file and edit
the names.

## Scope (v1)

- ✅ Roles
- ✅ Grants (tables/functions, data products, AI models, UI features),
  including column-level `SELECT` grants (`entity.columns`)
- ✅ Location grants (`location_grants`, separate endpoint `/locationGrants`)
- ✅ Column masks (CLS)
- ✅ Row filters (RLS)
- ✅ Assignments (user/group → role)
- ✅ Drift detection on row-filter / column-mask **expressions**: same name
  but a different text (whitespace-normalised) is planned as
  `DRIFT (expression differs)` (both texts shown) and `--apply` refuses
  (exit code 4) while the plan contains any DRIFT — an existing expression is
  never silently reused. Align the YAML or the cluster (outside this tool,
  e.g. an in-place `PUT /api/v1/biac/expressions/rowFilter/{id}`), then
  re-plan. Identical text stays `SKIP (exists)`.
- ✅ Removals, only what is declared under the root key `remove:` (grants,
  location grants, mask / filter detaches and their orphan expressions,
  assignments, whole roles): see "Removing entitlements (`remove:`)".
  Nothing is deleted unless it is declared there.
- ❌ Pruning of entitlements that are not in the YAML (`--prune`): out of
  scope, the YAML is never taken as the full state of the cluster
- ❌ In-place update of an existing grant/mask/filter's `effect` or
  `expression` — the BIAC API rejects a duplicate create for the same
  action+entity regardless of effect (409 ALREADY_EXISTS), so changing one
  means removing it first (list it under `remove:`, apply), then moving it
  back to its creation section with the new value and applying again

## Requirements

- Python 3.8+
- `pip install -r requirements.txt` (PyYAML — the only dependency; the
  HTTP client itself uses only the standard library, no `requests`)

## Setup

1. Copy `.env.example` to `.env.<cluster-name>` and fill in real
   credentials. **Never commit this file** — it's gitignored.
2. Create the schemas/views the policy targets on the cluster first (Trino
   CLI, or any client with schema-creation rights): grants, masks and filters
   reference existing objects.

## Usage

```bash
# 1. See what would change, without touching the cluster
python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --dry-run

# 2. Apply — prompts for confirmation before any write
python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --apply

# 3. Read back the current state of everything declared in the config
python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --verify

# 4. Offline: validator + guardrails only (no --env, no network)
python3 biac_deploy.py --config examples/sample.biac.yaml --validate
```

The path of the credentials file is always given by `--env`; the script never
prints a password or token (error messages are redacted and no traceback is
shown).

### Signed plan (review, then apply exactly what was reviewed)

```bash
# 1. Compute the plan, write it with its fingerprint (JSON, mode 0600)
python3 biac_deploy.py --env .env.mycluster --config f.biac.yaml --dry-run --plan-out plan.json
# 2. A human reads the plan (printed, and in plan.json)
# 3. Apply: recomputes the plan against the live cluster, refuses if it differs. No prompt.
python3 biac_deploy.py --env .env.mycluster --config f.biac.yaml --apply --plan plan.json
```

The fingerprint is a SHA-256 over the canonical plan (sorted JSON), the exact
bytes of the YAML file (a comment is enough to change it) and the target
`host:port`. `--apply --plan` refuses — nothing is written — if the plan file
was altered, if the YAML changed since the plan was made, if the cluster state
changed (a role created meanwhile, etc.) or if the plan was made for another
cluster. Exit codes: `0` ok, `1` runtime error / manual apply aborted,
`2` invalid YAML or guardrail violation (or bad usage), `3` signed plan refused,
`4` `--apply` refused because the plan contains a `DRIFT (expression differs)`.
`--plan-out` is only valid with `--dry-run`, `--plan` only with `--apply`.
`--apply` without `--plan` keeps the interactive `yes` confirmation (manual use).

## Policy file format (`*.biac.yaml`)

See "Examples" below for complete, commented files covering every feature.

### Examples

All files are in `examples/`, use generic names (mostly the built-in `tpch`
catalog) and pass `--validate`; `python3 -m unittest` fails if one stops
validating.

| File | Shows |
|---|---|
| [`sample.biac.yaml`](examples/sample.biac.yaml) | A small end-to-end policy: three roles, schema and column grants, a UI grant, a location grant, one mask, one row filter, assignments and guardrails. Start here. |
| [`table-access.biac.yaml`](examples/table-access.biac.yaml) | Every TABLES scope (catalog-wide with `allow_catalog_wide`, schema, table, columns), the three effects (`ALLOW`, `DENY`, `ALLOW_WITH_GRANT_OPTION` for a SECURITY DEFINER view owner), multi-action grants, a writable sandbox (`CREATE`/`INSERT`/`REFRESH`…), location grants with and without grant option. |
| [`column-masks.biac.yaml`](examples/column-masks.biac.yaml) | Partial mask, hash (pseudonymisation), `NULL`, and a mask that returns **another column** of the same row (with the column grant it needs). |
| [`row-filters.biac.yaml`](examples/row-filters.biac.yaml) | Static filter, per-user perimeter from a mapping table (`current_user` subquery, with the grant on the mapping table), group-based filter (`current_groups()`), and a role without filter. |
| [`functions.biac.yaml`](examples/functions.biac.yaml) | `EXECUTE` on one routine, `CREATE`/`DROP`/`EXECUTE`/`SHOW` on a whole routine schema, `DENY` on one routine, `ALLOW_WITH_GRANT_OPTION` for a view owner. |
| [`remove.biac.yaml`](examples/remove.biac.yaml) | The `remove:` section: replace a column-level grant (create the new one, delete the old one), grants and location grants, detach a mask / filter with `delete_expression`, take a role away from a user and a group, delete a whole role. |
| [`data-products-ai-ui.biac.yaml`](examples/data-products-ai-ui.biac.yaml) | Data products (whole domain, one product, publisher actions incl. `PUBLISH`), AI models (`allEntities: true`), UI features (`QUERY_EDITOR`, `CATALOG_EXPLORER`, `DATA_PRODUCTS`, `AI_MODELS`). |

```bash
python3 biac_deploy.py --config examples/column-masks.biac.yaml --validate              # offline
python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --dry-run # plan only
```

Only `sample.biac.yaml` is meant to be applied as is on a test cluster (it
uses `tpch` and assigns `demo_*` accounts). `remove.biac.yaml` is a catalogue
of removal entries: `--dry-run` it, it is not a policy to apply. The others reference placeholder
catalogs (`lakehouse`, `postgres`), groups and routines: adapt the names first.

Actions used in the examples, by category (all applied on SEP 482-e lab
clusters):

| Category | Actions |
|---|---|
| `TABLES` | `SELECT`, `SHOW`, `CREATE`, `DROP`, `INSERT`, `DELETE`, `REFRESH` (materialized views) |
| `FUNCTIONS` | `EXECUTE`, `CREATE`, `DROP`, `SHOW` |
| `DATA_PRODUCTS` | `SHOW`, `CREATE`, `ALTER`, `DROP`, `PUBLISH` |
| `AI_MODELS` | `EXECUTE` |
| `USER_INTERFACE` | `SHOW` |

The validator does not check action names: a misspelt action is only caught
by the BIAC API, during `--apply`.

**Style convention — keep every grant on one flow-style line**, even when
`action` is a list:
```yaml
- {role: sample_ops, effect: ALLOW, action: [CREATE, DELETE, SELECT], entity: {category: TABLES, catalog: iceberg}}
```
Mixing flow-style (`{...}`) and block-style (one key per line) for the same
kind of entry invites exactly the kind of broken-YAML edit this project hit
twice (an unquoted comma, and later a stray `{`/`}` wrapped around
block-style lines). `column_masks` entries are the one exception — they stay
block-style (one key per line) since they're multi-field with nested
`entity`/`columns`, too long to read comfortably on one line.

```yaml
roles:
  - name: <lowercase_a-z0-9_only>

grants:
  - role: <role name declared above>
    effect: ALLOW | DENY | ALLOW_WITH_GRANT_OPTION
    action: SELECT | EXECUTE | INSERT | ...   # or a list: [SELECT, INSERT, ...]
    entity:
      category: TABLES | FUNCTIONS
      catalog: <catalog>
      schema: <schema>      # omit entirely for a catalog-wide grant
      table: <table>        # TABLES only — omit for a schema-wide grant
      function: <function>  # FUNCTIONS only — omit for a schema-wide grant
      columns: [<column>, ...]  # optional: column-level grant (use with TABLES + table;
                                # the validator does not check this)

location_grants:
  - role: <role name declared above>
    location: s3://<bucket>/<prefix>/*   # full URI, bucket + path required
    grant_option: false                  # optional, default false

column_masks:
  - name: <expression name, unique>
    description: <free text>
    expression: <SQL expression referencing the column>
    role: <role name declared above>
    entity:
      category: TABLES
      catalog: <catalog>
      schema: <schema>
      table: <table>
      columns: [<column>]

row_filters:
  - name: <expression name, unique>
    description: <free text>
    expression: <SQL boolean expression, e.g. a column IN (subquery)>
    role: <role name declared above>
    entity:
      category: TABLES
      catalog: <catalog>
      schema: <schema>
      table: <table>   # required — a row filter always targets one table

assignments:
  - role: <role name declared above>
    users: [<username>, ...]     # each must be listed in allowed_users
    groups: [<groupname>, ...]   # each must be listed in allowed_groups

remove:                          # optional, see "Removing entitlements (`remove:`)"
  grants: [...]                  # same entries as `grants:`
  location_grants: [...]
  column_masks: [...]            # name, role, entity [, delete_expression]
  row_filters: [...]
  assignments: [...]
  roles: [<role name>, ...]

# Guardrail declarations (root keys, all optional, all default to "nothing allowed")
allowed_users: [<username>, ...]
allowed_groups: [<groupname>, ...]
allow_catalog_wide: [<catalog>, ...]
```

## Removing entitlements (`remove:`)

The root key `remove:` declares objects that must be **absent** from the
cluster. It is the only way this tool deletes anything: an object that is not
listed there is never touched, and the YAML is never read as "the full state"
(there is no pruning). Each entry has the same format as in its creation
section, so an entry can be cut from `grants:` (etc.) and pasted under
`remove:`; keys that only matter for a creation (`expression`, `description`
of a mask or filter) are accepted and ignored.

```yaml
remove:
  grants:          # {role, effect, action (string or list), entity}
    - {role: sample_reader, effect: ALLOW, action: SELECT, entity: {category: TABLES, catalog: tpch, schema: tiny, table: customer, columns: [custkey, name]}}
  location_grants: # {role, location, grant_option?}
    - {role: sample_reader, location: "s3://example-bucket/landing/*"}
  column_masks:    # {name, role, entity, delete_expression?}
    - {name: sample_customer_phone_mask, role: sample_reader, delete_expression: true, entity: {category: TABLES, catalog: tpch, schema: tiny, table: customer, columns: [phone]}}
  row_filters:     # same shape (no columns)
    - {name: sample_nation_europe_only, role: sample_reader, entity: {category: TABLES, catalog: tpch, schema: tiny, table: nation}}
  assignments:     # {role, users?, groups?}: each account must be in allowed_users / allowed_groups
    - {role: sample_reader, users: [demo_analyst]}
  roles: [sample_legacy_role]   # the role itself, with everything attached to it
```

See [`examples/remove.biac.yaml`](examples/remove.biac.yaml).

### What the plan shows

Each entry becomes a line `[remove_<kind>] REMOVE <...>: DELETE` when the
object exists, or `SKIP (absent)` when it does not (idempotent: a second run
plans no `DELETE`). A `grants` entry with several actions gives one line per
action. `--apply` without `--plan` prints `N object(s) will be DELETED` before
the `yes` prompt (`--apply --plan` prints it too, there is no prompt).

```
=== Plan (dry-run, no changes made) ===
[role] sample_reader: SKIP (exists)
[grant] sample_reader -> ALLOW SELECT on tpch.tiny.customer.custkey,name,phone: CREATE
[remove_grant] REMOVE sample_reader -> ALLOW SELECT on tpch.tiny.customer.custkey,name: DELETE
[remove_grant] REMOVE sample_reader -> ALLOW INSERT on tpch.tiny.*: SKIP (absent)
```

### Matching rules

| Entry | An object matches when |
|---|---|
| `grants` | same role, same `effect`, same `action` (one match per action of a list) and the same entity: category, catalog, schema, table or function, and the **sorted, lowercased `columns`** (so `[b, a]` matches `[A, B]`, but `[a]` does not match `[a, b]`) |
| `location_grants` | same role, same `location`, same `grant_option` (default false) |
| `column_masks` / `row_filters` | the expression `name` is attached to the role on the same entity. `expression` and `description` are not compared. An unknown expression name, or a role that does not exist, is `SKIP (absent)` |
| `assignments` | the role is assigned to that user / group |
| `roles` | the role exists |

### Order: creations first, then removals

`--apply` runs every creation (as before), then the removals, in this order:
assignments, column-mask detaches, row-filter detaches, grants, location
grants, orphan expressions (masks, then filters), roles. The plan prints them
in that same order. Removals come **after** creations so that replacing an
object never opens a gap in access: changing the column list of a grant is
"create the new grant, then delete the old one" (see the example). Assignments
go first and the role last, so an account stops using a role before what the
role grants goes away.

### `delete_expression: true`

A detach removes the attachment (mask or filter on a role and a table), not the
named expression. With `delete_expression: true` the expression is also
deleted (`DELETE /api/v1/biac/expressions/{columnMask|rowFilter}/{id}`), but
only if **no role anywhere** keeps it attached once the planned detaches are
done (every role is scanned; the attachments removed by the same plan, role
cascade included, do not count). Otherwise the plan is **refused**, listing the
roles that still hold it: exit code 2, nothing written, in `--dry-run` as in
`--apply`. Default: `false`, the expression stays on the cluster. An expression
that is already gone is `SKIP (absent)`.

### `remove.roles`

The plan lists, one line each, everything attached to the role (assignments to
users and groups, column masks, row filters, grants, location grants) in the
stages above, then the role itself last. Expressions are not touched (use
`delete_expression` on a `column_masks` / `row_filters` entry for that). A role
that does not exist is `SKIP (absent)`. Ad-hoc deletion scripts (such as a
`biac_delete_role.py`) are no longer needed for declared objects.

### Failure handling

A `DELETE` answered `200`, `202` or `204` is a success. Any other status stops
the run immediately (fail closed): nothing after it is attempted, and what was
deleted before is what is printed as `deleted` above the error. Re-run
`--dry-run` to see what is left. With `--apply --plan`, the plan is recomputed
first and the apply is refused (exit 3) on any difference, including a removal
added or an object that has disappeared since.

### Validation (offline, exit code 2)

- unknown keys under `remove` or in its entries (a comma inside a flow-style
  `action:` is caught like in `grants`);
- never `sysadmin` / `public`, neither as the role to remove nor as the role
  of any removed object;
- an object cannot be both created and removed in one file (same identity: a
  grant by role + effect + action + entity, a location grant, a mask or filter
  by name + role + entity, an assignment by role + account). A `remove.roles`
  role must not be declared in `roles:` nor referenced by a creation entry, and
  `delete_expression` is refused for an expression that a creation section of
  the file also declares;
- roles named under `remove` need **not** be declared in `roles:` (they may be
  legacy) but must match `^[a-z0-9_]+$`;
- users / groups of `remove.assignments` must be in `allowed_users` /
  `allowed_groups`;
- entities follow the creation rules (no `'*'`, no `allEntities: true`, a
  `table` for masks and filters, `columns` for masks).

### `--verify`

After the declared roles, `--verify` prints the `remove:` section with each
object as `absent` or `STILL PRESENT`, and a count. Exit codes are unchanged.

## Guardrails (validator, fail closed)

These checks run before any network call, in every mode (`--dry-run`,
`--apply`, `--verify`, `--validate`). Any violation aborts the whole run
(exit code 2).

| Rule | Details |
|---|---|
| No `sysadmin` / `public` | A role named `sysadmin` or `public` (any case) cannot be declared, nor be the target of a grant, location grant, column mask, row filter or assignment. |
| `allowed_users` / `allowed_groups` | Every user (resp. group) in `assignments` must be listed in the root `allowed_users` (resp. `allowed_groups`) of the same file. A missing key means an empty list: any assignment is then refused. Exact, case-sensitive match. The file thus names the accounts it may touch (demo accounts, in the lab). |
| `allow_catalog_wide` | An `ALLOW` or `ALLOW_WITH_GRANT_OPTION` on a TABLES/FUNCTIONS entity **without `schema`** (whole catalog) is refused unless its catalog is listed in the root `allow_catalog_wide` (case-insensitive, per catalog). `DENY` and schema-scoped grants are not affected. |
| `remove:` | The same guardrails apply to removals (see "Removing entitlements"): no `sysadmin` / `public`, accounts declared in `allowed_users` / `allowed_groups`, no object both created and removed, unknown keys refused. |
| Expression name length | A `column_masks` / `row_filters` entry whose `name` is longer than 30 characters is refused, with the name and its length (BIAC API limit observed on SEP 482-e: `name: value may not be more than 30 characters`; it otherwise fails midway through `--apply`). Descriptions are capped at 250 characters. Role names: no limit documented or observed, so none is enforced. |

```yaml
allowed_users: [demo]
allowed_groups: [demo_dp_readers]
allow_catalog_wide: [tpch]      # opt-in, explicit, one catalog at a time
```

## Catalog-wide and schema-wide grants

A grant (or column mask) can target an entire catalog or schema instead of
one table, by **omitting** the narrower field(s) — not by setting them to
`'*'` (confirmed by testing against a real cluster, 2026-10-01: a literal
`'*'` is rejected by this tool's validator):

```yaml
entity: {category: TABLES, catalog: my_catalog}                  # catalog.*
entity: {category: TABLES, catalog: my_catalog, schema: my_schema} # catalog.schema.*
```

Non-data entities (grants only — masks and row filters accept TABLES only):

```yaml
entity: {category: DATA_PRODUCTS, domainName: CIB}                          # every DP of domain CIB
entity: {category: DATA_PRODUCTS, domainName: CIB, dataProductName: my_dp}  # one DP
entity: {category: AI_MODELS, allEntities: true}                            # all AI models (only allowed form)
entity: {category: USER_INTERFACE, uiFeature: AI_MODELS}                    # UI feature (QUERY_EDITOR, DATA_PRODUCTS…)
```

A column mask always targets one specific table (it masks specific
columns), so `table` is required there regardless.

## Column-level grants and column masks: behaviour

Observed on a lab cluster (SEP 482-e, 2026-11-16), with secure views:

- **A grant's identity includes its column list.** Idempotency compares
  effect + action + entity, and the entity includes the sorted, lowercased
  `columns`. Adding or removing a column in a column-level grant therefore
  plans a **new** grant (`CREATE`); the old grant stays on the cluster.
  Grants are cumulative `ALLOW`s: the old grant keeps giving access to its
  columns, so **removing a column from the YAML does not revoke it**. List the
  superseded grant under `remove:` (see "Removing entitlements"): the new one
  is created first, then the old one is deleted. Check that a following
  `--dry-run` plans neither `CREATE` nor `DELETE`.
- **A mask expression may reference another column of the same row**
  (e.g. expose `col_b`'s value in place of `col_a` for one role:
  `expression: "col_b"` on `columns: [col_a]`).
- **The mask is evaluated with the querying user's rights**: every column it
  references must be granted to the masked role, or the query fails with
  `Access Denied`, even though the mask, not the user, reads that column.
- **Filters and joins on a masked column use the masked value.** A
  `WHERE col_a = …` from a masked role matches the masked value, not the
  stored one: the underlying value is not leaked through a predicate.
- A role without a mask on the column sees the stored value, so one view
  column can carry a different value per role without any `CASE` on roles in
  the view.

## Security notes

- `allEntities: true` is rejected by this tool at validation time — every
  entity must name its catalog (and, narrower, schema/table or
  schema/function) explicitly, or use the catalog/schema-wide omission
  above. This is deliberate: `allEntities: true` combined with any other
  attribute is invalid per the BIAC API, and broad grants are a common
  source of over-permissioning.
- An EMPTY string for schema/table (as opposed to omitting the field) does
  NOT reliably work (confirmed on a demo cluster — `PERMISSION_DENIED` despite
  the grant existing). Use an explicit per-table grant, or omit the field
  entirely for a real catalog/schema-wide grant (see above) — never `""`.
- The script never deletes, revokes, or overwrites anything that is not
  declared under `remove:`. Re-running it against an unchanged config is a
  no-op (idempotent), removals included (`SKIP (absent)`).
- A removal is as visible as a creation: it is in the plan (`REMOVE` lines),
  in the signed plan's fingerprint, and counted before the `yes` prompt
  (`N object(s) will be DELETED`). A removal that cannot be proven safe (an
  expression still attached elsewhere) refuses the whole plan; a failed
  `DELETE` stops the run at once.
- `--apply` always prints the full plan and requires typing `yes` before
  any write, whenever at least one object would be created or deleted — unless
  `--plan <file>` is given: then there is no prompt and the apply only runs if
  the recomputed plan matches the signed one (see "Signed plan").
- Never granted, nor deleted, by this tool: anything on the roles `sysadmin` / `public`;
  anything on a whole catalog without an explicit `allow_catalog_wide`;
  assignments of accounts not declared in `allowed_users` / `allowed_groups`.
- Credentials live only in the file given by `--env`, parsed manually (never
  `source`d as shell, since values may contain special characters) and
  never logged or echoed back: HTTP error bodies are redacted and truncated,
  and errors are printed as a short message, never as a traceback.
- Writes require the `sysadmin` BIAC role (or an equivalent BIAC admin
  role) on the connecting user — set via the `X-Trino-Role` header.

## Known limitation

This tool cannot change the `effect` or `expression` of a grant/mask/filter
that is already on the cluster (the BIAC API treats a grant as the same object
once action+entity match, regardless of effect, and rejects a second create
with 409 ALREADY_EXISTS). To change one: list it under `remove:` and apply,
then move it back to its creation section with the new value and apply again
(one file cannot create and remove the same object, and doing it in two runs
leaves a short gap in access).

A column-level grant whose column list changes has no such gap: the new grant
is a different object, so it is created and the old one removed in the same
run, creations first (see "Column-level grants and column masks: behaviour").

Deleting is only possible for what is declared under `remove:`; there is no
pruning mode. The DELETE routes (confirmed on the lab, SEP 482-e, `sysadmin`
role; not covered by this repo's documentation of the API) are:

| Object | Route |
|---|---|
| Grant | `DELETE /api/v1/biac/roles/{roleId}/grants/{id}` |
| Row filter / column mask attachment | `DELETE /api/v1/biac/roles/{roleId}/rowFilters/{id}` / `.../columnMasks/{id}` |
| Location grant | `DELETE /api/v1/biac/roles/{roleId}/locationGrants/{id}` |
| Assignment | `DELETE /api/v1/biac/subjects/{groups\|users}/{name}/assignments/{id}` |
| Role (once empty) | `DELETE /api/v1/biac/roles/{roleId}` |
| Orphan expression | `DELETE /api/v1/biac/expressions/{rowFilter\|columnMask}/{id}` |

Ids come from the matching `GET` on the same path. In a role's assignments
(`GET /roles/{id}/assignments`) the subject's name is under `username` (user)
or `groupName` (group); any other shape stops the plan. User and group names
are URL-encoded as one path segment. `remove.assignments` reads the ids from
the per-subject listing (`GET /subjects/{users|groups}/{name}/assignments`),
assumed to carry the same assignment ids as the per-role listing (not yet
checked on a cluster).

## Tests

Offline unit tests (simulated BIAC client, no network, no credentials):

```bash
python3 -m unittest discover -s tests -v
```
