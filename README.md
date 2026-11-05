# starburst-biac-yaml-deploy

Deploy Starburst SEP BIAC (Built-in Access Control) entitlements — roles,
privilege grants, column masks, row filters, and role assignments — from a
declarative YAML file, via the BIAC REST API.

## Structure

One folder per cluster/environment under `environments/`:

```
environments/
  demo-lab/
    views.sql   # schema + view/table creation for this cluster
    biac.yaml   # roles/grants/masks/filters/assignments for this cluster
  staging/
    views.sql
    perimeter-perimetre.sql  # extra SQL file: RLS perimeter mapping table
    biac.yaml
```

An environment folder isn't limited to exactly `views.sql` + `biac.yaml` —
add further `.sql` files for any extra schema/table that `biac.yaml`'s
grants/row_filters reference, as staging does above.

Catalog/schema/table names are hardcoded in each environment's files — there
is no cross-environment templating. To reproduce a policy on a new cluster,
copy the folder and edit both files:

```bash
cp -r environments/demo-lab environments/acme-prod
# then edit environments/acme-prod/views.sql and biac.yaml with the real
# catalog/schema/table names on that cluster
```

## Scope (v1)

- ✅ Roles
- ✅ Grants (tables/functions, data products, AI models, UI features)
- ✅ Location grants (`location_grants`, endpoint séparé `/locationGrants`)
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
- ❌ Pruning of entitlements not in the YAML — never deletes or revokes
  anything
- ❌ In-place update of an existing grant/mask/filter's `effect` or
  `expression` — the BIAC API rejects a duplicate create for the same
  action+entity regardless of effect (409 ALREADY_EXISTS), so changing one
  means deleting it on the cluster first, outside this tool, then re-running
  `--apply`

## Requirements

- Python 3.8+
- `pip install -r requirements.txt` (PyYAML — the only dependency; the
  HTTP client itself uses only the standard library, no `requests`)

## Setup

1. Copy `.env.example` to `.env.<cluster-name>` and fill in real
   credentials. **Never commit this file** — it's gitignored.
2. Run `environments/<name>/views.sql` on the target cluster first (Trino
   CLI, or any client with `sysadmin`/schema-creation rights) — the grants
   and masks in `biac.yaml` target the views/tables it creates.

## Usage

```bash
# 1. See what would change, without touching the cluster
python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --dry-run

# 2. Apply — prompts for confirmation before any write
python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --apply

# 3. Read back the current state of everything declared in the config
python3 biac_deploy.py --env .env.lab --config environments/demo-lab/biac.yaml --verify

# 4. Offline: validator + guardrails only (no --env, no network)
python3 biac_deploy.py --config environments/demo-lab/biac.yaml --validate
```

The path of the credentials file is always given by `--env`; the script never
prints a password or token (error messages are redacted and no traceback is
shown).

### Signed plan (review, then apply exactly what was reviewed)

```bash
# 1. Compute the plan, write it with its fingerprint (JSON, mode 0600)
python3 biac_deploy.py --env .env.lab --config f.biac.yaml --dry-run --plan-out plan.json
# 2. A human reads the plan (printed, and in plan.json)
# 3. Apply: recomputes the plan against the live cluster, refuses if it differs. No prompt.
python3 biac_deploy.py --env .env.lab --config f.biac.yaml --apply --plan plan.json
```

The fingerprint is a SHA-256 over the canonical plan (sorted JSON), the exact
bytes of the YAML file (a comment is enough to change it) and the target
`host:port`. `--apply --plan` refuses — nothing is written — if the plan file
was altered, if the YAML changed since the plan was made, if the cluster state
changed (a role created meanwhile, etc.) or if the plan was made for another
cluster. Exit codes: `0` ok, `1` runtime error / manual apply aborted,
`2` invalid YAML or guardrail violation (or bad usage), `3` signed plan refused.
`--plan-out` is only valid with `--dry-run`, `--plan` only with `--apply`.
`--apply` without `--plan` keeps the interactive `yes` confirmation (manual use).

## `biac.yaml` format

See `environments/demo-lab/biac.yaml` for a complete, commented real example
(the acme datahub `poc_profile_open` / `poc_profile_restricted` /
`poc_profile_decrypt` policy).

**Style convention — keep every grant on one flow-style line**, even when
`action` is a list:
```yaml
- {role: poc_profile_open, effect: ALLOW, action: [CREATE, DELETE, SELECT], entity: {category: TABLES, catalog: iceberg}}
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

# Guardrail declarations (root keys, all optional, all default to "nothing allowed")
allowed_users: [<username>, ...]
allowed_groups: [<groupname>, ...]
allow_catalog_wide: [<catalog>, ...]
```

## Guardrails (validator, fail closed)

These checks run before any network call, in every mode (`--dry-run`,
`--apply`, `--verify`, `--validate`). Any violation aborts the whole run
(exit code 2).

| Rule | Details |
|---|---|
| No `sysadmin` / `public` | A role named `sysadmin` or `public` (any case) cannot be declared, nor be the target of a grant, location grant, column mask, row filter or assignment. |
| `allowed_users` / `allowed_groups` | Every user (resp. group) in `assignments` must be listed in the root `allowed_users` (resp. `allowed_groups`) of the same file. A missing key means an empty list: any assignment is then refused. Exact, case-sensitive match. The file thus names the accounts it may touch (demo accounts, in the lab). |
| `allow_catalog_wide` | An `ALLOW` or `ALLOW_WITH_GRANT_OPTION` on a TABLES/FUNCTIONS entity **without `schema`** (whole catalog) is refused unless its catalog is listed in the root `allow_catalog_wide` (case-insensitive, per catalog). `DENY` and schema-scoped grants are not affected. |
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
entity: {category: TABLES, catalog: datahub}                  # catalog.*
entity: {category: TABLES, catalog: datahub, schema: my_schema} # catalog.schema.*
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

## Security notes

- `allEntities: true` is rejected by this tool at validation time — every
  entity must name its catalog (and, narrower, schema/table or
  schema/function) explicitly, or use the catalog/schema-wide omission
  above. This is deliberate: `allEntities: true` combined with any other
  attribute is invalid per the BIAC API, and broad grants are a common
  source of over-permissioning.
- An EMPTY string for schema/table (as opposed to omitting the field) does
  NOT reliably work (confirmed on the acme demo — `PERMISSION_DENIED` despite
  the grant existing). Use an explicit per-table grant, or omit the field
  entirely for a real catalog/schema-wide grant (see above) — never `""`.
- The script never deletes, revokes, or overwrites anything. Re-running it
  against an unchanged config is a no-op (idempotent).
- `--apply` always prints the full plan and requires typing `yes` before
  any write, whenever at least one object would be created — unless
  `--plan <file>` is given: then there is no prompt and the apply only runs if
  the recomputed plan matches the signed one (see "Signed plan").
- Never granted by this tool: anything on the roles `sysadmin` / `public`;
  anything on a whole catalog without an explicit `allow_catalog_wide`;
  assignments of accounts not declared in `allowed_users` / `allowed_groups`.
- Credentials live only in the file given by `--env`, parsed manually (never
  `source`d as shell, since values may contain special characters) and
  never logged or echoed back: HTTP error bodies are redacted and truncated,
  and errors are printed as a short message, never as a traceback.
- Writes require the `sysadmin` BIAC role (or an equivalent BIAC admin
  role) on the connecting user — set via the `X-Trino-Role` header.

## Known limitation

This tool can only CREATE grants/masks/filters that don't already exist —
it cannot change the `effect` or `expression` of one that's already on the
cluster (the BIAC API treats a grant as the same object once action+entity
match, regardless of effect, and rejects a second create with 409
ALREADY_EXISTS). To change one, delete it directly via the BIAC API first
(outside this tool), then re-run `--apply` to recreate it from the YAML.

## Tests

Offline unit tests (simulated BIAC client, no network, no credentials):

```bash
python3 -m unittest discover -s tests -v
```
