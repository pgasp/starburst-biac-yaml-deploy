# starburst-biac-yaml-deploy

Deploy Starburst SEP BIAC (Built-in Access Control) entitlements — roles,
privilege grants, column masks, and role assignments — from a declarative
YAML file, via the BIAC REST API.

## Structure

One folder per cluster/environment under `environments/`:

```
environments/
  demo-lab/
    views.sql   # schema + view/table creation for this cluster
    biac.yaml   # roles/grants/masks/assignments for this cluster
```

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
- ✅ Grants (privileges on tables/functions)
- ✅ Column masks (CLS)
- ✅ Assignments (user/group → role)
- ❌ Row filters (RLS) — not supported in this version, add later if needed
- ❌ Drift detection / pruning of entitlements not in the YAML — never
  deletes or revokes anything

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
```

## `biac.yaml` format

See `environments/demo-lab/biac.yaml` for a complete, commented real example
(the acme datahub `poc_profile_open` / `poc_profile_restricted` /
`poc_profile_decrypt` policy).

```yaml
roles:
  - name: <lowercase_a-z0-9_only>

grants:
  - role: <role name declared above>
    effect: ALLOW | DENY | ALLOW_WITH_GRANT_OPTION
    action: SELECT | EXECUTE | INSERT | ...
    entity:
      category: TABLES | FUNCTIONS
      catalog: <catalog>
      schema: <schema>
      table: <table>        # TABLES only
      function: <function>  # FUNCTIONS only

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

assignments:
  - role: <role name declared above>
    users: [<username>, ...]
    groups: [<groupname>, ...]
```

## Security notes

- `allEntities: true` is rejected by this tool at validation time — every
  entity must name its catalog/schema/table (or catalog/schema/function)
  explicitly. This is deliberate: `allEntities: true` combined with any
  other attribute is invalid per the BIAC API, and broad grants are a
  common source of over-permissioning.
- BIAC grants with an empty/wildcard table (schema-wide) do NOT reliably
  work (confirmed on the acme demo — `PERMISSION_DENIED` despite the grant
  existing) — every grant is explicit, per-table.
- The script never deletes, revokes, or overwrites anything. Re-running it
  against an unchanged config is a no-op (idempotent).
- `--apply` always prints the full plan and requires typing `yes` before
  any write, whenever at least one object would be created.
- Credentials live only in the `.env.*` file, parsed manually (never
  `source`d as shell, since values may contain special characters) and
  never logged or echoed back.
- Writes require the `sysadmin` BIAC role (or an equivalent BIAC admin
  role) on the connecting user — set via the `X-Trino-Role` header.

## Known limitation

Row filters (RLS) are not implemented in this version. The config
validator will reject a `row_filters` section explicitly rather than
silently ignoring it. See the header comment in
`environments/demo-lab/biac.yaml` for the row filter expression to apply
manually.
