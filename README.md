# starburst-biac-yaml-deploy

Deploy Starburst SEP BIAC (Built-in Access Control) entitlements — roles,
privilege grants, column masks, and role assignments — from a declarative
YAML file, via the BIAC REST API.

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
2. Copy `examples/example-acme.yaml` and adapt it to your actual roles,
   tables, columns, and masking expressions.

## Usage

```bash
# 1. See what would change, without touching the cluster
python3 biac_deploy.py --env .env.lab --config config.yaml --dry-run

# 2. Apply — prompts for confirmation before any write
python3 biac_deploy.py --env .env.lab --config config.yaml --apply

# 3. Read back the current state of everything declared in the config
python3 biac_deploy.py --env .env.lab --config config.yaml --verify
```

## Config format

See `examples/example-acme.yaml` for a complete, commented example.

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
silently ignoring it.
