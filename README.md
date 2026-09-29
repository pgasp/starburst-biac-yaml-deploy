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
2. Copy `examples/example-acme.yaml` (generic template) and adapt it to
   your actual roles, tables, columns, and masking expressions.

## Examples included

- `examples/example-acme.yaml` — generic, minimal template (placeholder
  names throughout).
- `examples/acme-datahub-profils.yaml` — the actual `poc_profile_open` /
  `poc_profile_restricted` configuration validated on the internal demo cluster:
  unrestricted raw-table access vs. governed-view-only access with a
  salted-hash column mask on `id_col`. Row-level security (region
  filtering) is documented in the file's header comment but must be
  configured manually — it's out of scope for this tool (row filters
  aren't supported in v1).
- `examples/acme-sales_5m-decrypt.yaml` — the `poc_profile_decrypt`
  configuration for the `secret_col` AES-256 decryption use case. Requires
  the `decrypt_secret_col` UDF to already be deployed on the cluster — read the
  prerequisite comment at the top of the file before applying.

## Usage

```bash
# 1. See what would change, without touching the cluster
python3 biac_deploy.py --env .env.lab --config config.yaml --dry-run

# 2. Apply — prompts for confirmation before any write
python3 biac_deploy.py --env .env.lab --config config.yaml --apply

# 3. Read back the current state of everything declared in the config
python3 biac_deploy.py --env .env.lab --config config.yaml --verify

# If config.yaml uses entity_ref (see "Environments" below), add:
#   --environment environments/<your-cluster>.yaml
```

## Environments — reusing the same policy across clusters

Catalog/schema/table names are rarely the same twice: a demo cluster and a
real production cluster (or two different clients) will name the same
logical table differently. Hardcoding `catalog: iceberg, schema: datahub,
table: vact` into every grant/mask ties the whole policy file to one
specific cluster.

Instead, a policy file can reference an entity by **logical name**:

```yaml
grants:
  - role: poc_profile_restricted
    effect: ALLOW
    action: SELECT
    entity_ref: vact_governed   # resolved via --environment, not hardcoded
```

and a separate **environment file** maps each `entity_ref` to the real
catalog/schema/table (or function) *for one specific cluster*:

```yaml
# environments/demo-lab.yaml
entities:
  vact_governed: {catalog: iceberg, schema: datahub, table: vact}
```

Run the same policy file against different clusters just by swapping
`--environment`:

```bash
python3 biac_deploy.py --env .env.lab --config examples/acme-datahub-profils.yaml \
    --environment environments/demo-lab.yaml --dry-run

python3 biac_deploy.py --env .env.acme-prod --config examples/acme-datahub-profils.yaml \
    --environment environments/acme-prod.yaml --dry-run
```

To reproduce a policy on a new cluster: copy `environments/_template.yaml`
to `environments/<your-cluster-name>.yaml` and replace every `REPLACE_ME`
with the real name on that cluster — the policy file itself never changes.

`entity_ref` and inline `entity:` blocks can both be used (even in the same
file, on different items) — use `entity_ref` for anything that needs to
move between clusters, and inline `entity:` for something genuinely
cluster-specific that will never be reused elsewhere. A config that uses
`entity_ref` without passing `--environment` fails validation immediately,
before any network call — it never silently falls back to a guess.

## Config format

See `examples/example-acme.yaml` for a complete, commented example using
inline `entity:` blocks, or `examples/acme-datahub-profils.yaml` for one
using `entity_ref` (see "Environments" above).

```yaml
roles:
  - name: <lowercase_a-z0-9_only>

grants:
  - role: <role name declared above>
    effect: ALLOW | DENY | ALLOW_WITH_GRANT_OPTION
    action: SELECT | EXECUTE | INSERT | ...
    entity:                 # OR entity_ref: <name defined in --environment>
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
    entity:                 # OR entity_ref: <name> + columns: [<column>]
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
