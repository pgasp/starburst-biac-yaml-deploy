#!/usr/bin/env python3
"""
Deploy Starburst SEP BIAC entitlements (roles, grants, column masks, row
filters, assignments) declared in a YAML file, via the BIAC REST API.

Usage:
    python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --dry-run
    python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --apply
    python3 biac_deploy.py --env .env.mycluster --config examples/sample.biac.yaml --verify
    python3 biac_deploy.py --config examples/sample.biac.yaml --validate   # offline, no env, no network

Reviewed (signed) plan, no interactive prompt — the plan that was shown and
validated is the only one that can be applied:
    python3 biac_deploy.py --env .env.mycluster --config f.biac.yaml --dry-run --plan-out plan.json
    python3 biac_deploy.py --env .env.mycluster --config f.biac.yaml --apply --plan plan.json

Policy files are kept outside this repository, next to the project they
belong to (one *.biac.yaml per cluster and use case, with the real catalog/
schema/table names of that cluster). examples/ holds a generic sample.

Design:
- Idempotent: before creating any object, the existing cluster state is
  read via GET and compared. Matching objects are skipped, never recreated.
- Fail closed: config validation happens entirely before any network call.
  Any invalid or ambiguous entry aborts the whole run — nothing partial.
- No implicit destructive action: this script never deletes or revokes
  anything. Pruning is explicitly out of scope for v1. Drift detection is
  limited to row-filter / column-mask expressions: an expression that exists
  under the same name but with a different text (whitespace-normalised) is
  planned as 'DRIFT (expression differs)' and --apply refuses (exit 4) while
  the plan contains any DRIFT — it is never silently reused. Fix the YAML or
  align the cluster (outside this tool), then re-plan.
  This also means an existing grant/row filter/column mask can never be
  changed in place (e.g. ALLOW -> ALLOW_WITH_GRANT_OPTION on the same
  entity) — the BIAC API itself rejects a duplicate create in that case
  (409 ALREADY_EXISTS, keyed on action+entity, ignoring effect). To change
  an existing one, delete it on the cluster first (outside this tool), then
  re-run --apply.
- allEntities:true is never emitted for data entities — TABLES/FUNCTIONS
  are always scoped (catalog, catalog+schema, or catalog+schema+table/
  function), matching the BIAC API constraint that allEntities:true forbids
  any other attribute. Sole exception: AI_MODELS, where allEntities:true
  ("all AI models") is what the SEP UI itself emits.

Supported entity categories (grants):
  TABLES         {category: TABLES, catalog, [schema], [table]}
  FUNCTIONS      {category: FUNCTIONS, catalog, [schema], [function]}
  DATA_PRODUCTS  {category: DATA_PRODUCTS, domainName, [dataProductName]}
                 (domainName alone = every data product of the domain)
  AI_MODELS      {category: AI_MODELS, allEntities: true}
  USER_INTERFACE {category: USER_INTERFACE, uiFeature}
                 (e.g. AI_MODELS, DATA_PRODUCTS, QUERY_EDITOR, CATALOG_EXPLORER)
Formats read back from the BIAC API on a lab cluster (2026-10-15).
Column masks and row filters only accept TABLES.
Location grants (top-level 'location_grants': role, location, grant_option)
use their own endpoint /api/v1/biac/roles/{id}/locationGrants.
"""

# The code lives in the `biac/` package (config, validation, client, planner,
# executor, signed_plan, cli). This file is the command-line entry point and
# re-exports the package's public names, so `import biac_deploy` keeps working.
import os
import sys

# Make the `biac` package importable however this file is loaded: run as a
# script, imported, or loaded by path with importlib (python -I included).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from biac import cli  # noqa: E402
from biac.cli import (EXIT_DRIFT, EXIT_PLAN_REFUSED, EXIT_VALIDATION, build_parser, redact, run)  # noqa: E402,F401
from biac.client import BiacClient  # noqa: E402,F401
from biac.config import load_config, load_env, parse_config, read_config_bytes  # noqa: E402,F401
from biac.entities import (NON_DATA_CATEGORIES, NON_DATA_CATEGORIES_KEYS, _norm, describe_entity,  # noqa: E402,F401
                           entities_equal)
from biac.executor import apply, verify  # noqa: E402,F401
from biac.planner import (DRIFT_ACTION, drift_actions, drift_label, expression_drifts,  # noqa: E402,F401
                          expression_text, plan, print_plan)
from biac.policy import (FORBIDDEN_ROLES, MAX_DESCRIPTION_LENGTH, MAX_EXPRESSION_NAME_LENGTH,  # noqa: E402,F401
                         ROLE_NAME_RE, WIDENING_EFFECTS, grant_actions)
from biac.signed_plan import (PLAN_FILE_VERSION, build_signed_plan, canonical_json, check_signed_plan,  # noqa: E402,F401
                              load_plan_file, plan_diff_lines, plan_fingerprint, plan_records,
                              sha256_hex, write_plan_file)
from biac.validation import validate_config  # noqa: E402,F401


def main(argv=None):
    # BiacClient / load_env are looked up here, at call time, so that
    # replacing them on this module (tests, wrappers) takes effect.
    return cli.main(argv, description=__doc__, load_env=load_env, client_factory=BiacClient)


if __name__ == "__main__":
    sys.exit(main())
