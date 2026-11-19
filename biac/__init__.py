"""BIAC policy-as-code: the library behind the `biac_deploy.py` command.

Modules: policy (constants, shared helpers), entities, validation, config,
client, planner, executor, signed_plan, cli.
"""
import sys

try:
    import yaml  # noqa: F401  (checked once here, for every module of the package)
except ImportError:
    print("Missing dependency: PyYAML. Install with: pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(1)
