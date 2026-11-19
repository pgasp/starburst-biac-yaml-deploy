"""Command line: argument parsing, the four modes, exit codes, error display.

Exit codes: 0 ok, 1 runtime error / manual apply aborted, 2 invalid YAML,
guardrail violation or bad usage, 3 signed plan refused, 4 apply refused
because of DRIFT, 130 interrupted.
"""
import argparse
import base64
import sys
import urllib.error
from typing import NamedTuple

import yaml

from .client import BiacClient
from .config import load_env, parse_config, read_config_bytes
from .executor import apply, verify
from .planner import CREATE, drift_actions, plan, print_plan
from .signed_plan import build_signed_plan, check_signed_plan, load_plan_file, write_plan_file

EXIT_VALIDATION = 2    # invalid YAML / guardrail violation / bad CLI usage
EXIT_PLAN_REFUSED = 3  # --apply --plan: signed plan does not match
EXIT_DRIFT = 4         # --apply: an existing expression differs from the YAML

DEFAULT_DESCRIPTION = "Deploy Starburst SEP BIAC entitlements declared in a YAML file (see biac_deploy.py)."


def redact(text, env, limit=None):
    """Strip credential material from any text about to be printed."""
    text = str(text)
    for secret in (env.get("SB_PASSWORD"),
                   base64.b64encode(f"{env.get('SB_USER')}:{env.get('SB_PASSWORD')}".encode()).decode()
                   if env.get("SB_PASSWORD") else None):
        if secret:
            text = text.replace(secret, "****")
    return text if limit is None else text[:limit]


def build_parser(description=None):
    p = argparse.ArgumentParser(description=description or DEFAULT_DESCRIPTION,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", help="Path to .env file (SB_HOST/SB_PORT/SB_USER/SB_PASSWORD); "
                                 "required except with --validate")
    p.add_argument("--config", required=True, help="Path to the policy file (<name>.biac.yaml)")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Print the plan, no writes")
    mode.add_argument("--apply", action="store_true", help="Execute the plan")
    mode.add_argument("--verify", action="store_true", help="Read back and print current state")
    mode.add_argument("--validate", action="store_true",
                      help="Offline: run the validator (guardrails included) on --config only; "
                           "no env file, no network")
    p.add_argument("--plan-out", metavar="FILE",
                   help="With --dry-run: write the plan and its SHA-256 fingerprint to FILE (JSON)")
    p.add_argument("--plan", metavar="FILE",
                   help="With --apply: apply only if the recomputed plan matches FILE "
                        "(no interactive prompt; refuses with exit code 3 otherwise)")
    return p


class _Session(NamedTuple):
    client: object
    config: dict
    config_bytes: bytes
    cluster: str


# --------------------------------------------------------------------------
# Modes. Each returns the process exit code.
# --------------------------------------------------------------------------

def _validate(args):
    parse_config(read_config_bytes(args.config))
    print(f"OK: {args.config} passes validation (offline, no network).")
    return 0


def _dry_run(args, s):
    actions = plan(s.client, s.config)
    print_plan(actions, "=== Plan (dry-run, no changes made) ===")
    drifts = drift_actions(actions)
    if drifts:
        print(f"\nWARNING: {len(drifts)} expression(s) differ from the cluster (DRIFT) — "
              "--apply will refuse until they are aligned.", file=sys.stderr)
    if args.plan_out:
        signed = build_signed_plan(actions, s.config_bytes, s.cluster)
        write_plan_file(args.plan_out, signed)
        print(f"\nPlan written to {args.plan_out}")
        print(f"Fingerprint (SHA-256): {signed['fingerprint']}")
    return 0


def _apply(args, s):
    actions = plan(s.client, s.config)
    drifts = drift_actions(actions)
    if drifts:
        print_plan(actions, "=== Plan ===")
        print(f"REFUSED: {len(drifts)} expression(s) exist on the cluster with a different text "
              "(DRIFT) — nothing was applied. Align the YAML or the cluster, then re-plan.",
              file=sys.stderr)
        return EXIT_DRIFT
    if args.plan:
        return _apply_signed(args.plan, s, actions)
    return _apply_after_prompt(s, actions)


def _apply_signed(plan_path, s, actions):
    """No prompt: the reviewed (signed) plan is the authorisation."""
    signed = load_plan_file(plan_path)
    reasons = check_signed_plan(signed, actions, s.config_bytes, s.cluster)
    if reasons:
        print("REFUSED: the signed plan does not match — nothing was applied.", file=sys.stderr)
        for r in reasons:
            print(r if r.startswith("  ") else f"  * {r}", file=sys.stderr)
        print("Re-run --dry-run --plan-out and have the new plan validated.", file=sys.stderr)
        return EXIT_PLAN_REFUSED
    print_plan(actions, f"=== Plan (matches signed plan {signed['fingerprint'][:12]}…) ===")
    if not any(a[2] == CREATE for a in actions):
        print("\nNothing to do — cluster state already matches config.")
        return 0
    print("\n=== Applying (signed plan, no prompt) ===")
    apply(s.client, s.config)
    return 0


def _apply_after_prompt(s, actions):
    print_plan(actions, "=== Plan ===")
    creations = [a for a in actions if a[2] == CREATE]
    if not creations:
        print("\nNothing to do — cluster state already matches config.")
        return 0
    print(f"\n{len(creations)} new entitlement object(s) will be created (see plan above).")
    if input("Type 'yes' to proceed: ").strip().lower() != "yes":
        print("Aborted.")
        return 1
    print("\n=== Applying ===")
    apply(s.client, s.config)
    return 0


def run(args, secrets, load_env=load_env, client_factory=BiacClient):
    """Returns the process exit code. Raises on errors (handled by main).
    `secrets` receives the loaded env so main can redact error messages."""
    if args.validate:
        return _validate(args)

    env = load_env(args.env)
    secrets.update(env)
    print(f"Cluster: {env['SB_HOST']}:{env['SB_PORT']}  User: {env['SB_USER']}  Password: ****")

    config_bytes = read_config_bytes(args.config)
    config = parse_config(config_bytes)
    session = _Session(client_factory(env), config, config_bytes, f"{env['SB_HOST']}:{env['SB_PORT']}")

    if args.dry_run:
        return _dry_run(args, session)
    if args.apply:
        return _apply(args, session)
    verify(session.client, session.config)
    return 0


def main(argv=None, description=None, load_env=load_env, client_factory=BiacClient):
    """`load_env` and `client_factory` are injectable so that the biac_deploy.py
    facade (and tests) can substitute them."""
    p = build_parser(description)
    args = p.parse_args(argv)
    if not args.validate and not args.env:
        p.error("--env is required (except with --validate)")
    if args.plan_out and not args.dry_run:
        p.error("--plan-out is only valid with --dry-run")
    if args.plan and not args.apply:
        p.error("--plan is only valid with --apply")
    secrets = {}
    try:
        return run(args, secrets, load_env, client_factory)
    except (ValueError, yaml.YAMLError) as e:  # config / plan file validation (JSONDecodeError is a ValueError)
        print(redact(e, secrets), file=sys.stderr)
        return EXIT_VALIDATION
    except urllib.error.URLError as e:
        print(f"ERROR (network): {redact(getattr(e, 'reason', e), secrets, 500)}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError) as e:
        # Short message only: no traceback (a traceback or an HTTP error can
        # carry request headers / response bodies).
        print(f"ERROR ({type(e).__name__}): {redact(e, secrets, 500)}", file=sys.stderr)
        return 1
    except EOFError:
        print("Aborted (no interactive input).", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as e:  # last resort: never a raw traceback (could expose request data)
        print(f"ERROR ({type(e).__name__}): {redact(e, secrets, 500)}", file=sys.stderr)
        return 1
