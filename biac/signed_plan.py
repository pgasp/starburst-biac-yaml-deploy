"""Signed plan: `--dry-run --plan-out F` writes it, `--apply --plan F` checks it.

The fingerprint is a SHA-256 over the canonical plan, the exact bytes of the
YAML file and the target cluster: a change to any of the three invalidates it.
"""
import hashlib
import json
import os
import tempfile

PLAN_FILE_VERSION = 1


def plan_records(actions):
    """Plan tuples -> JSON-friendly records (stable order = plan order)."""
    return [{"kind": k, "label": label, "action": a} for k, label, a in actions]


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def plan_fingerprint(records, config_sha256, cluster):
    """SHA-256 over the canonical plan, the exact bytes of the YAML file and
    the target cluster. Any change to one of the three changes the fingerprint."""
    return sha256_hex(canonical_json({"cluster": cluster, "config_sha256": config_sha256, "plan": records}))


def build_signed_plan(actions, config_bytes, cluster):
    records = plan_records(actions)
    config_sha = sha256_hex(config_bytes)
    return {
        "version": PLAN_FILE_VERSION,
        "cluster": cluster,
        "config_sha256": config_sha,
        "plan": records,
        "fingerprint": plan_fingerprint(records, config_sha, cluster),
    }


def write_plan_file(path, signed_plan):
    """Atomic write, mode 0600 (the plan holds no credential, but there is no
    reason for it to be world-readable)."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".plan-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(signed_plan, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_plan_file(path):
    with open(path) as f:
        data = json.load(f)
    required = {"version", "cluster", "config_sha256", "plan", "fingerprint"}
    if not isinstance(data, dict) or not required <= set(data) or data["version"] != PLAN_FILE_VERSION:
        raise ValueError(f"{path}: not a valid plan file (version {PLAN_FILE_VERSION})")
    if not isinstance(data["plan"], list):
        raise ValueError(f"{path}: not a valid plan file ('plan' must be a list)")
    return data


def _record_text(canonical):
    r = json.loads(canonical)
    return f"[{r['kind']}] {r['label']}: {r['action']}"


def plan_diff_lines(old_records, new_records):
    old = {canonical_json(r) for r in old_records}
    new = {canonical_json(r) for r in new_records}
    lines = [f"  - only in the signed plan: {_record_text(r)}" for r in sorted(old - new)]
    lines += [f"  + only in the recomputed plan: {_record_text(r)}" for r in sorted(new - old)]
    return lines


def check_signed_plan(signed, live_actions, config_bytes, cluster):
    """Returns a list of refusal reasons (empty = the signed plan is valid)."""
    reasons = []
    stored_records = signed["plan"]
    if plan_fingerprint(stored_records, signed["config_sha256"], signed["cluster"]) != signed["fingerprint"]:
        reasons.append("the plan file was altered (its fingerprint does not match its own content)")
    if signed["cluster"] != cluster:
        reasons.append(f"the plan was made for cluster {signed['cluster']!r}, not {cluster!r}")
    if signed["config_sha256"] != sha256_hex(config_bytes):
        reasons.append("the YAML file changed since the plan was signed")
    live_records = plan_records(live_actions)
    live_fp = plan_fingerprint(live_records, sha256_hex(config_bytes), cluster)
    if live_fp != signed["fingerprint"]:
        reasons.append("the recomputed plan differs from the signed plan (cluster state or YAML changed)")
        reasons.extend(plan_diff_lines(stored_records, live_records))
    return reasons
