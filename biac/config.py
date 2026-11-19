"""Loading of the credentials file (--env) and of the policy file (--config)."""
import yaml

from .validation import validate_config


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    for required in ("SB_HOST", "SB_USER", "SB_PASSWORD"):
        if required not in env:
            raise ValueError(f"{path}: missing required key {required}")
    env.setdefault("SB_PORT", "443")
    return env


def read_config_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def parse_config(raw):
    config = yaml.safe_load(raw) or {}
    if not isinstance(config, dict):
        raise ValueError("Config validation failed:\n  - the YAML root must be a mapping")
    validate_config(config)
    return config


def load_config(path):
    return parse_config(read_config_bytes(path))
