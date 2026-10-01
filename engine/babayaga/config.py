'Resolution order for every key: ``BABAYAGA_*`` env > repo-root\n``babayaga.toml`` (stdlib tomllib, host-local, gitignored) > code default.\n\nv0 exposes exactly one key:\n\n- ``tools_dir`` — the operator instrument anchor. The session PATH is never\n  a resolver (cli.doctor fails closed while an instrument resolves there);\n  the anchor dir is the only legal home for instrument binaries\n  (``<tools_dir>/hydra``). Env: ``BABAYAGA_TOOLS``. Default:\n  ``<repo_root>/tools`` (gitignored; populated by the operator with\n  symlinks into local build trees).'

from __future__ import annotations

import os
import tomllib
from pathlib import Path

CONFIG_NAME = "babayaga.toml"
ENV_TOOLS = "BABAYAGA_TOOLS"

# Closed key set: a typo'd key would otherwise be silently ignored (the
# fail-open shape this layer exists to kill — rulecheck.py precedent).
ALLOWED_KEYS = ("tools_dir",)


class ConfigError(Exception):
    """Config file is malformed or carries unknown keys. Always a refusal (exit 2)."""


def repo_root() -> Path:
    # engine/babayaga/config.py -> engine/babayaga -> engine -> repo root
    return Path(__file__).resolve().parents[2]


def _toml_config() -> dict:
    path = repo_root() / CONFIG_NAME
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path} unreadable/invalid TOML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a table")
    unknown = sorted(set(data) - set(ALLOWED_KEYS))
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) {', '.join(unknown)} — the config shape "
            f"is closed: {', '.join(ALLOWED_KEYS)}")
    return data


def tools_dir() -> Path:
    """Resolve the instrument anchor dir: env > babayaga.toml > <repo>/tools.

    Existence is NOT checked here — resolution and validation are separate;
    doctor/run fail closed on an absent anchor.
    """
    env = os.environ.get(ENV_TOOLS)
    if env:
        return Path(env).expanduser()
    raw = _toml_config().get("tools_dir")
    if raw is not None:
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError(f"{CONFIG_NAME}: tools_dir must be a non-empty string")
        path = Path(raw).expanduser()
        return path if path.is_absolute() else repo_root() / path
    return repo_root() / "tools"


def instrument_path(binary: str) -> Path:
    """The anchored path of one instrument binary (never via session PATH)."""
    return tools_dir() / binary
