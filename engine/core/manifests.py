'Instrument adapter manifests: load, validate, version-range check (B18).\n\nFail-closed everywhere:\n- an unknown, missing, malformed, or schema-mismatched manifest is a\n  ManifestError (a refusal, exit 2), never a default;\n- a discovered version that is unparseable, ambiguous, or outside the pinned\n  range is a refusal tuple, never a best-guess accept;\n- ``vendored: true`` or an unknown ``relationship`` refuses at load: the\n  instrument boundary is runtime argv only (NOTICE, RESEARCH.md §1).'

from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA = "babayaga.instrument-manifest/1"

# Instrument names double as file stems: keep them path-safe.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Version strings: "9.8dev", "9.8", "7.1.2". A dev suffix sorts BEFORE the
# same release (upstream tags the in-development tree x.y+1dev).
VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(dev)?$")

# The only legal instrument relationship at v0 (citation, never combination).
RELATIONSHIPS = ("runtime-argv",)


class ManifestError(Exception):
    """Manifest is missing, malformed, or refuses the request. Always a refusal (exit 2)."""


def manifests_dir() -> Path:
    # engine/core/manifests.py -> engine/core -> engine -> scripts/ — the
    # manifests live FLAT in engine/scripts/ (moved from engine/host/manifests/
    # when the host/ adapter layer went away). Every *.json in that directory
    # is a manifest and is validated fail-closed by load()/parse() below.
    return Path(__file__).resolve().parents[1] / "scripts"


def available(base: str | Path | None = None) -> list[str]:
    """Names of every manifest present (sorted file stems)."""
    root = Path(base) if base is not None else manifests_dir()
    if not root.is_dir():
        return []
    return sorted(p.stem for p in root.glob("*.json"))


def parse_version(text: str) -> tuple[int, int, int, int]:
    """Parse "x.y[.z][dev]" into a comparable tuple; dev sorts before release."""
    m = VERSION_RE.match(text.strip()) if isinstance(text, str) else None
    if not m:
        raise ManifestError(f"unparseable version string {text!r} (expected x.y[.z][dev])")
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    release = 0 if m.group(4) else 1  # 9.8dev < 9.8
    return (major, minor, patch, release)


def _check_version_block(version: object, errors: list[str]) -> None:
    if not isinstance(version, dict):
        errors.append("version: object required")
        return
    argv = version.get("probe_argv")
    if (not isinstance(argv, list) or not argv
            or not all(isinstance(tok, str) and tok for tok in argv)):
        errors.append("version.probe_argv: non-empty list of strings required")
    pattern = version.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        errors.append("version.pattern: non-empty regex string required")
    else:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            errors.append(f"version.pattern: does not compile: {exc}")
        else:
            if compiled.groups != 1:
                errors.append("version.pattern: exactly one capture group required")
    bounds: dict[str, tuple[int, int, int, int]] = {}
    for key in ("min", "max_exclusive"):
        raw = version.get(key)
        if not isinstance(raw, str):
            errors.append(f"version.{key}: version string required")
            continue
        try:
            bounds[key] = parse_version(raw)
        except ManifestError as exc:
            errors.append(f"version.{key}: {exc}")
    if "min" in bounds and "max_exclusive" in bounds and not bounds["min"] < bounds["max_exclusive"]:
        errors.append("version: min must be below max_exclusive")
    anchored = version.get("anchored")
    if not isinstance(anchored, str):
        errors.append("version.anchored: version string required (the pinned, measured build)")
    else:
        try:
            anchored_v = parse_version(anchored)
        except ManifestError as exc:
            errors.append(f"version.anchored: {exc}")
        else:
            if "min" in bounds and "max_exclusive" in bounds:
                if not bounds["min"] <= anchored_v < bounds["max_exclusive"]:
                    errors.append("version.anchored: must lie inside [min, max_exclusive)")
    date = version.get("anchored_date")
    if not isinstance(date, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
        errors.append("version.anchored_date: YYYY-MM-DD string required")


def validate(obj: object) -> list[str]:
    """Return a list of problems; empty list means the manifest is valid."""
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["manifest must be a JSON object"]
    if obj.get("schema") != SCHEMA:
        errors.append(f"schema: must be {SCHEMA!r} (unknown schema is a refusal)")
    instrument = obj.get("instrument")
    if not isinstance(instrument, str) or not NAME_RE.match(instrument):
        errors.append("instrument: must match " + NAME_RE.pattern)
    binary = obj.get("binary")
    if (not isinstance(binary, str) or not binary.strip()
            or "/" in binary or "\\" in binary):
        errors.append("binary: bare executable name required (no path components)")
    upstream = obj.get("upstream")
    if not isinstance(upstream, dict):
        errors.append("upstream: object required")
    else:
        repo = upstream.get("repo")
        if not isinstance(repo, str) or not re.match(r"^[\w.-]+/[\w.-]+$", repo):
            errors.append("upstream.repo: 'owner/name' string required")
        license_ = upstream.get("license")
        if not isinstance(license_, str) or not license_.strip():
            errors.append("upstream.license: non-empty SPDX-style string required")
        if upstream.get("relationship") not in RELATIONSHIPS:
            errors.append("upstream.relationship: must be one of " + ", ".join(RELATIONSHIPS))
        if upstream.get("vendored") is not False:
            errors.append("upstream.vendored: must be false (instruments are cited, never vendored)")
    _check_version_block(obj.get("version"), errors)
    if not isinstance(obj.get("requires_standard_ports"), bool):
        errors.append("requires_standard_ports: boolean required")
    if "notes" in obj and not isinstance(obj["notes"], str):
        errors.append("notes: string required when present")
    return errors


def load(name: str, base: str | Path | None = None) -> dict:
    """Load and validate the manifest for instrument `name`. Fail-closed."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ManifestError(f"malformed instrument name {name!r}")
    root = Path(base) if base is not None else manifests_dir()
    path = root / f"{name}.json"
    if not path.is_file():
        raise ManifestError(f"no manifest for instrument {name!r} (looked in {root})")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"manifest unreadable/invalid JSON: {exc}") from exc
    errors = validate(obj)
    if isinstance(obj, dict) and obj.get("instrument") != name:
        errors.append(f"instrument field {obj.get('instrument')!r} does not match file stem {name!r}")
    if errors:
        raise ManifestError(f"manifest {name!r} invalid: " + "; ".join(errors))
    return obj


def extract_version(manifest: dict, probe_output: str) -> str:
    """Extract the version from a probe's combined output.

    Zero matches or more than one DISTINCT match is a refusal: unknown or
    ambiguous instrument output is never best-guessed.
    """
    pattern = manifest["version"]["pattern"]
    found = {m if isinstance(m, str) else m[0] for m in re.findall(pattern, probe_output)}
    if not found:
        raise ManifestError("no version string found in probe output")
    if len(found) > 1:
        raise ManifestError(f"ambiguous probe output: {len(found)} distinct version strings {sorted(found)}")
    return next(iter(found))


def check_version(manifest: dict, discovered: str) -> tuple[bool, str]:
    """Refusal tuple for a discovered version string against the pinned range."""
    version = manifest["version"]
    name = manifest["instrument"]
    lo, hi = version["min"], version["max_exclusive"]
    try:
        v = parse_version(discovered)
    except ManifestError:
        return False, f"{name} version {discovered!r} is unparseable — refusing (unknown output is never accepted)"
    if v < parse_version(lo):
        return False, f"{name} {discovered} is below the pinned range [{lo}, {hi})"
    if v >= parse_version(hi):
        return False, f"{name} {discovered} is at or above the pinned range [{lo}, {hi})"
    return True, f"{name} {discovered} within pinned range [{lo}, {hi})"
