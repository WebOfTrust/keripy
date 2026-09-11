#!/usr/bin/env python3
"""
check_spec_examples.py -- ACDC worked-examples drift guard.

keripy's tests are the single source of truth for the ACDC specification's
"Working ACDC Examples". The test suite emits a JSON manifest of every canonical
worked-example block (see tests/spec/acdc/test_acdc_examples.py and the
KERI_EMIT_WORKED_EXAMPLES env var). This checker compares that manifest against
the JSON blocks embedded in the spec's spec-body.md and fails if they diverge.

In spec-body.md each governed block is tagged with an HTML comment marker on the
line(s) immediately before its fenced JSON code block, e.g.:

    <!-- example: accreditationCompact -->
    ```json
    { ... }
    ```

Comparison is VALUE-EQUAL (parsed dict/list equality), so formatting, key order,
and whitespace do not matter -- only the actual data.

Usage:
    check_spec_examples.py --manifest <manifest.json> --spec <spec-body.md>

Exit code 0 and prints "OK: N blocks in sync" when everything matches.
Exit code 1 (with a report) on any mismatch, or any block present on one side
but missing on the other.

Dependency-light: standard library only (json, re, argparse, sys).
"""

import argparse
import ast
import json
import re
import sys


# Matches:  <!-- example: NAME -->  (whitespace-tolerant), then, skipping any
# blank lines, an opening ```json OR ```python fence, the body, and a closing
# ``` fence. The spec embeds schema/instance blocks two ways: json fences
# (canonical JSON) and python fences (Python-dict repr: single quotes, True /
# False / None). Both are governed and parsed to a value for comparison.
_BLOCK_RE = re.compile(
    r"<!--\s*example:\s*(?P<name>[^\s>-][^>]*?)\s*-->"  # marker w/ block name
    r"\s*"                                              # blank lines / ws
    r"```[ \t]*(?P<lang>json|python)[ \t]*\r?\n"        # opening fence + lang
    r"(?P<body>.*?)"                                    # block body (lazy)
    r"\r?\n[ \t]*```",                                  # closing fence
    re.DOTALL | re.IGNORECASE,
)


def _load_block_body(lang, body):
    """Parse a fenced block body into a Python value.

    ``json`` fences are parsed with ``json.loads``; ``python`` fences (a Python
    literal such as a dict repr with single quotes and True/False/None) are
    parsed with ``ast.literal_eval``, which evaluates literals ONLY and runs no
    code. Both yield native Python values, so a python-repr block and its JSON
    counterpart compare value-equal (Python ``False`` == JSON ``false``, etc.).

    Raises ``ValueError`` with a human-readable message on failure.
    """
    if lang.lower() == "json":
        try:
            return json.loads(body)
        except json.JSONDecodeError as ex:
            raise ValueError(f"spec JSON block does not parse: {ex}") from ex
    # python fence -> ast literal parse (safe: literals only, no execution)
    try:
        return ast.literal_eval(body)
    except (ValueError, SyntaxError) as ex:
        raise ValueError(f"spec python block does not parse: {ex}") from ex


def parse_spec_blocks(text):
    """Return (blocks, errors).

    blocks: dict name -> parsed value for every tagged json/python fence.
    errors: list of human-readable strings for markers whose body failed to
            parse or whose block name was duplicated.
    """
    blocks = {}
    errors = []
    for m in _BLOCK_RE.finditer(text):
        name = m.group("name").strip()
        lang = m.group("lang")
        body = m.group("body")
        try:
            value = _load_block_body(lang, body)
        except ValueError as ex:
            errors.append(f"{name}: {ex}")
            continue
        if name in blocks:
            errors.append(f"{name}: duplicate <!-- example: {name} --> marker "
                          f"in spec")
            continue
        blocks[name] = value
    return blocks, errors


def _diff_paths(expected, actual, path=""):
    """Yield concise 'path: detail' strings describing where two JSON values
    differ. `expected` is the manifest (canonical); `actual` is the spec."""
    if type(expected) is not type(actual) and not (
        isinstance(expected, (int, float)) and isinstance(actual, (int, float))
    ):
        yield (f"{path or '(root)'}: type differs "
               f"(manifest={type(expected).__name__}, "
               f"spec={type(actual).__name__})")
        return

    if isinstance(expected, dict):
        e_keys, a_keys = set(expected), set(actual)
        for k in sorted(e_keys - a_keys):
            yield f"{path}.{k}".lstrip(".") + ": missing in spec"
        for k in sorted(a_keys - e_keys):
            yield f"{path}.{k}".lstrip(".") + ": unexpected in spec"
        for k in sorted(e_keys & a_keys):
            child = f"{path}.{k}".lstrip(".")
            yield from _diff_paths(expected[k], actual[k], child)
        return

    if isinstance(expected, list):
        if len(expected) != len(actual):
            yield (f"{path or '(root)'}: list length differs "
                   f"(manifest={len(expected)}, spec={len(actual)})")
        for i in range(min(len(expected), len(actual))):
            yield from _diff_paths(expected[i], actual[i], f"{path}[{i}]")
        return

    if expected != actual:
        yield (f"{path or '(root)'}: value differs "
               f"(manifest={expected!r}, spec={actual!r})")


def compare(manifest, spec_blocks):
    """Return (ok, report_lines)."""
    report = []
    manifest_names = set(manifest)
    spec_names = set(spec_blocks)

    missing_in_spec = sorted(manifest_names - spec_names)
    extra_in_spec = sorted(spec_names - manifest_names)

    for name in missing_in_spec:
        report.append(f"MISSING IN SPEC: manifest block '{name}' has no "
                      f"<!-- example: {name} --> marker in spec-body.md")
    for name in extra_in_spec:
        report.append(f"EXTRA IN SPEC: spec block '{name}' has no matching "
                      f"block in the keripy manifest")

    mismatches = 0
    for name in sorted(manifest_names & spec_names):
        diffs = list(_diff_paths(manifest[name], spec_blocks[name]))
        if diffs:
            mismatches += 1
            report.append(f"MISMATCH: '{name}' differs "
                          f"({len(diffs)} path(s)):")
            for d in diffs[:40]:
                report.append(f"    - {d}")
            if len(diffs) > 40:
                report.append(f"    ... and {len(diffs) - 40} more")

    ok = not (missing_in_spec or extra_in_spec or mismatches)
    return ok, report


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Fail if the ACDC spec's worked-example JSON blocks drift "
                    "from keripy's canonical emitted manifest.")
    ap.add_argument("--manifest", required=True,
                    help="Path to keripy's emitted worked-examples manifest "
                         "(JSON: {blockName: acdcDict}).")
    ap.add_argument("--spec", required=True,
                    help="Path to the spec's spec-body.md.")
    args = ap.parse_args(argv)

    try:
        with open(args.manifest, encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as ex:
        print(f"ERROR: cannot read manifest {args.manifest!r}: {ex}",
              file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print(f"ERROR: manifest {args.manifest!r} is not a JSON object of "
              f"{{blockName: acdcDict}}", file=sys.stderr)
        return 2

    try:
        with open(args.spec, encoding="utf-8") as f:
            spec_text = f.read()
    except OSError as ex:
        print(f"ERROR: cannot read spec {args.spec!r}: {ex}", file=sys.stderr)
        return 2

    spec_blocks, parse_errors = parse_spec_blocks(spec_text)

    ok, report = compare(manifest, spec_blocks)

    if parse_errors:
        ok = False
        report = [f"PARSE ERROR: {e}" for e in parse_errors] + report

    if ok:
        print(f"OK: {len(manifest)} blocks in sync")
        return 0

    print("SPEC EXAMPLES DRIFT DETECTED")
    print("=" * 60)
    for line in report:
        print(line)
    print("=" * 60)
    print("The ACDC spec's worked-example blocks disagree with keripy's "
          "canonical generated ones.")
    print("keripy's tests are the source of truth; regenerate/sync the spec "
          "blocks (or the manifest) so they match.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
