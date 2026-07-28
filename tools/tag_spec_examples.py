#!/usr/bin/env python3
"""tag_spec_examples.py -- idempotent auto-tagger for the ACDC spec.

Inserts `<!-- example: NAME -->` markers before every fenced code block in the
spec's spec-body.md that parses (json OR python fence) to a dict value-equal to
a block in keripy's emitted worked-examples manifest, and does not already
carry a marker. Intended as a maintenance aid for check_spec_examples.py.

Rules (safety):
  * A fence is tagged only when its parsed value is value-equal to EXACTLY ONE
    manifest block. Ambiguous matches (0 or >1) are skipped and reported.
  * A fence already immediately preceded (skipping blank lines) by any
    `<!-- example: ... -->` marker is left untouched -> idempotent, and the 4
    already-tagged schema blocks are not retagged.
  * Only dict-valued manifest blocks are used as tag targets.

Usage:
    tag_spec_examples.py --manifest <manifest.json> --spec <spec-body.md>
                         [--dry-run]

Prints the list of blocks it tagged (or would tag).
"""

import argparse
import ast
import json
import re
import sys

_OPEN_RE = re.compile(r"^[ \t]*```[ \t]*(json|python)[ \t]*$", re.IGNORECASE)
_CLOSE_RE = re.compile(r"^[ \t]*```[ \t]*$")
_MARKER_RE = re.compile(r"^\s*<!--\s*example:\s*[^>]*-->\s*$")


def _parse_body(lang, body):
    if lang.lower() == "json":
        return json.loads(body)
    return ast.literal_eval(body)  # literals only; no code execution


def find_blocks(lines):
    """Yield (open_idx, close_idx, lang, body_text) for each fenced block."""
    i = 0
    n = len(lines)
    while i < n:
        m = _OPEN_RE.match(lines[i])
        if m:
            lang = m.group(1)
            j = i + 1
            while j < n and not _CLOSE_RE.match(lines[j]):
                j += 1
            if j < n:  # found close
                body = "\n".join(lines[i + 1:j])
                yield (i, j, lang, body)
                i = j + 1
                continue
        i += 1


def already_tagged(lines, open_idx):
    """True if the fence at open_idx already has an example marker above it
    (skipping blank lines)."""
    k = open_idx - 1
    while k >= 0 and lines[k].strip() == "":
        k -= 1
    return k >= 0 and bool(_MARKER_RE.match(lines[k]))


def tag(manifest, text):
    """Return (new_text, tagged_names, warnings)."""
    targets = [(name, val) for name, val in manifest.items()
               if isinstance(val, dict)]
    lines = text.split("\n")
    blocks = list(find_blocks(lines))

    inserts = []          # (open_idx, name)
    tagged = []
    warnings = []
    used = set()

    for open_idx, close_idx, lang, body in blocks:
        try:
            value = _parse_body(lang, body)
        except (ValueError, SyntaxError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        matches = [name for name, val in targets if val == value]
        if not matches:
            continue
        if len(matches) > 1:
            warnings.append(f"line {open_idx + 1}: ambiguous -- value-equal to "
                            f"multiple manifest blocks {matches}; skipped")
            continue
        name = matches[0]
        if already_tagged(lines, open_idx):
            continue
        if name in used:
            warnings.append(f"line {open_idx + 1}: manifest block '{name}' "
                            f"already tagged on an earlier fence; skipped")
            continue
        used.add(name)
        inserts.append((open_idx, name))
        tagged.append(name)

    # Apply insertions bottom-up so indices stay valid.
    for open_idx, name in sorted(inserts, reverse=True):
        lines.insert(open_idx, f"<!-- example: {name} -->")

    return "\n".join(lines), tagged, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be tagged; do not write.")
    args = ap.parse_args(argv)

    with open(args.manifest, encoding="utf-8") as f:
        manifest = json.load(f)
    with open(args.spec, encoding="utf-8") as f:
        text = f.read()

    new_text, tagged, warnings = tag(manifest, text)

    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)

    if not tagged:
        print("No untagged value-equal blocks found (nothing to do).")
        return 0

    print(f"{'Would tag' if args.dry_run else 'Tagged'} {len(tagged)} block(s):")
    for name in tagged:
        print(f"  + {name}")

    if not args.dry_run:
        with open(args.spec, "w", encoding="utf-8") as f:
            f.write(new_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
