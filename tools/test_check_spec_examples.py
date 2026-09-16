#!/usr/bin/env python3
"""Unit tests for tools/check_spec_examples.py.

Covers both fence kinds the spec uses: ```json (JSON) and ```python (a Python
dict repr), each in a good (value-equal to manifest) and a bad (drifted) case.
"""

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "check_spec_examples", os.path.join(_HERE, "check_spec_examples.py"))
csx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(csx)


# Canonical manifest block: JSON semantics (false / null / 3).
MANIFEST = {
    "widget": {"d": "abc", "flag": False, "n": 3, "opt": None, "list": [1, 2]},
}


def _spec_text(marker_name, lang, body):
    return f"prose\n\n<!-- example: {marker_name} -->\n```{lang}\n{body}\n```\n"


# ---- json fence -------------------------------------------------------------

def test_json_fence_good():
    body = '{"d": "abc", "flag": false, "n": 3, "opt": null, "list": [1, 2]}'
    blocks, errors = csx.parse_spec_blocks(_spec_text("widget", "json", body))
    assert not errors
    ok, report = csx.compare(MANIFEST, blocks)
    assert ok, report


def test_json_fence_bad():
    body = '{"d": "abc", "flag": true, "n": 3, "opt": null, "list": [1, 2]}'
    blocks, errors = csx.parse_spec_blocks(_spec_text("widget", "json", body))
    assert not errors
    ok, report = csx.compare(MANIFEST, blocks)
    assert not ok
    assert any("flag" in line for line in report)


# ---- python fence -----------------------------------------------------------

def test_python_fence_good():
    # Python-dict repr: single quotes, True/False/None. Value-equal to MANIFEST.
    body = "{'d': 'abc', 'flag': False, 'n': 3, 'opt': None, 'list': [1, 2]}"
    blocks, errors = csx.parse_spec_blocks(_spec_text("widget", "python", body))
    assert not errors
    ok, report = csx.compare(MANIFEST, blocks)
    assert ok, report


def test_python_fence_bad():
    body = "{'d': 'abc', 'flag': True, 'n': 3, 'opt': None, 'list': [1, 2]}"
    blocks, errors = csx.parse_spec_blocks(_spec_text("widget", "python", body))
    assert not errors
    ok, report = csx.compare(MANIFEST, blocks)
    assert not ok
    assert any("flag" in line for line in report)


def test_python_fence_unparseable_reports_error():
    body = "{'d': 'abc', this-is-not-a-literal}"
    blocks, errors = csx.parse_spec_blocks(_spec_text("widget", "python", body))
    assert not blocks
    assert errors and "python block does not parse" in errors[0]


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
