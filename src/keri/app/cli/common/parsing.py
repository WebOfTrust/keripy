# -*- encoding: utf-8 -*-
"""
keri.app.cli.common.parsing module

"""

import json
from argparse import ArgumentParser
from os import getenv
from typing import Any, List, Dict


class Parsery:
    """
    Defines utility methods creating common argument parsers.
    Can be used as parents to other argument parsers.
    """

    @staticmethod
    def keystore(required: bool = True):
        """
        Returns an ArgumentParser for a keystore parameters.

        Returns:
            ArgumentParser
        """
        parser = ArgumentParser(add_help=False)

        env_name = getenv("KLI_KEYSTORE_NAME", None)
        parser.add_argument(
            "--name",
            "-n",
            help="keystore name and file location of KERI keystore",
            required=required if env_name is None else False,
            default=env_name,
        )

        parser.add_argument(
            "--base",
            "-b",
            help="additional optional prefix to file location of KERI keystore",
            required=False,
            default=getenv("KLI_KEYSTORE_BASE", ""),
        )
        parser.add_argument(
            "--passcode",
            "-p",
            help="21 character encryption passcode for keystore (is not saved)",
            dest="bran",
            default=getenv("KLI_KEYSTORE_PASSCODE", None),
        )

        return parser


def loadJSON(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def isNumber(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def coerce(value: str) -> Any:
    ss = value.strip()
    if not ss:
        return ""
    if ss[0] in "{[" or ss in ("true", "false", "null") or isNumber(ss):
        try:
            return json.loads(ss)
        except Exception:
            return value
    return value


def parseDataItems(items: List[str]) -> Dict[str, Any]:
    """
    Accepts:
      - ["@file.json"] -> dict (must be object)
      - ['{"a":1}'] -> dict
      - ["a=1", "b=true", "c=[1,2]"] -> dict
    """
    if not items:
        return {}

    data: Dict[str, Any] = {}
    for item in items:
        if item is None:
            continue

        item = item.strip()
        if not item:
            continue

        if item.startswith("@"):
            obj = loadJSON(item[1:])
            if not isinstance(obj, dict):
                raise ValueError("@file must contain a JSON object")
            data.update(obj)
            continue

        if item.startswith("{"):
            obj = json.loads(item)
            if not isinstance(obj, dict):
                raise ValueError("JSON must be an object")
            data.update(obj)
            continue

        if "=" not in item:
            raise ValueError(
                f"invalid item '{item}', expected key=value, JSON object, or @file.json"
            )

        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid item '{item}', empty key")
        data[key] = coerce(value)
    return data
