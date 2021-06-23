# -*- encoding: utf-8 -*-
"""
keri.kli.common.config

"""
import json
from dataclasses import dataclass, asdict
from typing import Optional, List


@dataclass
class Config:
    """
    Config representation of prefix configuration
    """
    name: str  # Alias for prefix
    witnessExpire: Optional[int] = 60  # timeout for witness connection
    witnesses: Optional[List[str]] = None  # list of witness nodes
    transferable: Optional[bool] = None  # Use transferable derivation code

    def __iter__(self):
        return iter(asdict(self))


def loadConfig(file: str) -> Config:
    """
        Parameters:
            file (str): file location to load from
    """
    cfg = None
    if file != '':
        with open(file, "r") as f:
            cfg = Config(**json.loads(f.read()))
    return cfg
