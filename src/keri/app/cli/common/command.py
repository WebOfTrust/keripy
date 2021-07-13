# -*- encoding: utf-8 -*-
"""
keri.kli.common.command module

Command type for dispatching command doers

"""
from collections import Callable
from dataclasses import dataclass
from typing import Type

from hio.base.doing import Doer


class Command:
    def __init__(self, name: str, handler: Callable[[Type[dataclass]], Doer], opts: Type[dataclass]) -> None:
        self.name = name
        self.handler = handler
        self.opts = opts
        super().__init__()