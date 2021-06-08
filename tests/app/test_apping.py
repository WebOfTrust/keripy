# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import json
import os
from dataclasses import dataclass, asdict

import pytest

from hio.base import doing

from keri.app import apping, habbing, keeping
from keri.core import coring, eventing
from keri.core.coring import Serials
from keri.db import dbing, basing, koming

def test_app():
    """
    """
    """End Test"""



def test_consoler():
    """
    Test Consoler class

    Must run in WindIDE with Debug I/O configured as external console
    """
    tock = 0.03125
    ticks = 8
    limit = tock * ticks
    doist = doing.Doist(tock=tock, real=True, limit=limit)
    assert doist.tyme == 0.0  # on next cycle
    assert doist.tock == tock == 0.03125
    assert doist.real == True
    assert doist.limit == limit
    assert doist.doers == []

    doer = apping.Consoler()

    doers = [doer]
    try:
        doist.do(doers=doers)
        assert doist.tyme == limit
    except IOError:  # pytest runner blocks opening of console have to test manually
        pass

    assert doer.console.opened == False


if __name__ == "__main__":
    test_consoler()

