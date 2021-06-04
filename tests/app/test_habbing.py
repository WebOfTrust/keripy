# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import json
import os
from dataclasses import dataclass, asdict

import pytest

from keri.app import apping, habbing, keeping
from keri.core import coring, eventing
from keri.core.coring import Serials
from keri.db import dbing, koming



def test_habitat():
    """
    Test Habitat class
    """
    hab = habbing.Habitat(temp=True)
    assert hab.name == "test"

    hab.db.close(clear=True)
    hab.ks.close(clear=True)

    """End Test"""


def test_habitat_reinitialization():
    """
    Test Reinitializing Habitat class
    """
    name = "bob-test"
    with dbing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)

        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.dig
        assert hab.ridx == 0

    with dbing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        hab.rotate()

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.dig

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.dig

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.ridx == 1

        assert hab.kever.serder.dig != odig
        assert hab.kever.serder.dig == ndig

        hab.db.close(clear=True)
        hab.ks.close(clear=True)
    """End Test"""




if __name__ == "__main__":
    test_habitat()
