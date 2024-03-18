# -*- encoding: utf-8 -*-
"""
tests.core.test_counting module

"""
from dataclasses import dataclass, astuple, asdict
from  ordered_set import OrderedSet as oset

import pytest


from keri import kering

from keri.core import counting
from keri.core.counting import MapDom, MapCodex, Counter


def test_mapdom():
    """Test MapDom base dataclass"""

    @dataclass
    class TestMapDom(MapDom):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmd = TestMapDom()

    assert 'X' in tmd
    assert 'Y' in tmd
    assert 'Z' in tmd

    assert tmd["xray"] == tmd.xray == 'X'
    assert tmd["yankee"] == tmd.yankee == 'Y'
    assert tmd["zulu"] == tmd.zulu == 'Z'


    tmd["xray"] = "x"
    assert tmd.xray == tmd["xray"] == "x"

    tmd["yankee"] = "y"
    assert tmd.yankee == tmd["yankee"] == "y"

    tmd["zulu"] = "z"
    assert tmd.zulu == tmd["zulu"] == "z"

    delattr(tmd, "zulu")  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    tmd["zulu"] = "z"
    assert tmd["zulu"] == "z"

    del tmd["zulu"]  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    # create dynamic attribute
    with pytest.raises(AttributeError):
        assert tmd.alpha == None

    with pytest.raises(IndexError):
        assert tmd["alpha"] == None

    tmd["alpha"] = "A"  # add new attribute but without default
    assert tmd.alpha == tmd["alpha"] == "A"

    del tmd["alpha"]  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.alpha == "A"

    with pytest.raises(IndexError):
        assert tmd["alpha"] == "A"

    # another dynamic attribut but delattr instead of del
    with pytest.raises(AttributeError):
        assert tmd.beta == None

    with pytest.raises(IndexError):
        assert tmd["beta"] == None

    tmd["beta"] = "B"  # add new attribute but without default
    assert tmd.beta == tmd["beta"] == "B"

    delattr(tmd, "beta")  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.beta == "B"

    with pytest.raises(IndexError):
        assert tmd["beta"] == "B"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmd["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmd, "gamma")

    """End Test"""


def test_mapcodex():
    """Test MapCodex base dataclass frozen"""


    @dataclass(frozen=True)
    class TestMapCodex(MapCodex):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmc = TestMapCodex()

    assert 'X' in tmc
    assert 'Y' in tmc
    assert 'Z' in tmc

    assert tmc.xray == tmc["xray"] == 'X'
    assert tmc.yankee == tmc["yankee"] == 'Y'
    assert tmc.zulu == tmc["zulu"] == 'Z'

    with pytest.raises(IndexError):
        tmc["xray"] = "x"

    with pytest.raises(AttributeError):
        tmc.xray = "x"

    with pytest.raises(IndexError):
        del tmc["xray"]

    with pytest.raises(AttributeError):
        delattr(tmc, "xray")

    with pytest.raises(IndexError):
        tmc["alpha"] = "A"

    with pytest.raises(AttributeError):
        tmc.alpha = "A"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmc["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmc, "gamma")

    """End Test"""

if __name__ == "__main__":
    test_mapdom()
    test_mapcodex()


