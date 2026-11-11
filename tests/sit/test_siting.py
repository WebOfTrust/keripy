# -*- encoding: utf-8 -*-
"""
tests.sit.test_siting module

"""

import pytest

from keri.sit import (MaxHeight, MaxPathLength, Nodage, NodageFull,
                     Leafage, LeafageFull, Siter)

def test_siting_basic():
    """Basic Tests"""

    assert MaxHeight == 256
    assert MaxPathLength == MaxHeight

    nodage = Nodage(said="ABC", height="EFG", path="HIJ")
    assert nodage._asdict() == {'said': 'ABC', 'height': 'EFG', 'path': 'HIJ', 'left': '', 'right': ''}

    """Done Test"""

if __name__ == "__main__":
    test_siting_basic()

