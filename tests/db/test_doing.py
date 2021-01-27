# -*- encoding: utf-8 -*-
"""
tests.db.doing module

"""
import pytest

import os

from hio.base import doing
from keri.db import dbing


def test_baserdoer():
    """
    Test BaserDoer


    """
    db0 = dbing.Baser(name='test0', temp=True, reopen=False)
    assert db0.opened == False
    assert db0.path == None
    assert db0.env == None

    dbdoer0 = dbing.BaserDoer(baser=db0)
    assert dbdoer0.baser == db0
    assert dbdoer0.baser.opened == False

    db1 = dbing.Baser(name='test1', temp=True, reopen=False)
    assert db1.opened == False
    assert db1.path == None
    assert db1.env == None

    dbDoer1 = dbing.BaserDoer(baser=db1)
    assert dbDoer1.baser == db1
    assert dbDoer1.baser.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [dbdoer0, dbDoer1]

    dogs = doist.ready(doers=doers)
    assert len(dogs) == 2
    assert [val[1] for val in dogs] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer._tymist == doist
        assert doer.baser.opened
        assert "_test/keri/db/test" in doer.baser.path

    doist.once(dogs)
    assert doist.tyme == 0.03125  # on next cycle
    assert len(dogs) == 2
    for doer in doers:
        assert doer.baser.opened == True

    for dog, retyme, index in dogs:
        dog.close()

    for doer in doers:
        assert doer.baser.opened == False
        assert doer.baser.env == None
        assert not os.path.exists(doer.baser.path)

    # start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.baser.opened == False
        assert doer.baser.env == None
        assert not os.path.exists(doer.baser.path)

    """End Test"""


if __name__ == "__main__":
    test_baserdoer()
