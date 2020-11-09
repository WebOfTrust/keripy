# -*- encoding: utf-8 -*-
"""
tests.base.keeping module

"""
import pytest

import os
import lmdb

from hio.base import  doing
from keri.base import keeping


def test_openkeep():
    """
    test contextmanager decorator for test Keeper databases
    """
    with keeping.openKeep() as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "test"
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_keep_")
        assert keeper.path.endswith("_test/keri/keep/test")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)
        assert keeper.opened

    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    with keeping.openKeep(name="blue") as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "blue"
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_keep_")
        assert keeper.path.endswith("_test/keri/keep/blue")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)
        assert keeper.opened

    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    with keeping.openKeep(name="red") as red, keeping.openKeep(name="tan") as tan:
        assert isinstance(red, keeping.Keeper)
        assert red.name == "red"
        assert red.env.path() == red.path
        assert os.path.exists(red.path)
        assert red.opened

        assert isinstance(tan, keeping.Keeper)
        assert tan.name == "tan"
        assert tan.env.path() == tan.path
        assert os.path.exists(tan.path)
        assert tan.opened

    assert not os.path.exists(red.path)
    assert not red.opened
    assert not os.path.exists(tan.path)
    assert not tan.opened

    """ End Test """

def test_keeper():
    """
    Test Keeper creation
    """
    keeper = keeping.Keeper()
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/keep/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)

    assert isinstance(keeper.prms, lmdb._Database)
    assert isinstance(keeper.keys, lmdb._Database)
    assert isinstance(keeper.dtss, lmdb._Database)


    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # test not opened on init
    keeper = keeping.Keeper(reopen=False)
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert keeper.opened == False
    assert keeper.path == None
    assert keeper.env == None

    keeper.reopen()
    assert keeper.opened
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/keep/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)

    assert isinstance(keeper.prms, lmdb._Database)
    assert isinstance(keeper.keys, lmdb._Database)
    assert isinstance(keeper.dtss, lmdb._Database)

    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened



    # Test using context manager
    with keeping.openKeep() as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "test"
        assert keeper.temp == True
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_keep_")
        assert keeper.path.endswith("_test/keri/keep/test")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)

        assert isinstance(keeper.prms, lmdb._Database)
        assert isinstance(keeper.keys, lmdb._Database)
        assert isinstance(keeper.dtss, lmdb._Database)

    assert not os.path.exists(keeper.path)

    """ End Test """


def test_keeperdoer():
    """
    KeeperDoer
    """
    keep0 = keeping.Keeper(name='test0', temp=True, reopen=False)
    assert keep0.opened == False
    assert keep0.path == None
    assert keep0.env == None

    kpDoer0 = keeping.KeeperDoer(keeper=keep0)
    assert kpDoer0.keeper == keep0
    assert kpDoer0.keeper.opened == False

    keep1 = keeping.Keeper(name='test1', temp=True, reopen=False)
    assert keep1.opened == False
    assert keep1.path == None
    assert keep1.env == None

    kpDoer1 = keeping.KeeperDoer(keeper=keep1)
    assert kpDoer1.keeper == keep1
    assert kpDoer1.keeper.opened == False

    limit = 0.25
    tock = 0.03125
    doist = doing.Doist(limit=limit, tock=tock)

    doers = [kpDoer0, kpDoer1]

    dogs = doist.ready(doers=doers)
    assert len(dogs) == 2
    assert [val[1] for val in dogs] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer._tymist == doist
        assert doer.keeper.opened
        assert "_test/keri/keep/test" in doer.keeper.path

    doist.once(dogs)
    assert doist.tyme == 0.03125  # on next cycle
    assert len(dogs) == 2
    for doer in doers:
        assert doer.keeper.opened == True

    for dog, retyme, index in dogs:
        dog.close()

    for doer in doers:
        assert doer.keeper.opened == False
        assert doer.keeper.env == None
        assert not os.path.exists(doer.keeper.path)

    #start over
    doist.tyme = 0.0
    doist.do(doers=doers)
    assert doist.tyme == limit
    for doer in doers:
        assert doer.keeper.opened == False
        assert doer.keeper.env == None
        assert not os.path.exists(doer.keeper.path)

    """End Test"""



if __name__ == "__main__":
    test_keeperdoer()
