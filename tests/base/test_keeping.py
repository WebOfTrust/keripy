# -*- encoding: utf-8 -*-
"""
tests.base.keeping module

"""
import pytest

import os
import stat
import json
from dataclasses import asdict

import lmdb

from hio.base import doing

from keri.help import helping
from keri.base import keeping
from keri.core import coring


def test_publot_pubsit():
    """
    test key set tracking and creation parameters
    """
    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    pub = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    pri = b'AaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
    seed = '0AZxWJGkCkpDcHuVG4GM1KVw'

    pl = keeping.Publot()
    assert isinstance(pl, keeping.Publot)
    assert pl.pubs == []
    assert pl.ridx == 0
    assert pl.kidx == 0
    assert pl.dt == ''

    assert asdict(pl) == dict(pubs=[], ridx=0, kidx=0, dt='')
    pl = helping.datify(keeping.Publot, dict(pubs=[], ridx=0, kidx=0, dt=''))
    assert pl.pubs == []
    assert pl.ridx == 0
    assert pl.kidx == 0
    assert pl.dt == ''

    ps = keeping.Pubsit()
    assert isinstance(ps, keeping.Pubsit)
    assert ps.salt == ''
    assert ps.level == coring.SecLevels.low
    assert ps.algo == keeping.Algos.index == 'index'
    assert isinstance(ps.old, keeping.Publot)
    assert isinstance(ps.new, keeping.Publot)
    assert isinstance(ps.nxt, keeping.Publot)
    assert ps.old.pubs == []
    assert ps.old.ridx ==  0
    assert ps.old.kidx == 0
    assert ps.old.dt == ''
    assert ps.new.pubs == []
    assert ps.new.ridx ==  0
    assert ps.new.kidx == 0
    assert ps.new.dt == ''
    assert ps.nxt.pubs == []
    assert ps.nxt.ridx ==  0
    assert ps.nxt.kidx == 0
    assert ps.nxt.dt == ''
    assert asdict(ps) == dict(salt='',
                              level=coring.SecLevels.low,
                              algo=keeping.Algos.index,
                              old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              )
    ps = helping.datify(keeping.Pubsit, dict(salt='',
                                             level=coring.SecLevels.low,
                                             algo=keeping.Algos.index,
                                             old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                          ))

    assert isinstance(ps, keeping.Pubsit)
    assert ps.salt == ''
    assert ps.level == coring.SecLevels.low
    assert ps.algo == keeping.Algos.index == 'index'
    assert isinstance(ps.old, keeping.Publot)
    assert isinstance(ps.new, keeping.Publot)
    assert isinstance(ps.nxt, keeping.Publot)
    assert ps.old.pubs == []
    assert ps.old.ridx ==  0
    assert ps.old.kidx == 0
    assert ps.old.dt == ''
    assert ps.new.pubs == []
    assert ps.new.ridx ==  0
    assert ps.new.kidx == 0
    assert ps.new.dt == ''
    assert ps.nxt.pubs == []
    assert ps.nxt.ridx ==  0
    assert ps.nxt.kidx == 0
    assert ps.nxt.dt == ''
    """End Test"""


def test_openkeep():
    """
    test contextmanager decorator for test Keeper databases
    """
    with keeping.openKeeper() as keeper:
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

    with keeping.openKeeper(name="blue") as keeper:
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

    with keeping.openKeeper(name="red") as red, keeping.openKeeper(name="tan") as tan:
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

    """
    stat.S_ISVTX  is Sticky bit. When this bit is set on a directory it means
        that a file in that directory can be renamed or deleted only by the
        owner of the file, by the owner of the directory, or by a privileged process.

    stat.S_IRUSR Owner has read permission.
    stat.S_IWUSR Owner has write permission.
    stat.S_IXUSR Owner has execute permission.
    """
    dirMode = stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
    assert dirMode == 0o1700

    # set mode to sticky bit plus rwx only for owner/user
    keeper = keeping.Keeper()
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/keep/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)
    assert oct(os.stat(keeper.path).st_mode)[-4:] == "1700"
    assert keeper.DirMode == dirMode

    assert isinstance(keeper.secs, lmdb._Database)
    assert isinstance(keeper.sits, lmdb._Database)


    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # set to unrestricted mode
    keeper = keeping.Keeper(dirMode=0o775)
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/keep/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)
    assert oct(os.stat(keeper.path).st_mode)[-4:] == "0775"

    assert isinstance(keeper.secs, lmdb._Database)
    assert isinstance(keeper.sits, lmdb._Database)

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

    assert isinstance(keeper.secs, lmdb._Database)
    assert isinstance(keeper.sits, lmdb._Database)

    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # Test using context manager
    with keeping.openKeeper() as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "test"
        assert keeper.temp == True
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_keep_")
        assert keeper.path.endswith("_test/keri/keep/test")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)

        assert isinstance(keeper.secs, lmdb._Database)
        assert isinstance(keeper.sits, lmdb._Database)

        seed = b'0AZxWJGkCkpDcHuVG4GM1KVw'
        pria = b'AaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
        prib = b'AE2yPgBXiP6h_J2cZeCy4MaOa6eOCJQcgEozYb1GgV9z'
        puba = b'DGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
        pubb = b'DoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-QiVgbRbyAIZG'
        pubc = b'DAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4G'
        prea = b'EWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
        preb = b'EQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gz'

        #  test .secs sub db methods
        key = puba
        assert keeper.getSec(key) == None
        assert keeper.delSec(key) == False
        assert keeper.putSec(key, val=pria) == True
        assert keeper.getSec(key) == pria
        assert keeper.putSec(key, val=prib) == False
        assert keeper.setSec(key, val=prib) == True
        assert keeper.getSec(key) == prib
        assert keeper.delSec(key) == True
        assert keeper.getSec(key) == None

        #  test .sits sub db methods
        key = prea
        sita = json.dumps(
                    dict(salt=seed.decode("utf-8"),
                         level='low',
                         algo='index',
                         old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                         new=dict(pubs=[puba.decode("utf-8")], ridx=1, kidx=1, dt=helping.nowIso8601()),
                         nxt=dict(pubs=[pubb.decode("utf-8")], ridx=2, kidx=2, dt=helping.nowIso8601())
                    )).encode("utf-8")
        sitb = json.dumps(
                    dict(salt='',
                         level='low',
                         algo='novel',
                         old=dict(pubs=[puba.decode("utf-8")], ridx=0, kidx=0, dt=helping.nowIso8601()),
                         new=dict(pubs=[pubb.decode("utf-8")], ridx=1, kidx=1, dt=helping.nowIso8601()),
                         nxt=dict(pubs=[pubc.decode("utf-8")], ridx=2, kidx=2, dt=helping.nowIso8601())
                    )).encode("utf-8")
        assert keeper.getSit(key) == None
        assert keeper.delSit(key) == False
        assert keeper.putSit(key, val=sita) == True
        assert keeper.getSit(key) == sita
        assert keeper.putSit(key, val=sitb) == False
        assert keeper.setSit(key, val=sitb) == True
        assert keeper.getSit(key) == sitb
        assert keeper.delSit(key) == True
        assert keeper.getSit(key) == None


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
    test_publot_pubsit()
