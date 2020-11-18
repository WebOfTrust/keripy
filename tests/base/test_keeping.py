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
from keri.core import coring
from keri.base import keeping


def test_publot_pubsit():
    """
    test key set tracking and creation parameters
    """
    pre = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    pub = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    pri = b'AaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
    seed = '0AZxWJGkCkpDcHuVG4GM1KVw'

    pl = keeping.PubLot()
    assert isinstance(pl, keeping.PubLot)
    assert pl.pubs == []
    assert pl.ridx == 0
    assert pl.kidx == 0
    assert pl.dt == ''

    assert asdict(pl) == dict(pubs=[], ridx=0, kidx=0, dt='')
    pl = helping.datify(keeping.PubLot, dict(pubs=[], ridx=0, kidx=0, dt=''))
    assert pl.pubs == []
    assert pl.ridx == 0
    assert pl.kidx == 0
    assert pl.dt == ''

    # dt = helping.nowIso8601()
    dt = '2020-11-16T22:30:34.812526+00:00'
    pl = keeping.PubLot(pubs=[], ridx=1, kidx=3, dt=dt)
    assert pl.pubs == []
    assert pl.ridx == 1
    assert pl.kidx == 3
    assert pl.dt == dt


    ps = keeping.PubSit()
    assert isinstance(ps, keeping.PubSit)
    assert ps.pidx == 0
    assert ps.algo == keeping.Algos.salty == 'salty'
    assert ps.salt == ''
    assert ps.level == coring.SecLevels.low
    assert isinstance(ps.old, keeping.PubLot)
    assert isinstance(ps.new, keeping.PubLot)
    assert isinstance(ps.nxt, keeping.PubLot)
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
    assert asdict(ps) == dict(pidx=0,
                              algo=keeping.Algos.salty,
                              salt='',
                              level=coring.SecLevels.low,
                              old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              )
    ps = helping.datify(keeping.PubSit, dict(pidx=0,
                                             algo=keeping.Algos.salty,
                                             salt='',
                                             level=coring.SecLevels.low,
                                             old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                          ))

    assert isinstance(ps, keeping.PubSit)
    assert ps.pidx == 0
    assert ps.algo == keeping.Algos.salty == 'salty'
    assert ps.salt == ''
    assert ps.level == coring.SecLevels.low
    assert isinstance(ps.old, keeping.PubLot)
    assert isinstance(ps.new, keeping.PubLot)
    assert isinstance(ps.nxt, keeping.PubLot)
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

    old = keeping.PubLot(ridx=0, kidx=0)
    new = keeping.PubLot(ridx=1, kidx=3)
    nxt = keeping.PubLot(ridx=2, kidx=6)
    ps = keeping.PubSit(pidx=1, algo=keeping.Algos.randy, old=old, new=new, nxt=nxt)
    assert ps.pidx == 1
    assert ps.algo == keeping.Algos.randy
    assert ps.salt == ''
    assert ps.level == coring.SecLevels.low
    assert ps.old.ridx == 0
    assert ps.old.kidx == 0
    assert ps.new.ridx == 1
    assert ps.new.kidx == 3
    assert ps.nxt.ridx == 2
    assert ps.nxt.kidx == 6

    """End Test"""


def test_openkeeper():
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

    assert isinstance(keeper.prms, lmdb._Database)
    assert isinstance(keeper.pris, lmdb._Database)
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

    assert isinstance(keeper.prms, lmdb._Database)
    assert isinstance(keeper.pris, lmdb._Database)
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

    assert isinstance(keeper.prms, lmdb._Database)
    assert isinstance(keeper.pris, lmdb._Database)
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

        assert isinstance(keeper.prms, lmdb._Database)
        assert isinstance(keeper.pris, lmdb._Database)
        assert isinstance(keeper.sits, lmdb._Database)

        salta = b'0AZxWJGkCkpDcHuVG4GM1KVw'
        saltb = b'0AHuVG4GM1KVwZxWJGkCkpDc'
        pria = b'AaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
        prib = b'AE2yPgBXiP6h_J2cZeCy4MaOa6eOCJQcgEozYb1GgV9z'
        puba = b'DGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
        pubb = b'DoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-QiVgbRbyAIZG'
        pubc = b'DAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4G'
        prea = b'EWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
        preb = b'EQPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gz'

        #  test .prms sub db methods
        key = b'pidx'
        pidxa = b'%x' % 0  # "{:x}".format(pidx).encode("utf-8")
        pidxb = b'%x' % 1  # "{:x}".format(pidx).encode("utf-8"
        assert keeper.getPri(key) == None
        assert keeper.delPri(key) == False
        assert keeper.putPri(key, val=pidxa) == True
        assert keeper.getPri(key) == pidxa
        assert keeper.putPri(key, val=pidxb) == False
        assert keeper.getPri(key) == pidxa
        assert keeper.setPri(key, val=pidxb) == True
        assert keeper.getPri(key) == pidxb
        assert keeper.delPri(key) == True
        assert keeper.getPri(key) == None

        key = b'salt'
        assert keeper.getPri(key) == None
        assert keeper.delPri(key) == False
        assert keeper.putPri(key, val=salta) == True
        assert keeper.getPri(key) == salta
        assert keeper.putPri(key, val=saltb) == False
        assert keeper.getPri(key) == salta
        assert keeper.setPri(key, val=saltb) == True
        assert keeper.getPri(key) == saltb
        assert keeper.delPri(key) == True
        assert keeper.getPri(key) == None

        #  test .pris sub db methods
        key = puba
        assert keeper.getPri(key) == None
        assert keeper.delPri(key) == False
        assert keeper.putPri(key, val=pria) == True
        assert keeper.getPri(key) == pria
        assert keeper.putPri(key, val=prib) == False
        assert keeper.getPri(key) == pria
        assert keeper.setPri(key, val=prib) == True
        assert keeper.getPri(key) == prib
        assert keeper.delPri(key) == True
        assert keeper.getPri(key) == None

        #  test .sits sub db methods
        key = prea
        sita = json.dumps(
                    dict(algo='index',
                         salt=salta.decode("utf-8"),
                         level='low',
                         old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                         new=dict(pubs=[puba.decode("utf-8")], ridx=1, kidx=1, dt=helping.nowIso8601()),
                         nxt=dict(pubs=[pubb.decode("utf-8")], ridx=2, kidx=2, dt=helping.nowIso8601())
                    )).encode("utf-8")
        sitb = json.dumps(
                    dict(algo='randy',
                         salt='',
                         level='low',
                         old=dict(pubs=[puba.decode("utf-8")], ridx=0, kidx=0, dt=helping.nowIso8601()),
                         new=dict(pubs=[pubb.decode("utf-8")], ridx=1, kidx=1, dt=helping.nowIso8601()),
                         nxt=dict(pubs=[pubc.decode("utf-8")], ridx=2, kidx=2, dt=helping.nowIso8601())
                    )).encode("utf-8")
        assert keeper.getSit(key) == None
        assert keeper.delSit(key) == False
        assert keeper.putSit(key, val=sita) == True
        assert keeper.getSit(key) == sita
        assert keeper.putSit(key, val=sitb) == False
        assert keeper.getSit(key) == sita
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

def test_creator():
    """
    test Creator and Creatory classes
    """
    creator = keeping.Creator()
    assert isinstance(creator, keeping.Creator)
    assert creator.create() == []

    creator = keeping.RandyCreator()
    assert isinstance(creator, keeping.RandyCreator)
    assert isinstance(creator, keeping.Creator)
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.CryOneDex.Ed25519_Seed
    assert signer.verfer.code == coring.CryOneDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.CryOneDex.Ed25519_Seed
        assert signer.verfer.code == coring.CryOneDex.Ed25519N
        assert signer.verfer.code in coring.CryNonTransDex

    creator = keeping.SaltyCreator()
    assert isinstance(creator, keeping.SaltyCreator)
    assert isinstance(creator, keeping.Creator)
    assert isinstance(creator.salter, coring.Salter)
    assert creator.salter.code == coring.CryTwoDex.Salt_128
    assert creator.salt == creator.salter.qb64
    assert creator.level == creator.salter.level
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.CryOneDex.Ed25519_Seed
    assert signer.verfer.code == coring.CryOneDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.CryOneDex.Ed25519_Seed
        assert signer.verfer.code == coring.CryOneDex.Ed25519N
        assert signer.verfer.code in coring.CryNonTransDex

    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64
    assert salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    creator = keeping.SaltyCreator(salt=salt)
    assert isinstance(creator, keeping.SaltyCreator)
    assert isinstance(creator, keeping.Creator)
    assert isinstance(creator.salter, coring.Salter)
    assert creator.salter.code == coring.CryTwoDex.Salt_128
    assert creator.salter.raw == raw
    assert creator.salter.qb64 == salt
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.CryOneDex.Ed25519_Seed
    assert signer.qb64 == 'A8wl7SXA6nCdf0-S9fWaHbq-XMZiXpFaBYZyVzwIBAn0'
    assert signer.verfer.code == coring.CryOneDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex
    assert signer.verfer.qb64 == 'DxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ'

    signers = creator.create(count=1, transferable=False, temp=True)
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.CryOneDex.Ed25519_Seed
    assert signer.qb64 == 'AwasAzSejEulG1472bEZP7LNhKsoXAky40jgqWZKTbp4'
    assert signer.verfer.code == coring.CryOneDex.Ed25519N
    assert signer.verfer.code in coring.CryNonTransDex
    assert signer.verfer.qb64 == 'BVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM'

    creator = keeping.Creatory(algo=keeping.Algos.salty).make(salt=salt)
    assert isinstance(creator, keeping.SaltyCreator)
    assert creator.salter.qb64 == salt

    creator = keeping.Creatory(algo=keeping.Algos.randy).make()
    assert isinstance(creator, keeping.RandyCreator)
    """End Test"""


def test_manager():
    """
    test Manager class
    """
    manager = keeping.Manager()
    assert isinstance(manager, keeping.Manager)
    assert isinstance(manager.keeper, keeping.Keeper)
    assert manager.keeper.opened

    manager.keeper.close(clear=True)
    assert not os.path.exists(manager.keeper.path)
    assert not manager.keeper.opened

    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64
    assert salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    with keeping.openKeeper() as keeper:
        manager = keeping.Manager(keeper=keeper, salt=salt)
        assert manager.keeper.opened
        assert manager.signers == {}
        assert manager._pidx == 0
        assert manager._salt == salt

        # salty algorithm incept
        verfers, digers = manager.incept(salt=salt, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.getPidx() == 1

        spre = verfers[0].qb64b
        assert spre == b'DVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM'

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)
        assert ps.algo == keeping.Algos.salty
        assert ps.salt == salt
        assert ps.level == coring.SecLevels.low
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM']
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DcHJWO4GszUP0rvVO4Tl2rUdUM1Ln5osP7BwiUeJWhdc']
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ['DVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM']
        for key in keys:
            assert key in manager.signers
            assert manager.signers[key].verfer.qb64 == key
            val = bytes(manager.keeper.getPri(key.encode("utf-8")))
            assert val == manager.signers[key].qb64b

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['E8UYvbKn7KYw9e4F2DR-iduGtdA1o16ePAYjpyCYSeYo']

        oldspre = spre
        spre = b'DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc'
        manager.repre(old=oldspre, new=spre)

        #  attempt to reincept same pre
        #with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            #verfers, digers = manager.incept(salt=salt, temp=True)
        #assert ex.value.args[0].startswith('Already incepted pre')


        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        assert len(verfers) == 1
        assert len(digers) == 1

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)
        assert ps.algo == keeping.Algos.salty
        assert ps.salt == salt
        assert ps.level == coring.SecLevels.low
        assert ps.old.pubs == ['DVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM']
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DcHJWO4GszUP0rvVO4Tl2rUdUM1Ln5osP7BwiUeJWhdc']
        assert ps.new.ridx == 1
        assert ps.new.kidx == 1
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DRpGly44ejh01ur4ltL_LVrYcyqVCQyVLJnqWrVa57Yc']
        assert ps.nxt.ridx == 2
        assert ps.nxt.kidx == 2

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ['DcHJWO4GszUP0rvVO4Tl2rUdUM1Ln5osP7BwiUeJWhdc']
        for key in keys:
            assert key in manager.signers
            assert manager.signers[key].verfer.qb64 == key
            val = bytes(manager.keeper.getPri(key.encode("utf-8")))
            assert val == manager.signers[key].qb64b

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EJUzDm_HbdIZDp94OlIoZH1gcaSdWLZhJwqKz2rVJZrc']

        assert oldpubs == ps.old.pubs

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        deadpubs = ps.old.pubs

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)

        assert oldpubs == ps.old.pubs

        for pub in deadpubs:
            assert pub not in manager.signers
            assert not manager.keeper.getPri(key=pub.encode("utf-8"))

        # salty algorithm rotate to null

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"), count=0)

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)

        assert digers == []
        assert ps.nxt.pubs == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=spre.decode("utf-8"))
        assert ex.value.args[0].startswith('Attempt to rotate nontransferable ')

        # randy algo incept
        verfers, digers = manager.incept(algo=keeping.Algos.randy)
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.getPidx() == 2
        rpre = verfers[0].qb64b

        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)
        assert ps.algo == keeping.Algos.randy
        assert ps.salt == salt
        assert ps.level == coring.SecLevels.low
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        for key in keys:
            assert key in manager.signers
            assert manager.signers[key].verfer.qb64 == key
            val = bytes(manager.keeper.getPri(key.encode("utf-8")))
            assert val == manager.signers[key].qb64b

        digs = [diger.qb64 for diger in  digers]
        assert len(digs) == 1

        oldrpre = rpre
        rpre = b'DMqxMVG3IcCNK4lpFfCu5o5cxzv1lgpMM-9rfkY3XVUc'
        manager.repre(old=oldrpre, new=rpre)

        # randy algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]

        verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))

        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)

        assert oldpubs == ps.old.pubs

        # randy algo incept with null nxt
        verfers, digers = manager.incept(algo=keeping.Algos.randy, ncount=0)
        assert manager.getPidx() == 3
        rpre = verfers[0].qb64b
        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PubSit, ps)

        assert digers == []
        assert ps.nxt.pubs == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))



    assert not os.path.exists(manager.keeper.path)
    assert not manager.keeper.opened
    """End Test"""


if __name__ == "__main__":
    test_manager()
