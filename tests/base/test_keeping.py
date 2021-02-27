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

    pp = keeping.PrePrm()
    assert isinstance(pp, keeping.PrePrm)
    assert pp.pidx == 0
    assert pp.algo == keeping.Algos.salty == 'salty'
    assert pp.stem == ''
    assert pp.salt == ''
    assert pp.tier == ''
    assert asdict(pp) == dict(pidx=0,
                              algo=keeping.Algos.salty,
                              salt='',
                              stem='',
                              tier='',
                              )
    pp = helping.datify(keeping.PrePrm, dict(pidx=0,
                                             algo=keeping.Algos.salty,
                                             salt='',
                                             stem='',
                                             tier='',
                                          ))

    assert isinstance(pp, keeping.PrePrm)
    assert pp.pidx == 0
    assert pp.algo == keeping.Algos.salty == 'salty'
    assert pp.stem == ''
    assert pp.salt == ''
    assert pp.tier == ''

    pp = keeping.PrePrm(pidx=1, algo=keeping.Algos.randy)
    assert pp.pidx == 1
    assert pp.algo == keeping.Algos.randy
    assert pp.salt == ''
    assert pp.stem == ''
    assert pp.tier == ''

    ps = keeping.PreSit()
    assert isinstance(ps, keeping.PreSit)
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
    assert asdict(ps) == dict(
                              old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                              )
    ps = helping.datify(keeping.PreSit, dict(
                                             old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             new=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                             nxt=dict(pubs=[], ridx=0, kidx=0, dt=''),
                                          ))

    assert isinstance(ps, keeping.PreSit)
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

    ps = keeping.PreSit(old=old, new=new, nxt=nxt)
    assert ps.old.ridx == 0
    assert ps.old.kidx == 0
    assert ps.new.ridx == 1
    assert ps.new.kidx == 3
    assert ps.nxt.ridx == 2
    assert ps.nxt.kidx == 6

    """End Test"""


def test_key_funcs():
    """
    Test key utility functions
    """
    pre = 'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    preb = b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    ri = 3

    assert keeping.riKey(pre, ri) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')
    assert keeping.riKey(preb, ri) == (b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                        b'.00000000000000000000000000000003')

    with pytest.raises(TypeError):
        keeping.riKey(pre, sn='3')

    """Done Test"""


def test_openkeeper():
    """
    test contextmanager decorator for test Keeper databases
    """
    with keeping.openKS() as keeper:
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

    with keeping.openKS(name="blue") as keeper:
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

    with keeping.openKS(name="red") as red, keeping.openKS(name="tan") as tan:
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

    assert isinstance(keeper.gbls, lmdb._Database)
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

    assert isinstance(keeper.gbls, lmdb._Database)
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

    assert isinstance(keeper.gbls, lmdb._Database)
    assert isinstance(keeper.pris, lmdb._Database)
    assert isinstance(keeper.sits, lmdb._Database)

    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # Test using context manager
    with keeping.openKS() as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "test"
        assert keeper.temp == True
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_keep_")
        assert keeper.path.endswith("_test/keri/keep/test")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)

        assert isinstance(keeper.gbls, lmdb._Database)
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

        #  test .gbls sub db methods
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

        key = b'tier'
        assert keeper.getPri(key) == None
        assert keeper.delPri(key) == False
        assert keeper.putPri(key, val=coring.Tiers.low) == True
        assert keeper.getPri(key) == coring.Tiers.low.encode("utf-8")
        assert keeper.putPri(key, val=coring.Tiers.med) == False
        assert keeper.getPri(key) == coring.Tiers.low.encode("utf-8")
        assert keeper.setPri(key, val=coring.Tiers.med) == True
        assert keeper.getPri(key) == coring.Tiers.med.encode("utf-8")
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

        #  test .pres sub db methods
        key = puba
        assert keeper.getPre(key) == None
        assert keeper.delPre(key) == False
        assert keeper.putPre(key, val=prea) == True
        assert keeper.getPre(key) == prea
        assert keeper.putPre(key, val=preb) == False
        assert keeper.getPre(key) == prea
        assert keeper.setPre(key, val=preb) == True
        assert keeper.getPre(key) == preb
        assert keeper.delPre(key) == True
        assert keeper.getPre(key) == None

        #  test .prms sub db methods
        key = prea
        prma = json.dumps(
                    dict(pidx=0,
                         algo='salty',
                         salt=salta.decode("utf-8"),
                         stem='',
                         tier='low',
                    )).encode("utf-8")
        prmb = json.dumps(
                    dict(pidx=1,
                         algo='randy',
                         salt='',
                         stem='',
                         level='',
                    )).encode("utf-8")
        assert keeper.getPrm(key) == None
        assert keeper.delPrm(key) == False
        assert keeper.putPrm(key, val=prma) == True
        assert keeper.getPrm(key) == prma
        assert keeper.putPrm(key, val=prmb) == False
        assert keeper.getPrm(key) == prma
        assert keeper.setPrm(key, val=prmb) == True
        assert keeper.getPrm(key) == prmb
        assert keeper.delPrm(key) == True
        assert keeper.getPrm(key) == None


        #  test .sits sub db methods
        key = prea
        sita = json.dumps(
                    dict(
                         old=dict(pubs=[], ridx=0, kidx=0, dt=''),
                         new=dict(pubs=[puba.decode("utf-8")], ridx=1, kidx=1, dt=helping.nowIso8601()),
                         nxt=dict(pubs=[pubb.decode("utf-8")], ridx=2, kidx=2, dt=helping.nowIso8601())
                    )).encode("utf-8")
        sitb = json.dumps(
                    dict(
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

        #  test .pubs sub db methods
        key0 = keeping.riKey(prea, 0)
        pubs1 = [puba.decode("utf-8"), pubb.decode("utf-8")]
        pubs2 = [pubc.decode("utf-8")]
        spubs1 = json.dumps(pubs1).encode("utf-8")
        assert spubs1 == (b'["DGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4", '
                          b'"DoXvbGv9IPb0foWTZvI_4GAPkzNZMtX-QiVgbRbyAIZG"]')
        spubs2 = json.dumps(pubs2).encode("utf-8")
        assert spubs2 == b'["DAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4G"]'
        assert keeper.getPubs(key0) == None
        assert keeper.delPubs(key0) == False
        assert keeper.putPubs(key0, val=spubs1) == True
        assert keeper.getPubs(key0) == spubs1
        assert keeper.putPubs(key0, val=spubs2) == False
        assert keeper.getPubs(key0) == spubs1
        assert keeper.setPubs(key0, val=spubs2) == True
        assert keeper.getPubs(key0) == spubs2
        assert keeper.delPubs(key0) == True
        assert keeper.getPubs(key0) == None


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
    assert creator.salt == ''
    assert creator.stem == ''
    assert creator.tier == ''

    creator = keeping.RandyCreator()
    assert isinstance(creator, keeping.RandyCreator)
    assert isinstance(creator, keeping.Creator)
    assert creator.salt == ''
    assert creator.stem == ''
    assert creator.tier == ''
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.MtrDex.Ed25519_Seed
    assert signer.verfer.code == coring.MtrDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.MtrDex.Ed25519_Seed
        assert signer.verfer.code == coring.MtrDex.Ed25519N
        assert signer.verfer.code in coring.CryNonTransDex

    creator = keeping.SaltyCreator()
    assert isinstance(creator, keeping.SaltyCreator)
    assert isinstance(creator, keeping.Creator)
    assert isinstance(creator.salter, coring.Salter)
    assert creator.salter.code == coring.MtrDex.Salt_128
    assert creator.salt == creator.salter.qb64
    assert creator.stem == ''
    assert creator.tier == creator.salter.tier
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.MtrDex.Ed25519_Seed
    assert signer.verfer.code == coring.MtrDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.MtrDex.Ed25519_Seed
        assert signer.verfer.code == coring.MtrDex.Ed25519N
        assert signer.verfer.code in coring.CryNonTransDex

    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64
    assert salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    creator = keeping.SaltyCreator(salt=salt)
    assert isinstance(creator, keeping.SaltyCreator)
    assert isinstance(creator, keeping.Creator)
    assert isinstance(creator.salter, coring.Salter)
    assert creator.salter.code == coring.MtrDex.Salt_128
    assert creator.salter.raw == raw
    assert creator.salter.qb64 == salt
    signers = creator.create()
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.MtrDex.Ed25519_Seed
    assert signer.qb64 == 'A8wl7SXA6nCdf0-S9fWaHbq-XMZiXpFaBYZyVzwIBAn0'
    assert signer.verfer.code == coring.MtrDex.Ed25519
    assert signer.verfer.code not in coring.CryNonTransDex
    assert signer.verfer.qb64 == 'DxnLqpuCcrO8ITn3i1DhI-zqkgQJdNhAEfsGQLiE1jcQ'

    signers = creator.create(count=1, transferable=False, temp=True)
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.MtrDex.Ed25519_Seed
    assert signer.qb64 == 'AwasAzSejEulG1472bEZP7LNhKsoXAky40jgqWZKTbp4'
    assert signer.verfer.code == coring.MtrDex.Ed25519N
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
    stem = "red"

    assert salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'

    ser = bytes(b'{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                    b'70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                    b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz'
                    b'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA'
                    b'ApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOv'
                    b'VjHpdZlty3Hgk6ilF8pVpAQ')

    with keeping.openKS() as keeper:
        manager = keeping.Manager(keeper=keeper, salt=salt)
        assert manager.keeper.opened
        assert manager._pidx == 0
        assert manager._salt == ''  # zeroed out
        assert manager._tier == coring.Tiers.low

        # salty algorithm incept
        verfers, digers = manager.incept(salt=salt, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.getPidx() == 1

        spre = verfers[0].qb64b
        assert spre == b'DVG3IcCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxM'

        pp = json.loads(bytes(manager.keeper.getPrm(key=spre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
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
        assert keys == ps.new.pubs

        # test .pubs db
        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.new.ridx))).decode("utf-8"))
        assert pl == ps.new.pubs

        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.nxt.ridx))).decode("utf-8"))
        assert pl == ps.nxt.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['E8UYvbKn7KYw9e4F2DR-iduGtdA1o16ePAYjpyCYSeYo']

        oldspre = spre
        spre = b'DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc'
        manager.move(old=oldspre, new=spre)

        # test .pubs db after move
        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.new.ridx))).decode("utf-8"))
        assert pl == ps.new.pubs

        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.nxt.ridx))).decode("utf-8"))
        assert pl == ps.nxt.pubs

        psigers = manager.sign(ser=ser, pubs=ps.new.pubs)
        for siger in psigers:
            assert isinstance(siger, coring.Siger)
        vsigers = manager.sign(ser=ser, verfers=verfers)
        psigs = [siger.qb64 for siger in psigers]
        vsigs = [siger.qb64 for siger in vsigers]
        assert psigs == vsigs
        assert psigs == ['AAGu9G-EJ0zrRjrDKnHszLVcwhbkSRxniDJFmB2eWcRiFzNFw1QM5GHQnmnXz385SgunZH4sLidCMyzhJWmp1IBw']

        pcigars = manager.sign(ser=ser, pubs=ps.new.pubs, indexed=False)
        for cigar in pcigars:
            assert isinstance(cigar, coring.Cigar)
        vcigars = manager.sign(ser=ser, verfers=verfers, indexed=False)
        psigs = [cigar.qb64 for cigar in pcigars]
        vsigs = [cigar.qb64 for cigar in vcigars]
        assert psigs == vsigs
        assert psigs == ['0BGu9G-EJ0zrRjrDKnHszLVcwhbkSRxniDJFmB2eWcRiFzNFw1QM5GHQnmnXz385SgunZH4sLidCMyzhJWmp1IBw']

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        assert len(verfers) == 1
        assert len(digers) == 1

        pp = json.loads(bytes(manager.keeper.getPrm(key=spre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
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
        assert keys == ps.new.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EJUzDm_HbdIZDp94OlIoZH1gcaSdWLZhJwqKz2rVJZrc']

        assert oldpubs == ps.old.pubs

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        deadpubs = ps.old.pubs

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        pp = json.loads(bytes(manager.keeper.getPrm(key=spre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 0

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)

        assert oldpubs == ps.old.pubs

        for pub in deadpubs:
            assert not manager.keeper.getPri(key=pub.encode("utf-8"))

        # test .pubs db
        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.new.ridx))).decode("utf-8"))
        assert pl == ps.new.pubs

        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(spre, ps.nxt.ridx))).decode("utf-8"))
        assert pl == ps.nxt.pubs

        # salty algorithm rotate to null

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"), count=0)

        pp = json.loads(bytes(manager.keeper.getPrm(key=spre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 0

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)

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

        pp = json.loads(bytes(manager.keeper.getPrm(key=rpre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 1
        assert pp.algo == keeping.Algos.randy
        assert pp.salt == ''
        assert pp.stem == ''
        assert pp.tier == ''

        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        for key in keys:
            val = bytes(manager.keeper.getPri(key.encode("utf-8")))

        digs = [diger.qb64 for diger in  digers]
        assert len(digs) == 1

        oldrpre = rpre
        rpre = b'DMqxMVG3IcCNK4lpFfCu5o5cxzv1lgpMM-9rfkY3XVUc'
        manager.move(old=oldrpre, new=rpre)

        # randy algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]

        verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))

        pp = json.loads(bytes(manager.keeper.getPrm(key=rpre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 1

        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)

        assert oldpubs == ps.old.pubs

        # randy algo incept with null nxt
        verfers, digers = manager.incept(algo=keeping.Algos.randy, ncount=0)
        assert manager.getPidx() == 3
        rpre = verfers[0].qb64b

        pp = json.loads(bytes(manager.keeper.getPrm(key=rpre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 2

        ps = json.loads(bytes(manager.keeper.getSit(key=rpre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)

        assert digers == []
        assert ps.nxt.pubs == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))

        # salty algorithm incept with stem
        verfers, digers = manager.incept(salt=salt, stem=stem, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.getPidx() == 4

        spre = verfers[0].qb64b
        assert spre == b'D627iBfehzh966wPzBYjKQuGOSmIkdcR7b14nZv_ULIw'

        pp = json.loads(bytes(manager.keeper.getPrm(key=spre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 3
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == stem == 'red'
        assert pp.tier == coring.Tiers.low

        ps = json.loads(bytes(manager.keeper.getSit(key=spre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['D627iBfehzh966wPzBYjKQuGOSmIkdcR7b14nZv_ULIw']
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DHNnq96NI0Bmle_VINGcgX8_VSpxbl3am7ZT6_66Fe8Q']
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EAQ7QvfBLj0OrGTqzJZGutLJowUht_zBA6213agRQ8hA']


        #  attempt to reincept same first pub
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.incept(salt=salt, stem=stem, temp=True)
        assert ex.value.args[0].startswith('Already incepted pre')

        oldspre = spre
        spre = b'DCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxMVG3Ic'
        manager.move(old=oldspre, new=spre)

        #  attempt to reincept same first pub after move pre
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.incept(salt=salt, stem=stem, temp=True)
        assert ex.value.args[0].startswith('Already incepted pre')

        # Create nontransferable keys that are nontransferable identifier prefixes
        verfers, digers = manager.incept(ncount=0, salt=salt, stem="wit0",
                                         transferable=False, temp=True)
        wit0pre = verfers[0].qb64
        assert verfers[0].qb64 == 'B5M0jhHM3vTo15w12pOUYRwxJNaIVS96wSqbFZH-inyc'
        assert verfers[0].code == coring.MtrDex.Ed25519N
        assert not digers

        verfers, digers = manager.incept(ncount=0, salt=salt, stem="wit1",
                                         transferable=False, temp=True)
        wit1pre = verfers[0].qb64
        assert verfers[0].qb64 == 'BAH_nE1cfiGjEMK0Ac8U8N51npjBOjyZt3D-_QA4c4y0'
        assert verfers[0].code == coring.MtrDex.Ed25519N
        assert not digers

        assert wit0pre != wit1pre

        # test .ingest of sequences of keys
        secrecies = [
                        ['ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc'],
                        ['A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q'],
                        ['AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y'],
                        ['Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8'],
                        ['A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E'],
                        ['AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc'],
                        ['AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw'],
                        ['ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'],
                    ]

        pidx, rsalt, rtier = manager.setup()   #  verify current state
        assert pidx == 6
        assert rsalt == salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
        assert rtier == coring.Tiers.low
        verferies, digers = manager.ingest(secrecies=secrecies)
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'],
                                ['DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI'],
                                ['DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8'],
                                ['DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ'],
                                ['D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU'],
                                ['D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM'],
                                ['DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4'],
                                ['DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg']
                            ]

        ipre = publicies[0][0]

        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = bytes(manager.keeper.getPri(key=pubs[0]))
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                pri = bytes(manager.keeper.getPri(key=pub))
                assert pri

        pp = json.loads(bytes(manager.keeper.getPrm(key=ipre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 6

        assert manager.getPidx() == 7

        ps = json.loads(bytes(manager.keeper.getSit(key=ipre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
        assert ps.new.ridx == 7
        assert ps.new.pubs == publicies[ps.new.ridx]

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(ipre, i))).decode("utf-8"))
            assert pl == pubs

        #  nxt pubs
        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(ipre, i+1))).decode("utf-8"))
        assert pl

        assert [diger.qb64 for diger in digers] == ['Ewt_7B0gfSE7DnMtmNEHiy8BGPVw5at2-e_JgJ1jAfEc']

        for i in range(len(publicies)):
            verfers, digers = manager.replay(ipre, i)
            assert verfers[0].qb64 == publicies[i][0]
            assert digers

        # test .ingest multi-sig of sequences of keys
        secrecies = [
                        [
                            'AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                            'AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                            'AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM'
                        ],
                        [
                            'AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs'
                        ],
                        [
                            'Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                            'Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                            'AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc'
                        ],
                        [
                            'ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s'
                        ]
                    ]

        pidx, rsalt, rtier = manager.setup()   #  verify current state
        assert pidx == 7
        assert rsalt == salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
        assert rtier == coring.Tiers.low
        verferies, digers = manager.ingest(secrecies=secrecies, ncount=3)
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                [
                                    'D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc',
                                    'DbWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI',
                                    'Dmis7BM1brr-1r4DgdO5KMcCf8AnGcUUPhZYUxprI97s'
                                ],
                                [
                                    'DfHMsSg0CJCou4erOqaJDr3OyDEikBp5QRp7HjcJGdgw'
                                ],
                                [
                                    'DOaXCkU3Qd0oBSYxGfYtJxUbN6U7VjZiKthPHIHbzabs',
                                    'DLOmEabR-cYJLMrAd0HvQC4lecbF-j2r7w3UQIY3mGMQ',
                                    'DAIyL2yT9nU6kChGXWce8d6q07l0vBLPNImw_f9bazeQ'
                                ],
                                [
                                    'D69EflciVP9zgsihNU14Dbm2bPXoNGxKHK_BBVFMQ-YU'
                                ]
                            ]

        ipre = publicies[0][0]

        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = bytes(manager.keeper.getPri(key=pubs[0]))
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                pri = bytes(manager.keeper.getPri(key=pub))
                assert pri

        pp = json.loads(bytes(manager.keeper.getPrm(key=ipre)).decode("utf-8"))
        pp = helping.datify(keeping.PrePrm, pp)
        assert pp.pidx == 7

        assert manager.getPidx() == 8

        ps = json.loads(bytes(manager.keeper.getSit(key=ipre)).decode("utf-8"))
        ps = helping.datify(keeping.PreSit, ps)
        assert ps.new.ridx == 3
        assert ps.new.kidx == 7
        assert ps.new.pubs == publicies[ps.new.ridx]

        assert len(ps.nxt.pubs) == 3

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(ipre, i))).decode("utf-8"))
            assert pl == pubs

        #  nxt pubs
        pl = json.loads(bytes(manager.keeper.getPubs(key=keeping.riKey(ipre, i+1))).decode("utf-8"))
        assert pl

        assert [diger.qb64 for diger in digers] == ['E7Ch-T3dCZZ_i0u1ACi_Yv1lyyAMoQCT5ar81eUGoPYY',
                                                    'EhwPuWbyrJRyU5HpJaoJrq04biTLWx3heNY3TvQrlbU8',
                                                    'EJKLXis7QLnodqvtkbkTUKdciTuM-yzhEPUzS9jtxS6Y']

        for i in range(len(publicies)):
            verfers, digers = manager.replay(ipre, i)
            assert verfers[0].qb64 == publicies[i][0]
            assert digers

    assert not os.path.exists(manager.keeper.path)
    assert not manager.keeper.opened
    """End Test"""


if __name__ == "__main__":
    test_manager()
