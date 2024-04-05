# -*- encoding: utf-8 -*-
"""
tests.app.keeping module

"""
import pytest

import os
import stat
import json
from dataclasses import asdict
from math import ceil

import lmdb
import pysodium

from hio.base import doing

from keri import kering
from keri.help import helping

from keri.core import coring, indexing
from keri.core.indexing import IdrDex
from keri.app import keeping


def test_dataclasses():
    """
    test key set tracking and creation dataclasses
    """
    pre = b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc' # b'BWzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    pub = b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4' # b'EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
    pri = b'AAOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M' # b'AaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
    seed = '0ABxWJGkCkpDcHuVG4GM1KVw'

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
    assert pl.dt == dt == '2020-11-16T22:30:34.812526+00:00'

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
    assert asdict(ps) == {'old': {'pubs': [], 'ridx': 0, 'kidx': 0, 'dt': ''},
                          'new': {'pubs': [], 'ridx': 0, 'kidx': 0, 'dt': ''},
                          'nxt': {'pubs': [], 'ridx': 0, 'kidx': 0, 'dt': ''}}
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
    assert ps.nxt.ridx == 0
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

    pt = keeping.PubSet(pubs=[pre, pub])
    assert pt.pubs == [pre, pub]
    assert asdict(pt) == {"pubs": [pre, pub],}
    ptd = helping.datify(keeping.PubSet, {"pubs": [pre, pub],})
    assert isinstance(ptd, keeping.PubSet)


    """End Test"""


def test_key_funcs():
    """
    Test key utility functions
    """
    pre = 'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
    preb = pre.encode("utf-8")
    ri = 3

    assert keeping.riKey(pre, ri) == (b'BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
                                      b'.00000000000000000000000000000003')
    assert keeping.riKey(preb, ri) == keeping.riKey(pre, ri)

    with pytest.raises(TypeError):
        keeping.riKey(pre, sn='3')

    """Done Test"""


def test_openkeeper():
    """
    test contextmanager decorator for test Keeper databases
    """
    with keeping.openKS() as ks:
        assert isinstance(ks, keeping.Keeper)
        assert ks.name == "test"
        assert isinstance(ks.env, lmdb.Environment)
        assert ks.path.startswith("/tmp/keri_ks_")
        assert ks.path.endswith("_test/keri/ks/test")
        assert ks.env.path() == ks.path
        assert os.path.exists(ks.path)
        assert ks.opened

    assert not os.path.exists(ks.path)
    assert not ks.opened

    with keeping.openKS(name="blue") as ks:
        assert isinstance(ks, keeping.Keeper)
        assert ks.name == "blue"
        assert isinstance(ks.env, lmdb.Environment)
        assert ks.path.startswith("/tmp/keri_ks_")
        assert ks.path.endswith("_test/keri/ks/blue")
        assert ks.env.path() == ks.path
        assert os.path.exists(ks.path)
        assert ks.opened

    assert not os.path.exists(ks.path)
    assert not ks.opened

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
    perm = stat.S_ISVTX | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
    assert perm == 0o1700

    # set mode to sticky bit plus rwx only for owner/user
    keeper = keeping.Keeper(reopen=True)
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/ks/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)
    assert oct(os.stat(keeper.path).st_mode)[-4:] == "1700"
    assert keeper.Perm == perm

    assert isinstance(keeper.gbls.sdb, lmdb._Database)
    assert isinstance(keeper.pris.sdb, lmdb._Database)
    assert isinstance(keeper.sits.sdb, lmdb._Database)


    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # set to unrestricted mode
    keeper = keeping.Keeper(perm=0o775, reopen=True)
    assert isinstance(keeper, keeping.Keeper)
    assert keeper.name == "main"
    assert keeper.temp == False
    assert isinstance(keeper.env, lmdb.Environment)
    assert keeper.path.endswith("keri/ks/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)
    assert oct(os.stat(keeper.path).st_mode)[-4:] == "0775"

    assert isinstance(keeper.gbls.sdb, lmdb._Database)
    assert isinstance(keeper.pris.sdb, lmdb._Database)
    assert isinstance(keeper.sits.sdb, lmdb._Database)

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
    assert keeper.path.endswith("keri/ks/main")
    assert keeper.env.path() == keeper.path
    assert os.path.exists(keeper.path)

    assert isinstance(keeper.gbls.sdb, lmdb._Database)
    assert isinstance(keeper.pris.sdb, lmdb._Database)
    assert isinstance(keeper.sits.sdb, lmdb._Database)

    keeper.close(clear=True)
    assert not os.path.exists(keeper.path)
    assert not keeper.opened

    # Test using context manager
    with keeping.openKS() as keeper:
        assert isinstance(keeper, keeping.Keeper)
        assert keeper.name == "test"
        assert keeper.temp == True
        assert isinstance(keeper.env, lmdb.Environment)
        assert keeper.path.startswith("/tmp/keri_ks_")
        assert keeper.path.endswith("_test/keri/ks/test")
        assert keeper.env.path() == keeper.path
        assert os.path.exists(keeper.path)

        assert isinstance(keeper.gbls.sdb, lmdb._Database)
        assert isinstance(keeper.pris.sdb, lmdb._Database)
        assert isinstance(keeper.sits.sdb, lmdb._Database)

        salta = '0ABxWJGkCkpDcHuVG4GM1KVw'
        saltb = '0ACuVG4GM1KVwZxWJGkCkpDc'
        pria = b'AAOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4M'
        prib = b'AB2cZeCy4MaOa6eOCJQcgEozYb1GgV9zE2yPgBXiP6hA'
        puba = b'DAAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4'
        pubb = b'DBXvbGv9IPb0foWTZvI_4GAPkzNZMtX-QiVgbRbyAIZG'
        pubc = b'DCPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4G'
        pubd = 'BDE2yPgBXiP6h_J2cZeCy4MaOa6eOCJQcgEozYb1GgV9'
        pube = 'BEQcgEozYb1GgV9zE2yPgBXiP6h_J2cZeCy4MaOa6eOC'
        prea = b'EAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc'
        preb = b'EBPYGGwTmuupUhPx5_yZ-Wk1x4ejhccWzwEHHzq7K0gz'


        #  test .gbls Suber  methods
        key = b'aeid'
        assert keeper.gbls.get(key) == None
        assert keeper.gbls.rem(key) == False
        assert keeper.gbls.put(key, val=pubd) == True
        assert keeper.gbls.get(key) == pubd
        assert keeper.gbls.put(key, val=pube) == False
        assert keeper.gbls.get(key) == pubd
        assert keeper.gbls.pin(key, val=pube) == True
        assert keeper.gbls.get(key) == pube
        assert keeper.gbls.rem(key) == True
        assert keeper.gbls.get(key) == None


        key = b'pidx'
        pidxa = '%x' % 0  # "{:x}".format(pidx).encode("utf-8")
        pidxb = '%x' % 1  # "{:x}".format(pidx).encode("utf-8"
        assert keeper.gbls.get(key) == None
        assert keeper.gbls.rem(key) == False
        assert keeper.gbls.put(key, val=pidxa) == True
        assert keeper.gbls.get(key) == pidxa
        assert keeper.gbls.put(key, val=pidxb) == False
        assert keeper.gbls.get(key) == pidxa
        assert keeper.gbls.pin(key, val=pidxb) == True
        assert keeper.gbls.get(key) == pidxb
        assert keeper.gbls.rem(key) == True
        assert keeper.gbls.get(key) == None

        key = b'algo'
        algoa = keeping.Algos.salty
        algob = keeping.Algos.randy
        assert keeper.gbls.get(key) == None
        assert keeper.gbls.rem(key) == False
        assert keeper.gbls.put(key, val=algoa) == True
        assert keeper.gbls.get(key) == algoa
        assert keeper.gbls.put(key, val=algob) == False
        assert keeper.gbls.get(key) == algoa
        assert keeper.gbls.pin(key, val=algob) == True
        assert keeper.gbls.get(key) == algob
        assert keeper.gbls.rem(key) == True
        assert keeper.gbls.get(key) == None

        key = b'salt'
        assert keeper.gbls.get(key) == None
        assert keeper.gbls.rem(key) == False
        assert keeper.gbls.put(key, val=salta) == True
        assert keeper.gbls.get(key) == salta
        assert keeper.gbls.put(key, val=saltb) == False
        assert keeper.gbls.get(key) == salta
        assert keeper.gbls.pin(key, val=saltb) == True
        assert keeper.gbls.get(key) == saltb
        assert keeper.gbls.rem(key) == True
        assert keeper.gbls.get(key) == None

        key = b'tier'
        assert keeper.gbls.get(key) == None
        assert keeper.gbls.rem(key) == False
        assert keeper.gbls.put(key, val=coring.Tiers.low) == True
        assert keeper.gbls.get(key) == coring.Tiers.low
        assert keeper.gbls.put(key, val=coring.Tiers.med) == False
        assert keeper.gbls.get(key) == coring.Tiers.low
        assert keeper.gbls.pin(key, val=coring.Tiers.med) == True
        assert keeper.gbls.get(key) == coring.Tiers.med
        assert keeper.gbls.rem(key) == True
        assert keeper.gbls.get(key) == None

        #  test .pris sub db methods
        key = puba
        signera = coring.Signer(qb64b=pria)
        assert signera.qb64b == pria
        signerb = coring.Signer(qb64b=prib)
        assert signerb.qb64b == prib
        assert keeper.pris.get(key) == None
        assert keeper.pris.rem(key) == False
        assert keeper.pris.put(key, val=signera) == True
        assert keeper.pris.get(key).qb64b == pria
        assert keeper.pris.put(key, val=signerb) == False
        assert keeper.pris.get(key).qb64b == pria
        assert keeper.pris.pin(key, val=signerb) == True
        assert keeper.pris.get(key).qb64b == prib
        assert keeper.pris.rem(key) == True
        assert keeper.pris.get(key) == None

        #  test .pres sub db methods
        key = puba
        prefixera = coring.Prefixer(qb64=prea)
        prefixerb = coring.Prefixer(qb64=preb)
        assert keeper.pres.get(key) == None
        assert keeper.pres.rem(key) == False
        assert keeper.pres.put(key, val=prefixera) == True
        assert keeper.pres.get(key).qb64 == prefixera.qb64
        assert keeper.pres.put(key, val=prefixera) == False
        assert keeper.pres.get(key).qb64 == prefixera.qb64
        assert keeper.pres.pin(key, val=prefixerb) == True
        assert keeper.pres.get(key).qb64 == prefixerb.qb64
        assert keeper.pres.rem(key) == True
        assert keeper.pres.get(key) == None

        #  test .prms sub db methods
        key = prea
        prma = keeping.PrePrm(pidx=0,
                              algo='salty',
                              salt=salta,
                              stem='',
                              tier='low')

        prmb = keeping.PrePrm(pidx=1,
                              algo='randy',
                              salt='',
                              stem='',
                              tier='')

        assert keeper.prms.get(key) == None
        assert keeper.prms.rem(key) == False
        assert keeper.prms.put(key, val=prma) == True
        assert keeper.prms.get(key) == prma
        assert keeper.prms.put(key, val=prmb) == False
        assert keeper.prms.get(key) == prma
        assert keeper.prms.pin(key, val=prmb) == True
        assert keeper.prms.get(key) == prmb
        assert keeper.prms.rem(key) == True
        assert keeper.prms.get(key) == None

        #  test .sits sub db methods with pubs
        key = prea
        sita = keeping.PreSit(
                               old=keeping.PubLot(pubs=[],
                                                  ridx=0,
                                                  kidx=0,
                                                  dt=''),
                               new=keeping.PubLot(pubs=[puba.decode("utf-8")],
                                                  ridx=1,
                                                  kidx=1,
                                                  dt=helping.nowIso8601()),
                               nxt=keeping.PubLot(pubs=[pubb.decode("utf-8")],
                                                  ridx=2,
                                                  kidx=2,
                                                  dt=helping.nowIso8601()),
                             )

        sitb = keeping.PreSit(
                               old=keeping.PubLot(pubs=[puba.decode("utf-8")],
                                                  ridx=0,
                                                  kidx=0,
                                                  dt=helping.nowIso8601()),
                               new=keeping.PubLot(pubs=[puba.decode("utf-8")],
                                                  ridx=1,
                                                  kidx=1,
                                                  dt=helping.nowIso8601()),
                               nxt=keeping.PubLot(pubs=[pubb.decode("utf-8")],
                                                  ridx=2,
                                                  kidx=2,
                                                  dt=helping.nowIso8601()),
                             )

        assert keeper.sits.get(key) == None
        assert keeper.sits.rem(key) == False
        assert keeper.sits.put(key, val=sita) == True
        assert keeper.sits.get(key) == sita
        assert keeper.sits.put(key, val=sitb) == False
        assert keeper.sits.get(key) == sita
        assert keeper.sits.pin(key, val=sitb) == True
        assert keeper.sits.get(key) == sitb
        assert keeper.sits.rem(key) == True
        assert keeper.sits.get(key) == None

        #  test .pubs sub db methods
        key0 = keeping.riKey(prea, 0)
        pubs1 = [puba.decode("utf-8"), pubb.decode("utf-8")]
        pubs2 = [pubc.decode("utf-8")]
        pt1 = keeping.PubSet(pubs=pubs1)
        pt2 = keeping.PubSet(pubs=pubs2)

        assert keeper.pubs.get(key0) == None
        assert keeper.pubs.rem(key0) == False
        assert keeper.pubs.put(key0, val=pt1) == True
        assert keeper.pubs.get(key0) == pt1
        assert keeper.pubs.put(key0, val=pt2) == False
        assert keeper.pubs.get(key0) == pt1
        assert keeper.pubs.pin(key0, val=pt2) == True
        assert keeper.pubs.get(key0) == pt2
        assert keeper.pubs.rem(key0) == True
        assert keeper.pubs.get(key0) == None

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
    doist.doers = doers
    doist.enter()
    assert len(doist.deeds) == 2
    assert [val[1] for val in doist.deeds] == [0.0, 0.0]  #  retymes
    for doer in doers:
        assert doer.keeper.opened
        assert "_test/keri/ks/test" in doer.keeper.path

    doist.recur()
    assert doist.tyme == 0.03125  # on next cycle
    assert len(doist.deeds) == 2
    for doer in doers:
        assert doer.keeper.opened == True

    for dog, retyme, index in doist.deeds:
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
    assert signer.verfer.code not in coring.NonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.MtrDex.Ed25519_Seed
        assert signer.verfer.code == coring.MtrDex.Ed25519N
        assert signer.verfer.code in coring.NonTransDex

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
    assert signer.verfer.code not in coring.NonTransDex

    signers = creator.create(count=2, transferable=False)
    assert len(signers) == 2
    for signer in signers:
        assert isinstance(signer, coring.Signer)
        assert signer.code == coring.MtrDex.Ed25519_Seed
        assert signer.verfer.code == coring.MtrDex.Ed25519N
        assert signer.verfer.code in coring.NonTransDex

    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64
    assert salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
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
    assert signer.qb64 == 'APMJe0lwOpwnX9PkvX1mh26vlzGYl6RWgWGclc8CAQJ9'
    assert signer.verfer.code == coring.MtrDex.Ed25519
    assert signer.verfer.code not in coring.NonTransDex
    assert signer.verfer.qb64 == 'DMZy6qbgnKzvCE594tQ4SPs6pIECXTYQBH7BkC4hNY3E'

    signers = creator.create(count=1, transferable=False, temp=True)
    assert len(signers) == 1
    signer = signers[0]
    assert isinstance(signer, coring.Signer)
    assert signer.code == coring.MtrDex.Ed25519_Seed
    assert signer.qb64 == 'AMGrAM0noxLpRteO9mxGT-yzYSrKFwJMuNI4KlmSk26e'
    assert signer.verfer.code == coring.MtrDex.Ed25519N
    assert signer.verfer.code in coring.NonTransDex
    assert signer.verfer.qb64 == 'BFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT'

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
    manager = keeping.Manager()  # ks not provided so creates and opens ks
    assert isinstance(manager, keeping.Manager)
    assert isinstance(manager.ks, keeping.Keeper)
    assert manager.ks.opened
    assert manager.inited

    manager.ks.close(clear=True)
    assert not os.path.exists(manager.ks.path)
    assert not manager.ks.opened

    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64
    stem = "red"

    assert salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'


    # the particular serialization does not matter test purposes
    ser = bytes(b'{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                    b'70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                    b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz'
                    b'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA'
                    b'ApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOv'
                    b'VjHpdZlty3Hgk6ilF8pVpAQ')

    with keeping.openKS() as keeper:

        with pytest.raises(kering.ConversionError):
            #test invalid qb64 of Salt
            manager = keeping.Manager(ks=keeper, salt='0AzwMTIzNDU2Nzg5YWJjZGVm')

        manager = keeping.Manager(ks=keeper, salt=salt)
        assert manager.ks.opened
        assert manager.pidx == 0
        assert manager.tier == coring.Tiers.low
        assert manager.salt == salt
        assert manager.aeid == ""
        assert manager.seed == ""
        assert manager.encrypter == None
        assert manager.decrypter == None

        # salty algorithm incept
        verfers, digers = manager.incept(salt=salt, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.pidx == 1

        spre = verfers[0].qb64b
        assert spre == b'DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT'

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(spre)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT']
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX']
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        # test .pubs db
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EBhBRqVbqhhP7Ciah5pMIOdsY5Mm1ITm2Fjqb028tylu']

        oldspre = spre
        spre = b'DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc'
        manager.move(old=oldspre, new=spre)

        # test .pubs db after move
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        psigers = manager.sign(ser=ser, pubs=ps.new.pubs)
        for siger in psigers:
            assert isinstance(siger, indexing.Siger)
        vsigers = manager.sign(ser=ser, verfers=verfers)
        psigs = [siger.qb64 for siger in psigers]
        vsigs = [siger.qb64 for siger in vsigers]
        assert psigs == vsigs
        assert psigs == ['AAAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # Test sign with indices
        indices = [3]

        # Test with pubs list
        psigers = manager.sign(ser=ser, pubs=ps.new.pubs, indices=indices)
        for siger in psigers:
            assert isinstance(siger, indexing.Siger)
        assert psigers[0].index == indices[0]
        psigs = [siger.qb64 for siger in psigers]
        assert psigs == ['ADAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # Test with verfers list
        vsigers = manager.sign(ser=ser, verfers=verfers, indices=indices)
        for siger in vsigers:
            assert isinstance(siger, indexing.Siger)
        assert psigers[0].index == indices[0]
        vsigs = [siger.qb64 for siger in vsigers]
        assert vsigs == psigs

        pcigars = manager.sign(ser=ser, pubs=ps.new.pubs, indexed=False)
        for cigar in pcigars:
            assert isinstance(cigar, coring.Cigar)
        vcigars = manager.sign(ser=ser, verfers=verfers, indexed=False)
        psigs = [cigar.qb64 for cigar in pcigars]
        vsigs = [cigar.qb64 for cigar in vcigars]
        assert psigs == vsigs
        assert psigs == ['0BAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))
        assert len(verfers) == 1
        assert len(digers) == 1

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(spre)
        assert ps.old.pubs == ['DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT']
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX']
        assert ps.new.ridx == 1
        assert ps.new.kidx == 1
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DAoQ1WxT29XtCFtOpJZyuO2q38BD8KTefktf7X0WN4YW']
        assert ps.nxt.ridx == 2
        assert ps.nxt.kidx == 2

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EJczV8HmnEWZiEHw2lVuSatrvzCmJOZ3zpa7JFfrnjau']

        assert oldpubs == ps.old.pubs

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        deadpubs = ps.old.pubs

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0

        ps = manager.ks.sits.get(spre)
        assert oldpubs == ps.old.pubs

        for pub in deadpubs:
            # assert not manager.keeper.getPri(key=pub.encode("utf-8"))
            assert not manager.ks.pris.get(pub.encode("utf-8"))

        # test .pubs db
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs

        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        # salty algorithm rotate to null
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"), ncount=0)

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        ps = manager.ks.sits.get(spre)
        assert ps.nxt.pubs == []
        assert digers == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=spre.decode("utf-8"))
        assert ex.value.args[0].startswith('Attempt to rotate nontransferable ')

        # randy algo incept
        verfers, digers = manager.incept(algo=keeping.Algos.randy)
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.pidx == 2
        rpre = verfers[0].qb64b

        pp = manager.ks.prms.get(rpre)
        assert pp.pidx == 1
        assert pp.algo == keeping.Algos.randy
        assert pp.salt == ''
        assert pp.stem == ''
        assert pp.tier == ''

        ps = manager.ks.sits.get(rpre)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        for key in keys:
            assert manager.ks.pris.get(key.encode("utf-8")) is not None

        digs = [diger.qb64 for diger in  digers]
        assert len(digs) == 1

        oldrpre = rpre
        rpre = b'DMqxMVG3IcCNK4lpFfCu5o5cxzv1lgpMM-9rfkY3XVUc'
        manager.move(old=oldrpre, new=rpre)

        # randy algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]

        verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))

        pp = manager.ks.prms.get(rpre)
        assert pp.pidx == 1

        ps = manager.ks.sits.get(rpre)
        assert oldpubs == ps.old.pubs

        # randy algo incept with null nxt
        verfers, digers = manager.incept(algo=keeping.Algos.randy, ncount=0)
        assert manager.pidx == 3
        rpre = verfers[0].qb64b

        pp = manager.ks.prms.get(rpre)
        assert pp.pidx == 2

        ps = manager.ks.sits.get(rpre)
        assert ps.nxt.pubs == []
        assert digers == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=rpre.decode("utf-8"))

        # salty algorithm incept with stem
        verfers, digers = manager.incept(salt=salt, stem=stem, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.pidx == 4

        spre = verfers[0].qb64b
        assert spre == b'DOtu4gX3oc4feusD8wWIykLhjkpiJHXEe29eJ2b_1CyM'

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 3
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == stem == 'red'
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(spre)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DOtu4gX3oc4feusD8wWIykLhjkpiJHXEe29eJ2b_1CyM']
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DBzZ6vejSNAZpXv1SDRnIF_P1UqcW5d2pu2U-v-uhXvE']
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EIGjhyyBRcqCkPE9bmkph7morew0wW0ak-rQ-dHCH-M2']


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
        assert verfers[0].qb64 == 'BOTNI4RzN706NecNdqTlGEcMSTWiFUvesEqmxWR_op8n'
        assert verfers[0].code == coring.MtrDex.Ed25519N
        assert not digers

        verfers, digers = manager.incept(ncount=0, salt=salt, stem="wit1",
                                         transferable=False, temp=True)
        wit1pre = verfers[0].qb64
        assert verfers[0].qb64 == 'BAB_5xNXH4hoxDCtAHPFPDedZ6YwTo8mbdw_v0AOHOMt'
        assert verfers[0].code == coring.MtrDex.Ed25519N
        assert not digers

        assert wit0pre != wit1pre

        # test .ingest of sequences of keys at default iridx == 0
        secrecies = [
                        ['AAwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc'],
                        ['ABzz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q'],
                        ['ACwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y'],
                        ['ADntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8'],
                        ['AE-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E'],
                        ['AFuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc'],
                        ['AGFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw'],
                        ['AHq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'],
                    ]

        # verify current state
        assert manager.aeid == ''
        assert manager.pidx == 6
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low
        iridx =  0
        ipre, verferies = manager.ingest(secrecies=secrecies)  # use default iridx
        assert ipre == 'DNsGfyf7JArtQgioD7BdVwRulGAsQk5REIKSTjFJqE0a'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                ['DNsGfyf7JArtQgioD7BdVwRulGAsQk5REIKSTjFJqE0a'],
                                ['DJ4j3Lg1viS9sOjrS57i61sXcLO852LDMALqIApud8vX'],
                                ['DMU5BgkqtKK_srvx5WKicoeTuKWoBaEPvR4TWqdyJF4S'],
                                ['DCztsxTVwwmcsyzCoP1BJ6sG8ujOvhlEYNJq61o8Hk9P'],
                                ['DHprr5pG4D1DUujsDqLRTrFwkpEqcoOfC2C3DMUbSgno'],
                                ['DH0JLItMfXTGoYNdhIsgI1o3eMpyTnAzC1zlUjlX3GHM'],
                                ['DO65xRVt3BdHq7LsfEZvtoOeVjqO1Um1odlV-aO03hw3'],
                                ['DOljYz7bLR3lkH4j3o9foQ_zkwzGCAPxbLVhqQlIVW-Z']
                            ]

        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 6
        assert manager.pidx == 7

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 0 # 7
        assert ps.new.kidx == 0
        assert ps.new.pubs == publicies[ps.new.ridx]

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        # nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)

        # test .ingest of sequences of keys at iridx == 3

        secrecies = [
                        ['AAzz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q'],
                        ['ABwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc'],
                        ['ACwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y'],
                        ['ADntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8'],
                        ['AE-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E'],
                        ['AFuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc'],
                        ['AGFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw'],
                        ['AHq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'],
                    ]

        # verify current state
        assert manager.aeid == ''
        assert manager.pidx == 7
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low

        iridx = 3
        ipre, verferies = manager.ingest(secrecies=secrecies, iridx=iridx)
        assert ipre == 'DNBXynUR9FpjCmqK79waLfN__r3S7eKnmUgqIdrXVqY8'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                ['DNBXynUR9FpjCmqK79waLfN__r3S7eKnmUgqIdrXVqY8'],
                                ['DC-3hIkglkRPXYUtKkujoBs2xtVnc_hlDteFx9zlrdtI'],
                                ['DMU5BgkqtKK_srvx5WKicoeTuKWoBaEPvR4TWqdyJF4S'],
                                ['DCztsxTVwwmcsyzCoP1BJ6sG8ujOvhlEYNJq61o8Hk9P'],
                                ['DHprr5pG4D1DUujsDqLRTrFwkpEqcoOfC2C3DMUbSgno'],
                                ['DH0JLItMfXTGoYNdhIsgI1o3eMpyTnAzC1zlUjlX3GHM'],
                                ['DO65xRVt3BdHq7LsfEZvtoOeVjqO1Um1odlV-aO03hw3'],
                                ['DOljYz7bLR3lkH4j3o9foQ_zkwzGCAPxbLVhqQlIVW-Z']
                            ]

        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 7
        assert manager.pidx == 8

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 3
        assert ps.new.kidx == 3
        assert ps.new.pubs == publicies[ps.new.ridx]

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        # nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)

        # test .ingest of sequences of keys at iridx == len(secrecies -1) == 7
        secrecies = [
                        ['AAwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y'],
                        ['ABwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc'],
                        ['ACzz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q'],
                        ['ADntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8'],
                        ['AE-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E'],
                        ['AFuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc'],
                        ['AGFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw'],
                        ['AHq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY'],
                    ]

        # verify current state
        assert manager.aeid == ''
        assert manager.pidx == 8
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low

        iridx = 7
        ipre, verferies = manager.ingest(secrecies=secrecies, iridx=iridx)
        assert ipre == 'DK2H8iQ_oCiCA7Aa4D4nN9LeNUFQl5grfrqpmgm8griH'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                ['DK2H8iQ_oCiCA7Aa4D4nN9LeNUFQl5grfrqpmgm8griH'],
                                ['DC-3hIkglkRPXYUtKkujoBs2xtVnc_hlDteFx9zlrdtI'],
                                ['DEoIHvq8J883tZGN1f_env0iYAUtzPo9zgoOIWLsrwqv'],
                                ['DCztsxTVwwmcsyzCoP1BJ6sG8ujOvhlEYNJq61o8Hk9P'],
                                ['DHprr5pG4D1DUujsDqLRTrFwkpEqcoOfC2C3DMUbSgno'],
                                ['DH0JLItMfXTGoYNdhIsgI1o3eMpyTnAzC1zlUjlX3GHM'],
                                ['DO65xRVt3BdHq7LsfEZvtoOeVjqO1Um1odlV-aO03hw3'],
                                ['DOljYz7bLR3lkH4j3o9foQ_zkwzGCAPxbLVhqQlIVW-Z']
                            ]

        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 8
        assert manager.pidx == 9

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 7
        assert ps.new.kidx == 7
        assert ps.new.pubs == publicies[ps.new.ridx]

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        # nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)

        # test .ingest multi-sig of sequences of keys at default iridx == 0
        secrecies = [
                        [
                            'AAjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                            'ABUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                            'AC-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM'
                        ],
                        [
                            'AD2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs'
                        ],
                        [
                            'AE5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                            'AFlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                            'AGgumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc'
                        ],
                        [
                            'AHW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s'
                        ]
                    ]

        #  verify current state
        assert manager.aeid == ''
        assert manager.pidx == 9
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low

        iridx = 0
        ipre, verferies = manager.ingest(secrecies=secrecies, ncount=3)  # default iridx
        assert ipre == 'DJCWSFm1mJUjFXUk5SsckjZvSYCbCJhUBJjns2WFC1n0'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                [
                                    'DJCWSFm1mJUjFXUk5SsckjZvSYCbCJhUBJjns2WFC1n0',
                                    'DPlKkrIewJfuBCjCRYFoyWFVhd_MW5AkN6aiWTTVYX2Q',
                                    'DKc4NCaCGxzNEswLAZ-YB0Wsb0bkfWwz4L25rZjO7E8R'
                                ],
                                [
                                    'DCPJ1uslUstUK_NnEhcGqqHmPFlVfZga6WJf69_2HFWD'
                                ],
                                [
                                    'DNPTqeHJ--bJDAzPXf8OKOB-JAFJDBPBKg99bH7D490u',
                                    'DLKjI1dMeNUtJAiT_KqMumUJomUBBhEw_tLhmDbAorE1',
                                    'DMzm2BYz3wZqNf0-ZnlLeggWYD37-5bylk8opPfuV_8t'
                                ],
                                [
                                    'DJcjoRESNkUn4IrJNLNLHPE-373NMn6g3g6LDiJJhalB'
                                ]
                            ]


        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 9
        assert manager.pidx == 10

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 0 # 3
        assert ps.new.kidx == 0 # 7
        assert ps.new.pubs == publicies[ps.new.ridx]

        assert len(ps.nxt.pubs) == 1

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        #  nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)


        # test .ingest multi-sig of sequences of keys at iridx == 1
        secrecies = [
                        [
                            'AAUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                            'ABjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                            'AC-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM'
                        ],
                        [
                            'AD2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs'
                        ],
                        [
                            'AE5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                            'AFlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                            'AGgumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc'
                        ],
                        [
                            'AHW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s'
                        ]
                    ]

        #  verify current state
        assert manager.aeid == ''
        assert manager.pidx == 10
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low
        iridx = 1
        ipre, verferies = manager.ingest(secrecies=secrecies, iridx=iridx, ncount=3)
        assert ipre == 'DHc6ZvVpAjLq_digYYZMhq0OlEnnbCrgSvcxPJQY_oAE'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                [
                                    'DHc6ZvVpAjLq_digYYZMhq0OlEnnbCrgSvcxPJQY_oAE',
                                    'DPmRWtx8nwSzRdJ0zTvP5uBb0t3BSjjstDk0gTayFfjV',
                                    'DKc4NCaCGxzNEswLAZ-YB0Wsb0bkfWwz4L25rZjO7E8R'
                                ],
                                [
                                    'DCPJ1uslUstUK_NnEhcGqqHmPFlVfZga6WJf69_2HFWD'
                                ],
                                [
                                    'DNPTqeHJ--bJDAzPXf8OKOB-JAFJDBPBKg99bH7D490u',
                                    'DLKjI1dMeNUtJAiT_KqMumUJomUBBhEw_tLhmDbAorE1',
                                    'DMzm2BYz3wZqNf0-ZnlLeggWYD37-5bylk8opPfuV_8t'
                                ],
                                [
                                    'DJcjoRESNkUn4IrJNLNLHPE-373NMn6g3g6LDiJJhalB'
                                ]
                            ]


        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 10
        assert manager.pidx == 11

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 1
        assert ps.new.kidx == 3
        assert ps.new.pubs == publicies[ps.new.ridx]

        assert len(ps.nxt.pubs) == 3

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        #  nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)

        # test .ingest multi-sig of sequences of keys at
        # iridx == len(secrecies) -1 == 3
        secrecies = [
                        [
                            'AA-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM',
                            'ABUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ',
                            'ACjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw',
                        ],
                        [
                            'AD2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs'
                        ],
                        [
                            'AE5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k',
                            'AFlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8',
                            'AGgumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc'
                        ],
                        [
                            'AEW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s'
                        ]
                    ]

        #  verify current state
        assert manager.aeid == ''
        assert manager.pidx == 11
        assert manager.salt == salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
        assert manager.tier == coring.Tiers.low
        iridx =  3
        ipre, verferies = manager.ingest(secrecies=secrecies, iridx=iridx, ncount=3)
        assert ipre == 'DO1mU48dTzyFtHjqH744gl0QoEIMxphSC4qbgMoEuyq7'
        publicies = []
        for verfers in verferies:
            publicies.append([verfer.qb64 for verfer in verfers])
        assert publicies == [
                                [
                                    'DO1mU48dTzyFtHjqH744gl0QoEIMxphSC4qbgMoEuyq7',
                                    'DPlKkrIewJfuBCjCRYFoyWFVhd_MW5AkN6aiWTTVYX2Q',
                                    'DM7JN7tHARmh5XyYePxcFg0CB9CcHdXR3g3gJD1VZ7XI'
                                ],
                                [
                                    'DCPJ1uslUstUK_NnEhcGqqHmPFlVfZga6WJf69_2HFWD'
                                ],
                                [
                                    'DNPTqeHJ--bJDAzPXf8OKOB-JAFJDBPBKg99bH7D490u',
                                    'DLKjI1dMeNUtJAiT_KqMumUJomUBBhEw_tLhmDbAorE1',
                                    'DMzm2BYz3wZqNf0-ZnlLeggWYD37-5bylk8opPfuV_8t'
                                ],
                                [
                                    'DLbpfBp9HJCgzVq9w5kbwFE5kgIiqfLzhCjaxZo8hp5x'
                                ]
                            ]


        # test .pris db
        for i, pubs in enumerate(publicies):
            pri0 = manager.ks.pris.get(pubs[0]).qb64b
            assert pri0.decode("utf-8") == secrecies[i][0]
            for pub in pubs:
                assert manager.ks.pris.get(pub) is not None

        pp = manager.ks.prms.get(ipre)
        assert pp.pidx == 11
        assert manager.pidx == 12

        ps = manager.ks.sits.get(ipre)
        assert ps.new.ridx == 3
        assert ps.new.kidx == 7
        assert ps.new.pubs == publicies[ps.new.ridx]

        assert len(ps.nxt.pubs) == 3

        # test .pubs db
        for i, pubs in enumerate(publicies):
            pl = manager.ks.pubs.get(keeping.riKey(ipre, i))
            assert pl.pubs == pubs

        #  nxt pubs
        pl = manager.ks.pubs.get(keeping.riKey(ipre, i+1))
        assert pl

        # test replay as incept i.e. advance == False
        verfers, digers = manager.replay(ipre, advance=False)
        assert verfers[0].qb64 == publicies[iridx][0]
        assert digers

        # test replay as rotate i.e. advance == True default
        for i in range(iridx, len(publicies) - 1):
            verfers, digers = manager.replay(ipre)
            assert verfers[0].qb64 == publicies[i+1][0]
            assert digers

        with pytest.raises(IndexError):  # Test end of replay
            verfers, digers = manager.replay(ipre)


    assert not os.path.exists(manager.ks.path)
    assert not manager.ks.opened
    """End Test"""


def test_manager_with_aeid():
    """
    test Manager class with aeid
    """
    # rawsalt =pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    rawsalt = b'0123456789abcdef'
    salter = coring.Salter(raw=rawsalt)
    salt = salter.qb64
    assert salt == '0AAwMTIzNDU2Nzg5YWJjZGVm'
    stem = "blue"


    # cryptseed0 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed0 = b'h,#|\x8ap"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf'
    cryptsigner0 = coring.Signer(raw=cryptseed0, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)
    seed0 = cryptsigner0.qb64
    aeid0 = cryptsigner0.verfer.qb64
    assert aeid0 == 'BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB'
    decrypter0 = coring.Decrypter(seed=seed0)
    encrypter0 = coring.Encrypter(verkey=aeid0)
    assert encrypter0.verifySeed(seed=seed0)

    # cryptseed1 = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    cryptseed1 = (b"\x89\xfe{\xd9'\xa7\xb3\x89#\x19\xbec\xee\xed\xc0\xf9\x97\xd0\x8f9\x1dyNI"
               b'I\x98\xbd\xa4\xf6\xfe\xbb\x03')
    cryptsigner1 = coring.Signer(raw=cryptseed1, code=coring.MtrDex.Ed25519_Seed,
                           transferable=False)
    seed1 = cryptsigner1.qb64
    aeid1 = cryptsigner1.verfer.qb64
    assert aeid1 == 'BEcOrMrG_7r_NWaLl6h8UJapwIfQWIkjrIPXkCZm2fFM'
    decrypter1 = coring.Decrypter(seed=seed1)
    encrypter1 = coring.Encrypter(verkey=aeid1)
    assert encrypter1.verifySeed(seed=seed1)

    # something to sign doesn't matter what for testing purposes
    ser = bytes(b'{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG'
                    b'70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP'
                    b'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz'
                    b'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA'
                    b'ApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOv'
                    b'VjHpdZlty3Hgk6ilF8pVpAQ')

    with keeping.openKS() as keeper:
        # Create manager with encryption decryption due to aeid and seed
        manager = keeping.Manager(ks=keeper, seed=seed0, salt=salt, aeid=aeid0, )
        assert manager.ks.opened
        assert manager.inited
        assert manager._inits == {'salt': '0AAwMTIzNDU2Nzg5YWJjZGVm',
                                  'aeid': 'BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB'}

        # Validate encryption decryption inited
        assert manager.encrypter.qb64 == encrypter0.qb64  #  aeid provided
        assert manager.decrypter.qb64 == decrypter0.qb64  # aeid and seed provided
        assert manager.seed == seed0  # in memory only
        assert manager.aeid == aeid0  # on disk only

        assert manager.algo == keeping.Algos.salty
        assert manager.salt == salt  # encrypted on disk but property decrypts if seed
        assert manager.pidx == 0
        assert manager.tier == coring.Tiers.low
        saltCipher0 = coring.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert saltCipher0.decrypt(seed=seed0).qb64 == salt

        # salty algorithm incept
        verfers, digers = manager.incept(salt=salt, temp=True)  # algo default salty
        assert len(verfers) == 1
        assert len(digers) == 1
        assert manager.pidx == 1

        spre = verfers[0].qb64b
        assert spre == b'DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT'

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert manager.decrypter.decrypt(ser=pp.salt).qb64 == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(spre)
        assert ps.old.pubs == []
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT']
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX']
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 1

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        # test .pubs db
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        digs = [diger.qb64 for diger in  digers]
        assert digs == ['EBhBRqVbqhhP7Ciah5pMIOdsY5Mm1ITm2Fjqb028tylu']

        oldspre = spre
        spre = b'DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc'
        manager.move(old=oldspre, new=spre)

        # test .pubs db after move
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        psigers = manager.sign(ser=ser, pubs=ps.new.pubs)
        for siger in psigers:
            assert isinstance(siger, indexing.Siger)
        vsigers = manager.sign(ser=ser, verfers=verfers)
        psigs = [siger.qb64 for siger in psigers]
        vsigs = [siger.qb64 for siger in vsigers]
        assert psigs == vsigs
        assert psigs == ['AAAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # Test sign with indices
        indices = [3]

        # Test with pubs list
        psigers = manager.sign(ser=ser, pubs=ps.new.pubs, indices=indices)
        for siger in psigers:
            assert isinstance(siger, indexing.Siger)
        assert psigers[0].index == indices[0]
        psigs = [siger.qb64 for siger in psigers]
        assert psigs == ['ADAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # Test with verfers list
        vsigers = manager.sign(ser=ser, verfers=verfers, indices=indices)
        for siger in vsigers:
            assert isinstance(siger, indexing.Siger)
        assert psigers[0].index == indices[0]
        vsigs = [siger.qb64 for siger in vsigers]
        assert vsigs == psigs

        pcigars = manager.sign(ser=ser, pubs=ps.new.pubs, indexed=False)
        for cigar in pcigars:
            assert isinstance(cigar, coring.Cigar)
        vcigars = manager.sign(ser=ser, verfers=verfers, indexed=False)
        psigs = [cigar.qb64 for cigar in pcigars]
        vsigs = [cigar.qb64 for cigar in vcigars]
        assert psigs == vsigs
        assert psigs == ['0BAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH']

        # salty algorithm rotate
        oldpubs = [verfer.qb64 for verfer in verfers]
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))
        assert len(verfers) == 1
        assert len(digers) == 1

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert manager.decrypter.decrypt(ser=pp.salt).qb64 == salt
        assert pp.stem == ''
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(spre)
        assert ps.old.pubs == ['DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT']
        assert len(ps.new.pubs) == 1
        assert ps.new.pubs == ['DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX']
        assert ps.new.ridx == 1
        assert ps.new.kidx == 1
        assert len(ps.nxt.pubs) == 1
        assert ps.nxt.pubs == ['DAoQ1WxT29XtCFtOpJZyuO2q38BD8KTefktf7X0WN4YW']
        assert ps.nxt.ridx == 2
        assert ps.nxt.kidx == 2

        keys = [verfer.qb64 for verfer in verfers]
        assert keys == ps.new.pubs

        digs = [diger.qb64 for diger in digers]
        assert digs == ['EJczV8HmnEWZiEHw2lVuSatrvzCmJOZ3zpa7JFfrnjau']

        assert oldpubs == ps.old.pubs

        # Update aeid and seed
        manager.updateAeid(aeid=aeid1, seed=seed1)
        assert manager.encrypter.qb64 == encrypter1.qb64  #  aeid provided
        assert manager.decrypter.qb64 == decrypter1.qb64  # aeid and seed provided
        assert manager.seed == seed1  # in memory only
        assert manager.aeid == aeid1
        assert manager.algo == keeping.Algos.salty
        assert manager.salt == salt
        assert manager.pidx == 1
        assert manager.tier == coring.Tiers.low
        saltCipher1 = coring.Cipher(qb64=manager.ks.gbls.get('salt'))
        assert saltCipher1.decrypt(seed=seed1).qb64 == salt
        assert not saltCipher0.qb64 == saltCipher1.qb64  # old cipher different

        # salty algorithm rotate again
        oldpubs = [verfer.qb64 for verfer in verfers]
        deadpubs = ps.old.pubs

        verfers, digers = manager.rotate(pre=spre.decode("utf-8"))

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0

        ps = manager.ks.sits.get(spre)
        assert oldpubs == ps.old.pubs

        for pub in deadpubs:
            # assert not manager.keeper.getPri(key=pub.encode("utf-8"))
            assert not manager.ks.pris.get(pub.encode("utf-8"))

        # test .pubs db
        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.new.ridx))
        assert pl.pubs == ps.new.pubs

        pl = manager.ks.pubs.get(keeping.riKey(spre, ps.nxt.ridx))
        assert pl.pubs == ps.nxt.pubs

        # salty algorithm rotate to null
        verfers, digers = manager.rotate(pre=spre.decode("utf-8"), ncount=0)

        pp = manager.ks.prms.get(spre)
        assert pp.pidx == 0
        ps = manager.ks.sits.get(spre)
        assert ps.nxt.pubs == []
        assert digers == []

        #  attempt to rotate after null
        with pytest.raises(ValueError) as ex:  # attempt to reincept same pre
            verfers, digers = manager.rotate(pre=spre.decode("utf-8"))
        assert ex.value.args[0].startswith('Attempt to rotate nontransferable ')

    """End Test"""

def test_manager_sign_dual_indices():
    """
    test Manager signing with dual indices

    Parameters to Manager.sign()
        ser (bytes): serialization to sign
        pubs (list[str] | None): of qb64 public keys to lookup private keys
            one of pubs or verfers is required. If both then verfers is ignored.
        verfers (list[Verfer] | None): Verfer instances of public keys
            one of pubs or verfers is required. If both then verfers is ignored.
        indexed (bool):
            True means use use indexed signatures and return
            list of Siger instances.
            False means do not use indexed signatures and return
            list of Cigar instances

            When indexed True, each index is an offset that maps the offset
            in the coherent lists: pubs, verfers, signers (pris from keystore .ks)
            onto the appropriate offset into the signing keys or prior next
            keys lists of a key event as determined by the indices and ondices
            lists, or appropriate defaults when indices and/or ondices are not
            provided.

        indices (list[int] | None): indices (offsets) when indexed == True,
            to use for indexed signatures whose offset into the current keys
            or prior next list may differ from the order of appearance
            in the provided coherent pubs, verfers, signers lists.
            This allows witness indexed sigs or controller multi-sig
            where the parties do not share the same manager or ordering so
            the default ordering in pubs or verfers is wrong for the index.
            This sets the value of the index property of the returned Siger.
            When provided the length of indices must match the len of the
            coherent lists: pubs, verfers, signers (pris from keystore .ks)
            else raises ValueError.
            When not provided and indexed is True then use default index that
            is the offset into the coherent lists:
            pubs, verfers, signers (pris from keystore .ks)

        ondices (list[int | None] | None): other indices (offsets)
            when indexed is True  for indexed signatures whose offset into
            the prior next list may differ from the order of appearance
            in the provided coherent pubs, verfers, signers lists.
            This allows partial rotation with reserve or custodial key
            management so that the index (hash of index) of the public key
            for the signature appears at a different index in the
            current key list from the prior next list.
            This sets the value of the ondex property of the returned Siger.
            When provided the length of indices must match the len of the
            coherent lists: pubs, verfers, signers (pris from keystore .ks)
            else raises ValueError.
            When no ondex is applicable to a given signature then the value
            of the entry in ondices MUST be None.
            When  ondices is not provided then all sigers .ondex is None.
    """
    raw = b'0123456789abcdef'
    salt = coring.Salter(raw=raw).qb64

    # the particular serialization does not matter for test purposes
    ser = (b"See ya later Alligator. In a while Crocodile. "
           b"Not to soon Baboon. That's the plan Toucan. "
           b"As you wish Jellyfish. Have a nice day Bluejay.")


    with keeping.openKS() as keeper:
        manager = keeping.Manager(ks=keeper, salt=salt)
        assert manager.ks.opened
        assert manager.pidx == 0
        assert manager.tier == coring.Tiers.low
        assert manager.salt == salt
        assert manager.aeid == ""
        assert manager.seed == ""
        assert manager.encrypter == None
        assert manager.decrypter == None

        # salty algorithm incept
        stem = 'phlegm'
        icount = 4
        ncount =  3
        # algo default salty
        verfers, digers = manager.incept(icount=icount,
                                        ncount=ncount,
                                        salt=salt,
                                        stem = 'phlegm',
                                        temp=True)

        assert len(verfers) == icount
        assert len(digers) == ncount
        assert manager.pidx == 1  # incremented

        pre = verfers[0].qb64  # Key sequence parameters lookup by pre
        pp = manager.ks.prms.get(pre)
        assert pp.pidx == 0
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == stem
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(pre)
        assert len(ps.old.pubs) == 0
        assert ps.old.ridx == 0
        assert ps.old.kidx == 0

        assert len(ps.new.pubs) == icount
        assert ps.new.ridx == 0
        assert ps.new.kidx == 0

        assert len(ps.nxt.pubs) == ncount
        assert ps.nxt.ridx == 1
        assert ps.nxt.kidx == 0 + icount

        pubs0 = [verfer.qb64 for verfer in verfers]
        digs0 = [diger.qb64 for  diger in digers]


        # default seed (private key) code is MtrDex.Ed25519_Seed
        # so sign codes will be from Ed25519 set
        #IdrDex.Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
        #IdrDex.Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
        #IdrDex.Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both lists.
        #IdrDex.Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.

        # Test sign with indices different order and no ondices.
        # This idicates both same
        indices0 = [3, 2, 1, 0]
        sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0)
        for x in range(len(pubs0)):
            siger = sigers0[x]
            assert siger.index == indices0[x]
            assert siger.ondex == siger.index  # both same
            assert siger.code == IdrDex.Ed25519_Sig   # both same

        # Test sign with indices different order  and ondices all None.
        # This indicates current only
        indices0 = [3, 2, 1, 0]
        ondices0 = [None, None, None, None]
        sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)
        for x in range(len(pubs0)):
            siger = sigers0[x]
            assert siger.index == indices0[x]
            assert siger.ondex == None  # current only
            assert siger.code == IdrDex.Ed25519_Crt_Sig  # current only

        # Test sign with indices and ondices different from each other.
        # This indicates both different
        indices0 = [3, 2, 1, 0]
        ondices0 = [2, 0, 3, 1]
        sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)
        for x in range(len(pubs0)):
            siger = sigers0[x]
            assert siger.index == indices0[x]
            assert siger.ondex == ondices0[x]
            assert siger.code == IdrDex.Ed25519_Big_Sig  # both different

        # Test sign with indices and ondices different including None.
        # This indicates both different
        indices0 = [3, 2, 1, 0]
        ondices0 = [2, None, None, 0]
        sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)
        for x in range(len(pubs0)):
            siger = sigers0[x]
            assert siger.index == indices0[x]
            assert siger.ondex == ondices0[x]
            if siger.index == siger.ondex:
                assert siger.code == IdrDex.Ed25519_Sig
            elif siger.ondex is None:
                assert siger.code == IdrDex.Ed25519_Crt_Sig
            else:
                assert siger.code == IdrDex.Ed25519_Big_Sig

        indices0 = [None, 2, 1, 0]
        ondices0 = [2, None, None, 0]
        with pytest.raises(ValueError):
            sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)

        indices0 = [3, -2, 1, 0]
        ondices0 = [2, None, None, 0]
        with pytest.raises(ValueError):
            sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)

        indices0 = [3, 2, 1, 0]
        ondices0 = [2, None, None, -1]
        with pytest.raises(ValueError):
            sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)

        indices0 = [3, 2, 1, 0]
        ondices0 = [2, None, None, False]
        with pytest.raises(ValueError):
            sigers0 = manager.sign(ser=ser, pubs=pubs0, indices=indices0, ondices=ondices0)


        # salty algorithm rotate
        ocount = icount
        icount = ncount
        ncount = 5
        verfers, digers = manager.rotate(pre=pre, ncount=ncount, temp=True)
        assert len(verfers) == icount
        assert len(digers) == ncount

        # Key sequence parameters lookup by pre
        pp = manager.ks.prms.get(pre)
        assert pp.pidx == 0  # same sequence
        assert pp.algo == keeping.Algos.salty
        assert pp.salt == salt
        assert pp.stem == stem
        assert pp.tier == coring.Tiers.low

        ps = manager.ks.sits.get(pre)
        assert len(ps.old.pubs) == ocount
        assert ps.old.ridx == 0
        assert ps.old.kidx == 0

        assert len(ps.new.pubs) == icount
        assert ps.new.ridx == 1
        assert ps.new.kidx == 0 + ocount

        assert len(ps.nxt.pubs) == ncount
        assert ps.nxt.ridx == 2
        assert ps.nxt.kidx == ocount + icount

        pubs1 = [verfer.qb64 for verfer in verfers]
        digs1 = [diger.qb64 for  diger in digers]

        # now do signing with combination of keys from inception and rotation
        pubs = pubs1 + [pubs0[0], pubs0[2]]  # 3 from current + 2 from prior next
        indices1 = [0, 1, 2, 3, 4]  # current signing list indices
        ondices1 = [None, None, None, 0, 2]  # prior next signing ondices

        sigers1 = manager.sign(ser=ser, pubs=pubs, indices=indices1, ondices=ondices1)
        for x in range(len(pubs)):
            siger = sigers1[x]
            assert siger.index == indices1[x]
            assert siger.ondex == ondices1[x]
            if siger.index == siger.ondex:
                assert siger.code == IdrDex.Ed25519_Sig
            elif siger.ondex is None:
                assert siger.code == IdrDex.Ed25519_Crt_Sig
            else:
                assert siger.code == IdrDex.Ed25519_Big_Sig





    assert not os.path.exists(manager.ks.path)
    assert not manager.ks.opened
    """End Test"""

if __name__ == "__main__":
    test_manager_sign_dual_indices()
