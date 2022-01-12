# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import os
import shutil
import time

from hio.base import doing, tyming

from keri import kering
from keri import help
from keri.app import habbing, keeping, configing
from keri.db import basing
from keri.core import coring, eventing, parsing


def test_habery():
    """
    Test Habery class
    """
    # test default
    hby = habbing.Habery(temp=True)
    assert hby.name == "test"
    assert hby.base == ""
    assert hby.temp
    assert hby.inited

    assert hby.db.name == "test" == hby.name
    assert hby.db.base == "" == hby.base
    assert not hby.db.filed
    assert hby.db.path.endswith("/keri/db/test")
    assert hby.db.opened

    assert hby.ks.name == "test" == hby.name
    assert hby.ks.base == "" == hby.base
    assert not hby.ks.filed
    assert hby.ks.path.endswith("/keri/ks/test")
    assert hby.ks.opened

    assert hby.cf.name == "test" == hby.name
    assert hby.cf.base == "" == hby.base
    assert hby.cf.filed
    assert hby.cf.path.endswith("/keri/cf/test.json")
    assert hby.cf.opened
    assert not hby.cf.file.closed

    assert hby.mgr.seed == ""
    assert hby.mgr.aeid == ""
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 0
    assert hby.mgr.algo == keeping.Algos.salty
    assert hby.mgr.tier == coring.Tiers.low

    hby.cf.close(clear=True)
    hby.db.close(clear=True)
    hby.ks.close(clear=True)

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    # test bran to seed
    bran = "MyPasscodeIsRealSecret"
    assert len(bran) == 22
    hby = habbing.Habery(bran=bran, temp=True)
    assert hby.name == "test"
    assert hby.base == ""
    assert hby.temp
    assert hby.inited

    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 0
    assert hby.mgr.algo == keeping.Algos.salty
    assert hby.mgr.tier == coring.Tiers.low

    assert hby.rtr.routes
    assert hby.rvy.rtr == hby.rtr
    assert hby.kvy.rvy == hby.rvy
    assert hby.psr.kvy ==  hby.kvy
    assert hby.psr.rvy == hby.rvy

    hby.cf.close(clear=True)
    hby.db.close(clear=True)
    hby.ks.close(clear=True)

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)


    # test pre-create of injected resources
    base = "keep"
    name = "main"
    bran = "MyPasscodeIsRealSecret"
    temp = True

    # setup databases  for dependency injection and config file
    ks = keeping.Keeper(name=base, temp=temp)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=base, temp=temp)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes
    cf = configing.Configer(name=name, base=base, temp=temp)
    cfDoer = configing.ConfigerDoer(configer=cf)
    conf = cf.get()
    if not conf: # setup config file
        curls = ["ftp://localhost:5620/"]
        iurls = [f"ftp://localhost:5621/?role={kering.Roles.peer}&name=Bob"]
        conf = dict(dt=help.nowIso8601(), curls=curls, iurls=iurls)
        cf.put(conf)

    # setup habery
    hby = habbing.Habery(name=name, base=base, ks=ks, db=db, cf=cf, temp=temp,
                         bran=bran )
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    assert hby.name == "main"
    assert hby.base == "keep"
    assert hby.temp
    assert not hby.inited
    assert hby.mgr is None

    # need to run doers to open databases so can finish init
    doers = [ksDoer, dbDoer, cfDoer, hbyDoer]

    # run components
    tock = 0.03125
    limit =  1.0
    doist = doing.Doist(limit=limit, tock=tock, real=True)
    tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

    # doist.do(doers=doers)
    deeds = doist.enter(doers=doers)
    doist.recur(deeds=deeds)

    assert hby.inited
    assert hby.mgr is not None
    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 0
    assert hby.mgr.algo == keeping.Algos.salty
    assert hby.mgr.tier == coring.Tiers.low

    assert hby.rtr.routes
    assert hby.rvy.rtr == hby.rtr
    assert hby.kvy.rvy == hby.rvy
    assert hby.psr.kvy ==  hby.kvy
    assert hby.psr.rvy == hby.rvy


    #time.sleep(doist.tock)
    #while not tymer.expired:
        #doist.recur(deeds=deeds)
        #time.sleep(doist.tock)
    #assert doist.limit == limit  # already exited?
    doist.exit(deeds=deeds)

    assert not cf.opened
    assert not db.opened
    assert not ks.opened

    assert not os.path.exists(cf.path)
    assert not os.path.exists(db.path)
    assert not os.path.exists(ks.path)


    # test pre-create using habery itself
    base = "keep"
    name = "main"
    bran = "MyPasscodeIsRealSecret"
    temp = True

    # setup habery with resources
    hby = habbing.Habery(name=name, base=base, temp=temp, bran=bran, free=True)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    conf = hby.cf.get()
    if not conf: # setup config file
        curls = ["ftp://localhost:5620/"]
        iurls = [f"ftp://localhost:5621/?role={kering.Roles.peer}&name=Bob"]
        conf = dict(dt=help.nowIso8601(), curls=curls, iurls=iurls)
        hby.cf.put(conf)


    assert hby.name == "main"
    assert hby.base == "keep"
    assert hby.temp
    assert hby.inited
    assert hby.mgr is not None

    # habery doer to free resources on exit
    doers = [hbyDoer]

    # run components
    tock = 0.03125
    limit =  1.0
    doist = doing.Doist(limit=limit, tock=tock, real=True)
    tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

    # doist.do(doers=doers)
    deeds = doist.enter(doers=doers)
    doist.recur(deeds=deeds)

    assert hby.inited
    assert hby.mgr is not None
    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 0
    assert hby.mgr.algo == keeping.Algos.salty
    assert hby.mgr.tier == coring.Tiers.low

    assert hby.rtr.routes
    assert hby.rvy.rtr == hby.rtr
    assert hby.kvy.rvy == hby.rvy
    assert hby.psr.kvy ==  hby.kvy
    assert hby.psr.rvy == hby.rvy

    #time.sleep(doist.tock)
    #while not tymer.expired:
        #doist.recur(deeds=deeds)
        #time.sleep(doist.tock)
    #assert doist.limit == limit  # already exited?
    doist.exit(deeds=deeds)

    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)



    """End Test"""


def test_habitat():
    """
    Test Habitat class
    """
    hab = habbing.Habitat(temp=True)
    assert hab.name == "test"

    hab.db.close(clear=True)
    hab.ks.close(clear=True)

    """End Test"""


def test_habitat_rotate_with_witness():
    if os.path.exists('/usr/local/var/keri/db/phil-test'):
        shutil.rmtree('/usr/local/var/keri/db/phil-test')
    if os.path.exists('/usr/local/var/keri/ks/phil-test'):
        shutil.rmtree('/usr/local/var/keri/ks/phil-test')

    name = "phil-test"
    with basing.openDB(name=name, temp=False) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False,
                              wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said

    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False,
                              wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])

        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate(count=3)

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said


def test_habitat_reinitialization():
    """
    Test Reinitializing Habitat class
    """
    if os.path.exists('/usr/local/var/keri/db/bob-test'):
        shutil.rmtree('/usr/local/var/keri/db/bob-test')
    if os.path.exists('/usr/local/var/keri/ks/bob-test'):
        shutil.rmtree('/usr/local/var/keri/ks/bob-test')

    name = "bob-test"

    with basing.openDB(name=name, clear=True, temp=False) as db, \
            keeping.openKS(name=name, clear=True, temp=False) as ks:

        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said
        assert hab.ridx == 0

    with basing.openDB(name=name, temp=False) as db, \
            keeping.openKS(name=name, temp=False) as ks:

        assert opre not in db.prefixes
        assert opre in db.kevers  # write through cache

        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate()

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.said

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.ridx == 1

        assert hab.kever.serder.said != odig
        assert hab.kever.serder.said == ndig

        hab.ks.close(clear=True)
        hab.db.close(clear=True)

    assert not os.path.exists(hab.ks.path)
    assert not os.path.exists(hab.db.path)
    """End Test"""


def test_habitat_reinitialization_reload():
    if os.path.exists('/usr/local/var/keri/db/bob-test'):
        shutil.rmtree('/usr/local/var/keri/db/bob-test')
    if os.path.exists('/usr/local/var/keri/ks/bob-test'):
        shutil.rmtree('/usr/local/var/keri/ks/bob-test')
    if os.path.exists('/usr/local/var/keri/cf/bob-test.json'):
        os.remove('/usr/local/var/keri/cf/bob-test.json')

    name = "bob-test"

    with basing.openDB(name=name, clear=True, temp=False) as db, \
            keeping.openKS(name=name, clear=True, temp=False) as ks, \
            configing.openCF(name=name, base="", clear=True, temp=False) as  cf:
        hab = habbing.Habitat(name=name, ks=ks, db=db, cf=cf, icount=1, temp=False)
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said
        assert hab.ridx == 0

    # openDB with reload=True which should reload .habs into db.kevers and db.prefixes
    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks, \
            configing.openCF(name=name, base="", temp=False) as cf:
        assert opre in db.prefixes
        assert opre in db.kevers

        hab = habbing.Habitat(name=name, ks=ks, db=db, cf=cf, icount=1, temp=False)
        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate()

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.said

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.ridx == 1

        assert hab.kever.serder.said != odig
        assert hab.kever.serder.said == ndig

        hab.cf.close(clear=True)
        hab.ks.close(clear=True)
        hab.db.close(clear=True)

    assert not os.path.exists(hab.cf.path)
    assert not os.path.exists(hab.ks.path)
    assert not os.path.exists(hab.db.path)
    """End Test"""


def test_habitat_with_delegation():
    """
    Test Habitat class
    """
    delhab = habbing.Habitat(name="del", temp=True)
    delpre = delhab.pre
    assert delpre == "E-kwM1vdZf63KAnw0SbS3Jrq1cKavuM8z2fXz2tMA8KA"

    bobhab = habbing.Habitat(name="bob", temp=True, delpre=delpre)
    assert bobhab.pre == "EXBwGj6s62ZGKUaiNlzaFeycxs-hwgbkD2hUR1aI-bGg"

    assert bobhab.delserder.pre == "EXBwGj6s62ZGKUaiNlzaFeycxs-hwgbkD2hUR1aI-bGg"
    assert bobhab.delserder.ked["s"] == '0'
    assert bobhab.delserder.said == "EXBwGj6s62ZGKUaiNlzaFeycxs-hwgbkD2hUR1aI-bGg"

    assert bobhab.accepted is False

    bobhab.db.close(clear=True)
    bobhab.ks.close(clear=True)
    delhab.db.close(clear=True)
    delhab.ks.close(clear=True)

    """End Test"""

def test_habitat_reconfigure(mockHelpingNowUTC):
    """
    Test Habitat  .reconfigure method using .cf for config file

     conf
    {
      dt: "isodatetime",
      curls: ["tcp://localhost:5620/"],
      iurls: ["ftp://localhost:5621/?name=eve"],
    }

    """
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    cname = "tam"  # tam controller name
    cbase = "main" # tam controller main shared
    pname = "nel"  # nel peer name
    pbase = "head" # nel peer head shared

    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         configing.openCF(name="wes") as wesCF, \
         basing.openDB(name="wok") as wokDB, keeping.openKS(name="wok") as wokKS, \
         configing.openCF(name="wok") as wokCF, \
         basing.openDB(name="main") as tamDB, keeping.openKS(name="main") as tamKS, \
         configing.openCF(name="tam", base="main") as tamCF, \
         basing.openDB(name="wat") as watDB, keeping.openKS(name="wat") as watKS, \
         configing.openCF(name="wat") as watCF, \
         basing.openDB(name="head") as nelDB, keeping.openKS(name="head") as nelKS, \
         configing.openCF(name="nel", base="head") as nelCF:

        # witnesses first so can setup inception event for tam
        wsith = 1

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,  cf=wesCF,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        wesPrs = parsing.Parser(kvy=wesKvy)

        # setup Wok's habitat nontrans
        wokHab = habbing.Habitat(name='wok',ks=wokKS, db=wokDB, cf=wokCF,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wokHab.ks == wokKS
        assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)
        wokPrs = parsing.Parser(kvy=wokKvy)

        # setup Tam's config
        curls = ["tcp://localhost:5620/"]
        iurls = [f"tcp://localhost:5621/?role={kering.Roles.peer}&name={pname}"]
        assert (conf := tamCF.get()) == {}
        conf = dict(dt=help.nowIso8601(), curls=curls, iurls=iurls)
        tamCF.put(conf)

        assert tamCF.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                'curls': ['tcp://localhost:5620/'],
                                'iurls': ['tcp://localhost:5621/?role=peer&name=nel']}

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre]
        tsith = 1  # hex str of threshold int
        tamHab = habbing.Habitat(name='cam', ks=tamKS, db=tamDB, cf=tamCF,
                                   isith=tsith, icount=3,
                                   toad=2, wits=wits,
                                   salt=salt, temp=True)  # stem is .name
        assert tamHab.ks == tamKS
        assert tamHab.db == tamDB
        assert tamHab.cf == tamCF
        assert tamHab.kever.prefixer.transferable
        assert len(tamHab.iserder.werfers) == len(wits)
        for werfer in tamHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert tamHab.kever.wits == wits
        assert tamHab.kever.toad == 2
        assert tamHab.kever.sn == 0
        assert tamHab.kever.tholder.thold == tsith == 1
        # create non-local kevery for Tam to process non-local msgs
        tamKvy = eventing.Kevery(db=tamHab.db, lax=False, local=False)
        # create non-local parer for Tam to process non-local msgs
        tamPrs = parsing.Parser(kvy=tamKvy)

        # check tamHab.cf config setup
        ender = tamHab.db.ends.get(keys=(tamHab.pre, "controller", tamHab.pre))
        assert ender.allowed
        assert not ender.name
        locer = tamHab.db.locs.get(keys=(tamHab.pre, kering.Schemes.tcp))
        assert locer.url == 'tcp://localhost:5620/'

        # setup Wat's habitat nontrans
        watHab = habbing.Habitat(name='wat', ks=watKS, db=watDB, cf=watCF,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert watHab.ks == watKS
        assert watHab.db == watDB
        assert not watHab.kever.prefixer.transferable
        watKvy = eventing.Kevery(db=watHab.db, lax=False, local=False)

        # setup Nel's config
        curls = ["tcp://localhost:5621/"]
        iurls = [f"tcp://localhost:5620/?role={kering.Roles.peer}&name={cname}"]
        assert (conf := nelCF.get()) == {}
        conf = dict(dt=help.nowIso8601(), curls=curls, iurls=iurls)
        nelCF.put(conf)

        assert nelCF.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                'curls': ['tcp://localhost:5621/'],
                                'iurls': ['tcp://localhost:5620/?role=peer&name=tam']}

        # setup Nel's habitat nontrans
        nelHab = habbing.Habitat(name='nel', ks=nelKS, db=nelDB, cf=nelCF,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert nelHab.ks == nelKS
        assert nelHab.db == nelDB
        assert not nelHab.kever.prefixer.transferable
        nelKvy = eventing.Kevery(db=nelHab.db, lax=False, local=False)
        # create non-local parer for Nel to process non-local msgs
        nelPrs = parsing.Parser(kvy=nelKvy)

        assert nelHab.pre == 'Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI'
        assert nelHab.kever.prefixer.code == coring.MtrDex.Ed25519N
        assert nelHab.kever.verfers[0].qb64 == nelHab.pre

        # check nelHab.cf config setup
        ender = nelHab.db.ends.get(keys=(nelHab.pre, "controller", nelHab.pre))
        assert ender.allowed
        assert not ender.name
        locer = nelHab.db.locs.get(keys=(nelHab.pre, kering.Schemes.tcp))
        assert locer.url == 'tcp://localhost:5621/'



    assert not os.path.exists(nelCF.path)
    assert not os.path.exists(nelKS.path)
    assert not os.path.exists(nelDB.path)
    assert not os.path.exists(watCF.path)
    assert not os.path.exists(watKS.path)
    assert not os.path.exists(watDB.path)
    assert not os.path.exists(wokCF.path)
    assert not os.path.exists(wokKS.path)
    assert not os.path.exists(wokDB.path)
    assert not os.path.exists(wesCF.path)
    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)
    assert not os.path.exists(tamCF.path)
    assert not os.path.exists(tamKS.path)
    assert not os.path.exists(tamDB.path)
    """Done Test"""


if __name__ == "__main__":
    test_habery()
    # test_habitat_reinitialization_reload()
    # pytest.main(['-vv', 'test_reply.py::test_reply'])
