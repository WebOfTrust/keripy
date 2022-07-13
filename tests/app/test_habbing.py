# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""
import pytest

import os
import shutil

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
    assert hby.habs == {}

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
    assert hby.mgr.pidx == 1
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
    assert hby.habs == {}

    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 1
    assert hby.mgr.algo == keeping.Algos.salty
    assert hby.mgr.tier == coring.Tiers.low

    assert hby.rtr.routes
    assert hby.rvy.rtr == hby.rtr
    assert hby.kvy.rvy == hby.rvy
    assert hby.psr.kvy == hby.kvy
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
    assert hby.habs == {}
    assert hby.mgr is not None
    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 1
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
    assert hby.habs == {}
    assert hby.mgr is not None
    assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
    assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
    assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
    assert hby.mgr.pidx == 1
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

    with habbing.openHby() as hby:
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
        assert hby.mgr.salt == habbing.SALT
        assert hby.mgr.pidx == 1
        assert hby.mgr.algo == keeping.Algos.salty
        assert hby.mgr.tier == coring.Tiers.low

        assert hby.rtr.routes
        assert hby.rvy.rtr == hby.rtr
        assert hby.kvy.rvy == hby.rvy
        assert hby.psr.kvy == hby.kvy
        assert hby.psr.rvy == hby.rvy

    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)


    bran = "MyPasscodeIsRealSecret"
    with habbing.openHby(bran=bran) as hby:
        assert hby.name == "test"
        assert hby.base == ""
        assert hby.temp
        assert hby.inited
        assert hby.habs == {}

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

        # test bran to seed
        assert hby.mgr.seed == 'AZXIe9H4846eXjc7c1jp8XJ06xt2hwwhB-dzzpdS3eKk'
        assert hby.mgr.aeid == 'BgY4KXjfXwJnepwOrz_9s3WMtppLdsmeowZn7XMdZzrs'
        assert hby.mgr.salt == '0AMDEyMzQ1Njc4OWFiY2RlZg'
        assert hby.mgr.pidx == 1
        assert hby.mgr.algo == keeping.Algos.salty
        assert hby.mgr.tier == coring.Tiers.low

        assert hby.rtr.routes
        assert hby.rvy.rtr == hby.rtr
        assert hby.kvy.rvy == hby.rvy
        assert hby.psr.kvy == hby.kvy
        assert hby.psr.rvy == hby.rvy

    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)


    """End Test"""


def test_make_load_hab_with_habery():
    """
    Test creation methods for Hab instances with Habery
    """
    with pytest.raises(TypeError):  # missing required dependencies
        hab = habbing.Hab()  # defaults

    name = "Sue"
    with habbing.openHby() as hby:  # default is temp=True on openHab
        hab = hby.makeHab(name=name)
        assert isinstance(hab, habbing.Hab)
        assert hab.pre in hby.habs
        assert id(hby.habByName(hab.name)) == id(hab)

        assert hab.name == name
        assert hab.pre == 'ESDOVXbLrbDjo94qAw_HCo3npFXGBNo-DEQeflDL2RyE'
        assert hab.temp
        assert hab.accepted
        assert hab.inited

        assert hab.pre in hby.kevers
        assert hab.pre in hby.prefixes

        hab.db = hby.db  # injected
        hab.ks = hby.ks  # injected
        hab.cf = hby.cf  # injected
        hab.mgr = hby.mgr  # injected
        hab.rtr = hby.rtr  # injected
        hab.rvy = hby.rvy  # injected
        hab.kvy = hby.kvy  # injected
        hab.psr = hby.psr  # injected



    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    # create not temp and then reload from not temp
    if os.path.exists('/usr/local/var/keri/cf/hold/test.json'):
        os.remove('/usr/local/var/keri/cf/hold/test.json')
    if os.path.exists('/usr/local/var/keri/db/hold/test'):
        shutil.rmtree('/usr/local/var/keri/db/hold/test')
    if os.path.exists('/usr/local/var/keri/ks/hold/test'):
        shutil.rmtree('/usr/local/var/keri/ks/hold/test')

    base = "hold"
    with habbing.openHby(base=base, temp=False) as hby:  # default is temp=True
        assert hby.cf.path.endswith("keri/cf/hold/test.json")
        assert hby.db.path.endswith("keri/db/hold/test")
        assert hby.ks.path.endswith('keri/ks/hold/test')

        sueHab = hby.makeHab(name='Sue')
        assert isinstance(sueHab, habbing.Hab)
        assert sueHab.pre in hby.habs
        assert id(hby.habByName(sueHab.name)) == id(sueHab)

        assert sueHab.name == "Sue"
        assert sueHab.pre == 'EJzql954-toWFugKWCIyN2iAlb7jkLrCUd_6eG-lAE9I'
        assert not sueHab.temp
        assert sueHab.accepted
        assert sueHab.inited
        assert sueHab.pre in hby.kevers
        assert sueHab.pre in hby.prefixes

        bobHab = hby.makeHab(name='Bob')
        assert isinstance(bobHab, habbing.Hab)
        assert bobHab.pre in hby.habs
        assert id(hby.habByName(bobHab.name)) == id(bobHab)

        assert bobHab.name == "Bob"
        assert bobHab.pre == 'EF8fAMlW1-2mARLE8NPEulkM7JmVTye0n5JOLb3WKcOI'
        assert not bobHab.temp
        assert bobHab.accepted
        assert bobHab.inited
        assert bobHab.pre in hby.kevers
        assert bobHab.pre in hby.prefixes

        assert len(hby.habs) == 2


    assert not hby.cf.opened
    assert not hby.db.opened
    assert not hby.ks.opened

    assert os.path.exists(hby.cf.path)
    assert os.path.exists(hby.db.path)
    assert os.path.exists(hby.ks.path)

    # test load from database
    suePre = 'EJzql954-toWFugKWCIyN2iAlb7jkLrCUd_6eG-lAE9I'
    bobPre = 'EF8fAMlW1-2mARLE8NPEulkM7JmVTye0n5JOLb3WKcOI'
    base = "hold"
    with habbing.openHby(base=base, temp=False) as hby:  # default is temp=True
        assert hby.cf.path.endswith("keri/cf/hold/test.json")
        assert hby.db.path.endswith("keri/db/hold/test")
        assert hby.ks.path.endswith('keri/ks/hold/test')

        assert hby.inited
        assert len(hby.habs) == 2

        assert suePre in hby.kevers
        assert suePre in hby.prefixes
        assert suePre in hby.habs
        sueHab = hby.habByName("Sue")
        assert sueHab.name == "Sue"
        assert sueHab.pre == suePre
        assert sueHab.accepted
        assert sueHab.inited

        assert bobPre in hby.kevers
        assert bobPre in hby.prefixes
        assert bobPre in hby.habs
        bobHab = hby.habByName("Bob")
        assert bobHab.name == "Bob"
        assert bobHab.pre == bobPre
        assert bobHab.accepted
        assert bobHab.inited

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    """End Test"""



def test_hab_rotate_with_witness():
    """
    Reload from disk and rotate hab with witness
    """

    if os.path.exists('/usr/local/var/keri/cf/test/phil-test.json'):
        os.remove('/usr/local/var/keri/cf/test/phil-test.json')
    if os.path.exists('/usr/local/var/keri/db/test/phil-test'):
        shutil.rmtree('/usr/local/var/keri/db/test/phil-test')
    if os.path.exists('/usr/local/var/keri/ks/test/phil-test'):
        shutil.rmtree('/usr/local/var/keri/ks/test/phil-test')

    name = "phil-test"

    with habbing.openHby(name=name, base="test", temp=False) as hby:
        hab = hby.makeHab(name=name, icount=1, wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said


    with habbing.openHby(name=name, base="test", temp=False) as hby:
        # hab = hby.makeHab(name=name, icount=1, wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])
        hab = hby.habByName(name)
        assert hab.pre == opre
        assert hab.prefixes is hab.db.prefixes
        assert hab.kevers is hab.db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate(count=3)
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)


def test_habery_reinitialization():
    """Test Reinitializing Habery and its Habs
    """

    if os.path.exists('/usr/local/var/keri/cf/test/bob-test.json'):
        os.remove('/usr/local/var/keri/cf/test/bob-test.json')
    if os.path.exists('/usr/local/var/keri/db/test/bob-test'):
        shutil.rmtree('/usr/local/var/keri/db/test/bob-test')
    if os.path.exists('/usr/local/var/keri/ks/test/bob-test'):
        shutil.rmtree('/usr/local/var/keri/ks/test/bob-test')

    name = "bob-test"

    with habbing.openHby(name=name, base="test", temp=False, clear=True) as hby:
        hab = hby.makeHab(name=name, icount=1)
        oidig = hab.iserder.said
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.said


    with habbing.openHby(name=name, base="test", temp=False) as hby:

        assert opre in hby.db.kevers  # read through cache
        assert opre in hby.db.prefixes

        # hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        hab = hby.habByName(name)
        assert hab.pre == opre
        assert hab.prefixes is hab.db.prefixes
        assert hab.kevers is hab.db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.said == oidig

        hab.rotate()
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.said

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.said

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.kever.serder.said != odig
        assert hab.kever.serder.said == ndig

    hby.close(clear=True)
    hby.cf.close(clear=True)
    assert not os.path.exists(hby.cf.path)
    assert not os.path.exists(hby.db.path)
    assert not os.path.exists(hby.ks.path)

    """End Test"""


def test_habery_signatory():
    with habbing.openHby() as hby:
        signer = hby.signator

        assert signer is not None
        assert signer.pre == "B3ku7RGqm2YkL6JcSV0wyuUR7DtDTW17Z8uCqVupb3NE"

        # Assert we get the same one in subsequent calls
        sig2 = hby.signator
        assert sig2 == signer
        raw = b'this is the raw data'

        # Sign some data
        cig = signer.sign(ser=raw)
        assert cig.qb64b == b'0BXERDelN3sj1w50Wg60QYAOyRAsa_HwKkx72y2PEczASEK9UKM_R-XdGjzNRGyhT9Q3E9c2ncW3hEHIk9JZMrCw'

        # Verify the signature
        assert signer.verify(ser=raw, cigar=cig) is True

        # Make sure this new key doesn't effect the habery environment
        assert len(hby.habs) == 0
        assert len(hby.prefixes) == 0


def test_habery_reconfigure(mockHelpingNowUTC):
    """
    Test   .reconfigure method using .cf for config file

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


    with habbing.openHby(name='wes', base="test", salt=salt) as wesHby, \
         habbing.openHby(name='wok', base="test", salt=salt) as wokHby, \
         habbing.openHby(name='tam', base="test", salt=salt) as tamHby, \
         habbing.openHby(name='wat', base="test", salt=salt) as watHby, \
         habbing.openHby(name='nel', base="test", salt=salt) as nelHby:

        # witnesses first so can setup inception event for tam
        wsith = '1'

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name="wes", isith=wsith, icount=1, transferable=False)
        assert not wesHab.kever.prefixer.transferable
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        wesPrs = parsing.Parser(kvy=wesKvy)

        # setup Wok's habitat nontrans
        wokHab = wokHby.makeHab(name="wok", isith=wsith, icount=1, transferable=False)
        assert not wokHab.kever.prefixer.transferable
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)
        wokPrs = parsing.Parser(kvy=wokKvy)

        # setup Tam's config
        curls = ["tcp://localhost:5620/"]
        iurls = [f"tcp://localhost:5621/?role={kering.Roles.peer}&name={pname}"]
        assert (conf := tamHby.cf.get()) == {}
        conf = dict(dt=help.nowIso8601(), tam=dict(dt=help.nowIso8601(), curls=curls), iurls=iurls)
        tamHby.cf.put(conf)

        assert tamHby.cf.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                   'tam': {
                                       'dt': '2021-01-01T00:00:00.000000+00:00',
                                       'curls': ['tcp://localhost:5620/']
                                   },
                                   'iurls': ['tcp://localhost:5621/?role=peer&name=nel']}

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre]
        tsith = '1'  # hex str of threshold int
        tamHab = tamHby.makeHab(name="tam", isith=tsith, icount=3, toad=2, wits=wits)
        assert tamHab.kever.prefixer.transferable
        assert len(tamHab.iserder.werfers) == len(wits)
        for werfer in tamHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert tamHab.kever.wits == wits
        assert tamHab.kever.toad == 2
        assert tamHab.kever.sn == 0
        assert tamHab.kever.tholder.thold == 1 == int(tsith,16)
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
        watHab = watHby.makeHab(name="wat", isith=wsith, icount=1, transferable=False,)
        assert not watHab.kever.prefixer.transferable
        watKvy = eventing.Kevery(db=watHab.db, lax=False, local=False)

        # setup Nel's config
        curls = ["tcp://localhost:5621/"]
        iurls = [f"tcp://localhost:5620/?role={kering.Roles.peer}&name={cname}"]
        assert (conf := nelHby.cf.get()) == {}
        conf = dict(dt=help.nowIso8601(), nel=dict(dt=help.nowIso8601(), curls=curls), iurls=iurls)
        nelHby.cf.put(conf)

        assert nelHby.cf.get() == {'dt': '2021-01-01T00:00:00.000000+00:00',
                                   'nel': {
                                       'dt': '2021-01-01T00:00:00.000000+00:00',
                                       'curls': ['tcp://localhost:5621/'],
                                   },
                                   'iurls': ['tcp://localhost:5620/?role=peer&name=tam']}

        # setup Nel's habitat nontrans
        nelHab = nelHby.makeHab(name="nel", isith=wsith, icount=1, transferable=False)
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


    assert not os.path.exists(nelHby.cf.path)
    assert not os.path.exists(nelHby.db.path)
    assert not os.path.exists(nelHby.ks.path)
    assert not os.path.exists(watHby.cf.path)
    assert not os.path.exists(watHby.db.path)
    assert not os.path.exists(watHby.ks.path)
    assert not os.path.exists(wokHby.cf.path)
    assert not os.path.exists(wokHby.db.path)
    assert not os.path.exists(wokHby.ks.path)
    assert not os.path.exists(wesHby.cf.path)
    assert not os.path.exists(wesHby.db.path)
    assert not os.path.exists(wesHby.ks.path)
    assert not os.path.exists(tamHby.cf.path)
    assert not os.path.exists(tamHby.db.path)
    assert not os.path.exists(tamHby.ks.path)
    """Done Test"""


if __name__ == "__main__":
    test_make_load_hab_with_habery()
    # test_habitat_reinitialization_reload()
    # pytest.main(['-vv', 'test_reply.py::test_reply'])
