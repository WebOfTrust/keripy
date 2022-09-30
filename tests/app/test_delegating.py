# -*- encoding: utf-8 -*-
"""
tests.app.delegating module

"""
import time
from hio.base import doing, tyming

from keri import kering
from keri.app import habbing, delegating, indirecting, agenting, notifying
from keri.core import eventing, parsing, coring
from keri.db import dbing
from keri.end import ending
from keri.peer import exchanging


def test_boatswain(seeder):
    with habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="del", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as delHby:

        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)
        witDoer = agenting.WitnessReceiptor(hby=palHby)
        bts = delegating.Boatswain(hby=delHby)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.tcp])
        seeder.seedWitEnds(delHby.db, witHabs=[wesHab], protocols=[kering.Schemes.tcp])

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            delHby=delHby,
            witDoer=witDoer,
            bts=bts
        )

        doers = wesDoers + [witDoer, bts, doing.doify(boatswain_test_do, **opts)]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()

        palHab = palHby.habByName("pal")
        delHab = delHby.habByName("del")
        # Get the key of the seal we will create when delegation is anchored
        dgkey = dbing.dgKey(delHab.kever.prefixer.qb64b, delHab.kever.serder.saidb)
        # Get the value of the seal created when delegation is anchored
        couple = coring.Seqner(sn=palHab.kever.sn).qb64b + palHab.kever.serder.saidb
        assert bytes(delHby.db.getAes(dgkey)) == couple


def boatswain_test_do(tymth=None, tock=0.0, **opts):
    yield tock  # enter context

    wesHab = opts["wesHab"]
    palHby = opts["palHby"]
    delHby = opts["delHby"]
    witDoer = opts["witDoer"]
    bts = opts["bts"]

    palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True)

    assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

    witDoer.msgs.append(dict(pre=palHab.pre))
    while not witDoer.cues:
        yield tock
    witDoer.cues.popleft()

    msg = next(wesHab.db.clonePreIter(pre=palHab.pre))
    kvy = eventing.Kevery(db=delHby.db, local=False)
    parsing.Parser().parseOne(ims=bytearray(msg), kvy=kvy)

    while palHab.pre not in delHby.kevers:
        yield tock

    delHab = delHby.makeHab(name="del", icount=1, isith='1', ncount=1, nsith='1',
                            wits=[wesHab.pre],
                            delpre=palHab.pre)
    assert delHab.pre == "EGyXT1FmEeI05xmaBsYs2H4v8bazCy-JClB21rAfvXZu"

    bts.msgs.append(dict(pre=delHab.pre))

    palHab.rotate(data=[dict(i=delHab.pre, s="0", d=delHab.kever.serder.said)])
    witDoer.msgs.append(dict(pre=palHab.pre))
    while not witDoer.cues:
        yield tock
    witDoer.cues.popleft()

    # Get the key of the seal we will create when delegation is anchored
    dgkey = dbing.dgKey(delHab.kever.prefixer.qb64b, delHab.kever.serder.saidb)
    # Get the value of the seal created when delegation is anchored
    couple = coring.Seqner(sn=palHab.kever.sn).qb64b + palHab.kever.serder.saidb

    msg = next(wesHab.db.clonePreIter(pre=palHab.pre, fn=1))
    kvy = eventing.Kevery(db=delHby.db, local=False)
    parsing.Parser().parseOne(ims=bytearray(msg), kvy=kvy)

    # Wait for the anchor.  If we timeout before that happens, assertion in test will fail
    while delHby.db.getAes(dgkey) != couple:
        yield tock


def test_boatswain_proxy():
    with habbing.openHby(name="deltest", temp=True) as eeHby, \
            habbing.openHby(name="deltest", temp=True) as orHby:
        orHab = orHby.makeHab("delegator", transferable=True)
        assert orHab.pre == "EKL3to0Q059vtxKi7wWmaNFJ3NKE1nQsOPasRXqPzpjS"
        eeHab = eeHby.makeHab("del", transferable=True, delpre=orHab.pre,
                              wits=["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                                    "BAyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                                    "BBoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]

                              )
        assert eeHab.pre == 'EAszJpIhVoFsTw_fqOXT7N0yQbyPS-S1LV3FGvqUVcye'

        boats = delegating.Boatswain(hby=eeHby)
        phab = boats.proxy("deltest", eeHab.kever)

        assert phab.pre == 'EJXiQ33u2yXCtkH7UImC4D-RverPqvshuTlJyaAybKi4'
        assert phab.kever.wits == eeHab.kever.wits
        assert phab.kever.toader.num == eeHab.kever.toader.num
        assert phab.kever.tholder.sith == eeHab.kever.tholder.sith


def test_delegation_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True) as (hby, hab):

        delpre = "EArzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        serder = eventing.delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=delpre,
                                  nkeys=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])
        exn, atc = delegating.delegateRequestExn(hab=hab, delpre=delpre, ked=serder.ked)

        assert exn.ked["r"] == '/delegate/request'
        assert exn.saidb == b'ECExH5XhemF79vJOPuhIHzuWG-Zpc8ckIKkB1e3UDfzf'
        assert atc == (b'-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAADpPd_zfD-Q'
                       b'60O7de1woc7H6UJUCaiuUIzKs_MgRcrxjfH_5h6HzfI6B-rjt0pgCJRNFKgVRgv4'
                       b'llWS_u6DS58I')
        data = exn.ked["a"]
        assert data["delpre"] == delpre
        assert data["ked"] == serder.ked


def test_delegation_request_handler(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True) as (hby, hab):

        src = "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        ctrl = "EIwLgWhrDj2WI4WCiArWVAYsarrP-B48OM4T6_Wk6BLs"
        serder = eventing.delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=hab.pre,
                                  nkeys=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])

        notifier = notifying.Notifier(hby=hby)
        handler = delegating.DelegateRequestHandler(hby=hby, notifier=notifier)

        # Pass message missing keys:
        handler.msgs.append(dict(name="value"))
        handler.msgs.append(dict(pre=hab.kever.prefixer))
        handler.msgs.append(dict(pre=hab.kever.prefixer, payload=dict(delpre=hab.pre)))
        handler.msgs.append(dict(pre=hab.kever.prefixer, payload=dict(delpre=src, ked=serder.ked)))
        handler.msgs.append(dict(pre=hab.kever.prefixer, payload=dict(delpre=hab.pre, ked=serder.ked)))
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[handler])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        assert len(notifier.getNotes()) == 1

    with habbing.openHab(name="test", temp=True) as (hby, hab):

        src = "EfrzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        ctrl = "EIwLgWhrDj2WI4WCiArWVAYsarrP-B48OM4T6_Wk6BLs"
        serder = eventing.delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=hab.pre,
                                  nkeys=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])

        exn, atc = delegating.delegateRequestExn(hab=hab, delpre=hab.pre, ked=serder.ked)

        notifier = notifying.Notifier(hby=hby)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        oobiery = ending.Oobiery(hby=hby)

        delegating.loadHandlers(hby=hby, exc=exc, notifier=notifier)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        parsing.Parser().parseOne(ims=ims, exc=exc)

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=[exc])
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

        notes = notifier.getNotes()
        assert len(notes) == 1
        note = notes[0]
        assert note.pad['a']['r'] == '/delegate/request'
        assert note.pad['a']['ked'] == {'a': [],
                                        'b': [],
                                        'bt': '0',
                                        'c': [],
                                        'd': 'EAaXhAxAYiaJidAKLd4r1j_6gN3GTC-pP3UZmECnIEKv',
                                        'di': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                                        'i': 'EAaXhAxAYiaJidAKLd4r1j_6gN3GTC-pP3UZmECnIEKv',
                                        'k': ['DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs'],
                                        'kt': '1',
                                        'n': ['DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k'],
                                        'nt': '1',
                                        's': '0',
                                        't': 'dip',
                                        'v': 'KERI10JSON00015f_'}
