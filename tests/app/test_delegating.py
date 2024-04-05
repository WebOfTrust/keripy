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


def test_anchorer(seeder):
    with habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=coring.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="del", salt=coring.Salter(raw=b'0123456789ghijkl').qb64) as delHby:

        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)
        witDoer = agenting.Receiptor(hby=palHby)
        bts = delegating.Anchorer(hby=delHby)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http])
        seeder.seedWitEnds(delHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http])

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            delHby=delHby,
            witDoer=witDoer,
            bts=bts
        )

        doers = wesDoers + [witDoer, bts, doing.doify(anchorer_test_do, **opts)]

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


def anchorer_test_do(tymth=None, tock=0.0, **opts):
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
    kvy = eventing.Kevery(db=delHby.db, local=True)
    parsing.Parser().parseOne(ims=bytearray(msg), kvy=kvy, local=True)

    while palHab.pre not in delHby.kevers:
        yield tock

    proxyHab = delHby.makeHab(name="proxy", icount=1, isith='1', ncount=1, nsith='1',
                              wits=[wesHab.pre])
    assert proxyHab.pre == "EIQ9wnMWGxZHlontoBMp5-GPyVecLL99XrCVxmTCO22b"

    delHab = delHby.makeHab(name="del", icount=1, isith='1', ncount=1, nsith='1',
                            wits=[wesHab.pre],
                            delpre=palHab.pre)
    assert delHab.pre == "EGyXT1FmEeI05xmaBsYs2H4v8bazCy-JClB21rAfvXZu"

    bts.delegation(pre=delHab.pre, proxy=proxyHab)
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
    kvy = eventing.Kevery(db=delHby.db, local=True)
    parsing.Parser().parseOne(ims=bytearray(msg), kvy=kvy, local=True)

    # Wait for the anchor.  If we timeout before that happens, assertion in test will fail
    while delHby.db.getAes(dgkey) != couple:
        yield tock


def test_delegation_request(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True, salt=b'0123456789abcdef') as (hby, hab):

        delpre = "EArzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        serder = eventing.delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=delpre,
                                  ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])
        evt = hab.endorse(serder=serder)
        exn, atc = delegating.delegateRequestExn(hab=hab, delpre=delpre, evt=evt)

        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAADECnBl'
                       b'0c14SVi7Keh__sd1PVhinSy-itPr33ZxvSjJYFastqXw9ZTFGNKsY6iALUk5xP3S'
                       b'399tJrPFe7PtuNAN')

        assert exn.ked["r"] == '/delegate/request'
        assert exn.saidb == b'EOiDc2wEmhHc7sbLG64y2gveCIRlFe4BuISaz0mlOuZz'
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI30AAAAAAAAAAAAAAA'
                       b'AAAAAAAAEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAADECnBl'
                       b'0c14SVi7Keh__sd1PVhinSy-itPr33ZxvSjJYFastqXw9ZTFGNKsY6iALUk5xP3S'
                       b'399tJrPFe7PtuNAN')
        data = exn.ked["a"]
        assert data["delpre"] == delpre
        embeds = exn.ked['e']
        assert embeds["evt"] == serder.ked


def test_delegation_request_handler(mockHelpingNowUTC):
    with habbing.openHab(name="test", temp=True) as (hby, hab):

        serder = eventing.delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=hab.pre,
                                  ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"])

        evt = hab.endorse(serder=serder)
        notifier = notifying.Notifier(hby=hby)
        handler = delegating.DelegateRequestHandler(hby=hby, notifier=notifier)
        exn, _ = delegating.delegateRequestExn(hab, hab.pre, evt=evt)

        handler.handle(serder=exn)

        assert len(notifier.getNotes()) == 1
