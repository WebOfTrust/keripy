# -*- encoding: utf-8 -*-
"""
tests.app.delegating module

"""
import time
from types import SimpleNamespace

from hio.base import doing, tyming

from keri.kering import Schemes, Version, Vrsn_1_0, Kinds
from keri.core import Salter, Kevery, Parser, Seqner, Diger, delcept

from keri.app import (Anchorer, DelegateRequestHandler, Receiptor,
                      Notifier, setupWitness, openHby,
                      openHab, delegateRequestExn)
from keri.app import delegating

from tests.common import CUE_KWA, KWA


def test_anchorer_explicit_version_propagates_to_postman():
    with openHby(name="del", salt=Salter(raw=b'0123456789ghijkl').qb64, version=Version) as delHby:
        bts = Anchorer(hby=delHby, version=Vrsn_1_0, kind=Kinds.json)

        assert bts.postman.version == Vrsn_1_0
        assert bts.postman.kind == Kinds.json


def test_publish_delegator_republishes_delegate_event_with_anchor():
    publisher = SimpleNamespace(msgs=[])
    calls = {}

    def clone_delegation(_):
        yield b"delegator-msg"

    def msg_own_event(*, sn, framed, gvrsn):
        calls["msgOwnEvent"] = dict(sn=sn, framed=framed, gvrsn=gvrsn)
        return bytearray(b"delegate-msg")

    serder = SimpleNamespace(sn=1, pvrsn=Vrsn_1_0)
    hab = SimpleNamespace(pre="delegate-pre",
                          kever=SimpleNamespace(serder=serder),
                          db=SimpleNamespace(cloneDelegation=clone_delegation),
                          msgOwnEvent=msg_own_event)
    bts = Anchorer.__new__(Anchorer)
    bts.publishers = {"delegate-pre": publisher}
    bts.hby = SimpleNamespace(habs={"delegate-pre": hab})
    bts.extend = lambda doers: calls.setdefault("extended", []).extend(doers)

    bts.publishDelegator("delegate-pre", serder=serder)

    assert calls["extended"] == [publisher]
    assert calls["msgOwnEvent"] == dict(sn=1, framed=True, gvrsn=Vrsn_1_0)
    assert publisher.msgs == [
        dict(pre="delegate-pre", msg=b"delegator-msg"),
        dict(pre="delegate-pre", msg=b"delegate-msg"),
    ]

from tests.common import CUE_KWA, KWA


def test_anchorer(seeder):
    with openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64, version=Vrsn_1_0) as wesHby, \
            openHby(name="pal", salt=Salter(raw=b'0123456789abcdef').qb64, version=Vrsn_1_0) as palHby, \
            openHby(name="del", salt=Salter(raw=b'0123456789ghijkl').qb64, version=Vrsn_1_0) as delHby:

        wesDoers = setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644, **KWA)
        witDoer = Receiptor(hby=palHby)

        bts = Anchorer(hby=delHby, version=Vrsn_1_0, kind=Kinds.json)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[Schemes.http], **KWA)
        seeder.seedWitEnds(delHby.db, witHabs=[wesHab], protocols=[Schemes.http], **KWA)

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            delHby=delHby,
            witDoer=witDoer,
            bts=bts,
            kwa=KWA,
            cue_kwa=CUE_KWA,
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
        # Get the value of the seal created when delegation is anchored
        seqner = Seqner(sn=palHab.kever.sn)
        diger = Diger(qb64b=palHab.kever.serder.saidb)
        couple = seqner.qb64b + diger.qb64b
        result = delHby.db.aess.get(keys=(delHab.kever.prefixer.qb64b, delHab.kever.serder.saidb))
        assert result is not None
        rnumber, rdiger = result
        assert rnumber.qb64b + rdiger.qb64b == couple


def anchorer_test_do(tymth=None, tock=0.0, **opts):
    yield tock  # enter context

    wesHab = opts["wesHab"]
    palHby = opts["palHby"]
    delHby = opts["delHby"]
    witDoer = opts["witDoer"]
    bts = opts["bts"]
    kwa = opts["kwa"]
    cue_kwa = opts["cue_kwa"]

    palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True, **kwa)

    assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

    witDoer.msgs.append(dict(pre=palHab.pre))
    while not witDoer.cues:
        yield tock

    witDoer.cues.popleft()
    msg = next(wesHab.db.clonePreIter(pre=palHab.pre))
    kvy = Kevery(db=delHby.db, local=True)
    Parser(version=Vrsn_1_0).parseOne(ims=bytearray(msg), kvy=kvy, local=True)

    while palHab.pre not in delHby.kevers:
        yield tock

    proxyHab = delHby.makeHab(name="proxy", icount=1, isith='1', ncount=1, nsith='1',
                              wits=[wesHab.pre], **kwa)
    assert proxyHab.pre == "EIQ9wnMWGxZHlontoBMp5-GPyVecLL99XrCVxmTCO22b"

    delHab = delHby.makeHab(name="del", icount=1, isith='1', ncount=1, nsith='1',
                            wits=[wesHab.pre],
                            delpre=palHab.pre, **kwa)
    assert delHab.pre == "EGyXT1FmEeI05xmaBsYs2H4v8bazCy-JClB21rAfvXZu"

    bts.delegation(pre=delHab.pre, proxy=proxyHab)
    palHab.rotate(data=[dict(i=delHab.pre, s="0", d=delHab.kever.serder.said)],
                  framed=True, **cue_kwa)
    witDoer.msgs.append(dict(pre=palHab.pre))
    while not witDoer.cues:
        yield tock
    witDoer.cues.popleft()

    # Get the value of the seal created when delegation is anchored
    couple = Seqner(sn=palHab.kever.sn).qb64b + palHab.kever.serder.saidb

    msg = next(wesHab.db.clonePreIter(pre=palHab.pre, fn=1))
    kvy = Kevery(db=delHby.db, local=True)
    Parser(version=Vrsn_1_0).parseOne(ims=bytearray(msg), kvy=kvy, local=True)

    # Wait for the anchor.  If we timeout before that happens, assertion in test will fail
    seqner = Seqner(sn=palHab.kever.sn)
    diger = Diger(qb64b=palHab.kever.serder.saidb)
    couple = seqner.qb64b + diger.qb64b

    while result := delHby.db.aess.get(keys=(delHab.kever.prefixer.qb64b, delHab.kever.serder.saidb)):
        rnumber, rdiger = result
        if rnumber.qb64b + rdiger.qb64b == couple:
            break
        yield tock


def test_delegation_request(mockHelpingNowUTC):
    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (hby, hab):

        delpre = "EArzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        serder = delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=delpre,
                                  ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"],
                                  **KWA)
        evt = hab.endorse(serder=serder, framed=False, gvrsn=Vrsn_1_0)
        exn, atc = delegateRequestExn(hab=hab, delpre=delpre, evt=evt,
                                      version=Vrsn_1_0, kind=Kinds.json)

        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3MAAAEIaGMMWJFPmt'
                    b'XznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAACzeUyP6__0oDca-Oiv2iGXKghB'
                    b'w_8sI4ZHyyeMedvz0iZIIQYqJd2Zt7cDHRh7xBGWI85J_oOixLET3mFZUu0A')

        assert exn.ked["r"] == '/delegate/request'
        assert exn.saidb == b'EHPkcmdLGql9_1WD0wl0OalYk8PcF4HMMd7gGi-iqfSe'
        assert atc == (b'-FABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3MAAAEIaGMMWJFPmt'
                    b'XznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAACzeUyP6__0oDca-Oiv2iGXKghB'
                    b'w_8sI4ZHyyeMedvz0iZIIQYqJd2Zt7cDHRh7xBGWI85J_oOixLET3mFZUu0A')
        data = exn.ked["a"]
        assert data["delpre"] == delpre
        embeds = exn.ked['e']
        assert embeds["evt"] == serder.ked


def test_delegation_request_handler(mockHelpingNowUTC):
    with openHab(name="test", temp=True, **KWA) as (hby, hab):

        serder = delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=hab.pre,
                                  ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"],
                                  **KWA)

        evt = hab.endorse(serder=serder, framed=False, gvrsn=Vrsn_1_0)
        notifier = Notifier(hby=hby)
        handler = DelegateRequestHandler(hby=hby, notifier=notifier)
        exn, _ = delegateRequestExn(hab, hab.pre, evt=evt,
                                    version=Vrsn_1_0, kind=Kinds.json)

        handler.handle(serder=exn)

        assert len(notifier.getNotes()) == 1


def test_delegate_request_default_framing_uses_default_version_with_legacy_special_exn(mockHelpingNowUTC, monkeypatch):
    with openHab(name="test", temp=True, salt=b'0123456789abcdef', **KWA) as (_, hab):
        delpre = "EArzbTSWjccrTdNRsFUUfwaJ2dpYxu9_5jI2PJ-TRri0"
        serder = delcept(keys=["DUEFuPeaDH2TySI-wX7CY_uW5FF41LRu3a59jxg1_pMs"], delpre=delpre,
                         ndigs=["DLONLed3zFEWa0p21fvi1Jf5-x-EoyEPqFvOki3YhP1k"],
                         **KWA)
        evt = hab.endorse(serder=serder, framed=False, gvrsn=Vrsn_1_0)
        special_calls = {}
        endorse_calls = {}
        original_special_exchange = delegating.specialExchange
        original_endorse = hab.endorse

        def capture_special_exchange(*, sender, route, modifiers, attributes, embeds, version, kind):
            special_calls["version"] = version
            special_calls["kind"] = kind
            return original_special_exchange(sender=sender,
                                             route=route,
                                             modifiers=modifiers,
                                             attributes=attributes,
                                             embeds=embeds,
                                             version=version,
                                             kind=kind)

        def capture_endorse(*args, **kwargs):
            endorse_calls["gvrsn"] = kwargs.get("gvrsn")
            return original_endorse(*args, **kwargs)

        monkeypatch.setattr(delegating, "specialExchange", capture_special_exchange)
        monkeypatch.setattr(hab, "endorse", capture_endorse)

        delegateRequestExn(hab=hab, delpre=delpre, evt=evt)

        assert special_calls["version"] == Vrsn_1_0
        assert special_calls["kind"] == Kinds.json
        assert endorse_calls["gvrsn"] == Version
