# -*- encoding: utf-8 -*-
"""
tests.db.escrowing module

"""
from keri import kering
from keri.app import habbing
from keri.core import coring
from keri.db import escrowing, dbing, subing
from keri.help import helping


def test_broker():
    with dbing.openLMDB() as db:
        bork = escrowing.Broker(db=db, subkey="test")

        assert isinstance(bork.escrowdb, subing.CesrIoSetSuber)
        assert isinstance(bork.daterdb, subing.CesrSuber)
        assert isinstance(bork.serderdb, subing.SerderSuber)
        assert isinstance(bork.tigerdb, subing.CesrIoSetSuber)
        assert isinstance(bork.cigardb, subing.CatCesrIoSetSuber)
        assert isinstance(bork.escrowdb, subing.CesrIoSetSuber)
        assert isinstance(bork.saiderdb, subing.CesrSuber)


def test_broker_nontrans():
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = coring.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    #with dbing.openLMDB() as db, \
            #basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS:

    with dbing.openLMDB() as brokerdb, \
        habbing.openHby(name="wes", base="test", salt=salt) as wesHby:

        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False)
        #wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                 #isith='1', icount=1,
                                 #salt=salt, transferable=False, temp=True)

        bork = escrowing.Broker(db=brokerdb, subkey="test")

        dts = helping.nowIso8601()
        typ = "test"
        ked = {'v': 'KERI10JSON0001fb_', 't': 'rpy', 'd': 'E--rpyw2A5OATjluDezNIcgeMvLTSYALvMqVKnop-lJo',
               'dt': dts,
               'r': '/tsn/credential/Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI',
               'a': {'v': 'KERI10JSON000135_', 'i': 'EZc4FuRsgMJ3nagRMmz7kSCsh2VCHj9yI0fpaUOZf3Zs', 's': '0',
                     'd': 'EG6VAER9fTbirNC313PrMVdlJeaFjia4xBxYvhfmTQIw',
                     'ri': 'ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc', 'ra': {},
                     'a': {'s': 2, 'd': 'ElcdRh_66cR79tYDs7Q2OjjOjiAf_SZp6lWERgG1aSs8'},
                     'dt': dts, 'et': 'iss'}}
        pre = "EZc4FuRsgMJ3nagRMmz7kSCsh2VCHj9yI0fpaUOZf3Zs"
        aid = "EwWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"
        serder = coring.Serder(ked=ked)
        tserder = coring.Serder(ked=ked["a"])
        saider, _ = coring.Saider.saidify(sad=ked, kind=coring.Serials.json, label=coring.Ids.d)
        dater = coring.Dater(dts=dts)

        cigars = wesHab.sign(ser=serder.raw,
                             verfers=wesHab.kever.verfers,
                             indexed=False)

        bork.escrowStateNotice(typ=typ,
                               pre=saider.qb64,
                               aid=aid,
                               serder=serder,
                               saider=saider,
                               dater=dater,
                               cigars=cigars
                               )

        assert [s.qb64 for s in bork.escrowdb.get(keys=("test", saider.qb64, aid))] == [saider.qb64]
        assert [c.qb64 for (v, c) in bork.cigardb.get(keys=(saider.qb64,))] == [c.qb64 for c in cigars]
        assert bork.daterdb.get(keys=(saider.qb64,)).raw == dater.raw
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw

        def process(**kwargs):
            assert kwargs["route"] == ked["r"]
            assert [c.qb64 for c in kwargs["cigars"]] == [c.qb64 for c in cigars]
            assert kwargs["tsgs"] == []
            assert kwargs["aid"] == aid
            tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateState(aid=aid, serder=tser, saider=kwargs["saider"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=kering.OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == tserder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64


def test_broker_trans():
    #with dbing.openLMDB() as db, \
            #basing.openDB(name="bob") as bobDB, keeping.openKS(name="bob") as bobKS:
        #bobHab = habbing.Habitat(name="bob", ks=bobKS, db=bobDB, isith='1', icount=1, transferable=True,
                                 #wits=[], temp=True)

    with dbing.openLMDB() as brokerdb, \
        habbing.openHby(name="bob", base="test") as bobHby:

        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)

        bork = escrowing.Broker(db=brokerdb, subkey="test")
        dts = helping.nowIso8601()
        typ = "test"
        ked = {'v': 'KERI10JSON0001fb_', 't': 'rpy', 'd': 'E--rpyw2A5OATjluDezNIcgeMvLTSYALvMqVKnop-lJo',
               'dt': dts,
               'r': '/tsn/credential/Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI',
               'a': {'v': 'KERI10JSON000135_', 'i': 'EZc4FuRsgMJ3nagRMmz7kSCsh2VCHj9yI0fpaUOZf3Zs', 's': '0',
                     'd': 'EG6VAER9fTbirNC313PrMVdlJeaFjia4xBxYvhfmTQIw',
                     'ri': 'ECWWojIv_2OqlFL7BSwkyd69_vWKYaTUU5jUhxhXvjmc', 'ra': {},
                     'a': {'s': 2, 'd': 'ElcdRh_66cR79tYDs7Q2OjjOjiAf_SZp6lWERgG1aSs8'},
                     'dt': dts, 'et': 'iss'}}
        pre = "EZc4FuRsgMJ3nagRMmz7kSCsh2VCHj9yI0fpaUOZf3Zs"
        aid = "EwWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"
        serder = coring.Serder(ked=ked)
        tserder = coring.Serder(ked=ked["a"])
        saider, _ = coring.Saider.saidify(sad=ked, kind=coring.Serials.json, label=coring.Ids.d)
        dater = coring.Dater(dts=dts)

        sigers = bobHab.sign(ser=serder.raw,
                             verfers=bobHab.kever.verfers,
                             indexed=True)

        tsgs = [(bobHab.kever.prefixer, coring.Seqner(sn=bobHab.kever.lastEst.s),
                coring.Diger(qb64=bobHab.kever.lastEst.d), sigers)]
        bork.escrowStateNotice(typ=typ,
                               pre=saider.qb64,
                               aid=aid,
                               serder=serder,
                               saider=saider,
                               dater=dater,
                               tsgs=tsgs
                               )

        assert [s.qb64 for s in bork.escrowdb.get(keys=("test", saider.qb64, aid))] == [saider.qb64]
        quadkeys = (saider.qb64, bobHab.kever.prefixer.qb64, f"{bobHab.kever.lastEst.s:032x}", bobHab.kever.lastEst.d)
        assert [s.qb64 for s in bork.tigerdb.get(keys=quadkeys)] == [s.qb64 for s in sigers]
        assert bork.daterdb.get(keys=(saider.qb64,)).raw == dater.raw
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw

        def process(**kwargs):
            assert kwargs["route"] == ked["r"]
            assert len(kwargs["tsgs"]) == 1
            (prefixer, seqner, diger, sigs) = kwargs["tsgs"][0]
            assert [s.qb64 for s in sigs] == [s.qb64 for s in sigers]
            assert kwargs["cigars"] == []
            assert kwargs["aid"] == aid
            tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateState(aid=aid, serder=tser, saider=kwargs["saider"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=kering.OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == tserder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64
