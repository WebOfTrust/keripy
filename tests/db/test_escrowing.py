# -*- encoding: utf-8 -*-
"""
tests.db.escrowing module

"""
from keri.kering import OutOfOrderError, Kinds

from keri.core import (Salter, Seqner, Diger, Saider, Dater,
                       SerderKERI, SealEvent, Saids, reply)

from keri.app import openHby, openHab
from keri.db import (Broker, CesrIoSetSuber, CesrSuber,
                     SerderSuber, CatCesrIoSetSuber, openLMDB)
from keri.help import helping
from keri.vdr import RegStateRecord, Regery


def test_broker():
    with openLMDB() as db:
        bork = Broker(db=db, subkey="test")

        assert isinstance(bork.escrowdb, CesrIoSetSuber)
        assert isinstance(bork.daterdb, CesrSuber)
        assert isinstance(bork.serderdb, SerderSuber)
        assert isinstance(bork.tigerdb, CesrIoSetSuber)
        assert isinstance(bork.cigardb, CatCesrIoSetSuber)
        assert isinstance(bork.escrowdb, CesrIoSetSuber)



def test_broker_nontrans():
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salter = Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    with openLMDB() as brokerdb, \
         openHby(name="wes", base="test", salt=salt) as wesHby, \
         openHab(name="pal") as (hby, hab):

        regery = Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=Diger(qb64=hab.kever.serder.said))
        regery.processEscrows()
        rsr = issuer.tever.state()  # registry state RegStateRecord
        rpy = reply(route="/tsn/registry/" + issuer.regk, data=rsr._asdict())

        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False)
        bork = Broker(db=brokerdb, subkey="test")

        dts = helping.nowIso8601()
        typ = "test"

        ked = rpy.ked
        pre = ked['a']['i']
        aid = "EBWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"

        serder = SerderKERI(sad=ked)
        rrsr = RegStateRecord._fromdict(ked["a"])  # reply RegStateRecord
        #tserder = SerderKERI(sad=ked["a"])

        saider, _ = Saider.saidify(sad=ked, kind=Kinds.json, label=Saids.d)
        dater = Dater(dts=dts)

        cigars = wesHab.sign(ser=serder.raw,
                             verfers=wesHab.kever.verfers,
                             indexed=False)

        bork.escrowStateNotice(typ=typ,
                               pre=saider.qb64,
                               aid=aid,
                               serder=serder,
                               diger=saider,
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
            #tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateReply(aid=aid, serder=serder, diger=kwargs["diger"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64


def test_broker_trans():

    with openLMDB() as brokerdb, \
         openHby(name="bob", base="test") as bobHby, \
         openHab(name="pal") as (hby, hab):

        regery = Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=Diger(qb64=hab.kever.serder.said))
        regery.processEscrows()
        rsr = issuer.tever.state() # registry state RegStateRecord
        rpy = reply(route="/tsn/registry/" + issuer.regk, data=rsr._asdict())
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)

        bork = Broker(db=brokerdb, subkey="test")
        dts = helping.nowIso8601()
        typ = "test"
        ked = rpy.ked

        pre = issuer.regk
        aid = "EwWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"
        serder = SerderKERI(sad=ked)
        rrsr = RegStateRecord._fromdict(ked["a"])  # reply RegStateRecord
        #tserder = SerderKERI(sad=ked["a"])
        saider, _ = Saider.saidify(sad=ked, kind=Kinds.json, label=Saids.d)
        dater = Dater(dts=dts)

        sigers = bobHab.sign(ser=serder.raw,
                             verfers=bobHab.kever.verfers,
                             indexed=True)

        tsgs = [(bobHab.kever.prefixer, Seqner(sn=bobHab.kever.lastEst.s),
                Diger(qb64=bobHab.kever.lastEst.d), sigers)]
        bork.escrowStateNotice(typ=typ,
                               pre=saider.qb64,
                               aid=aid,
                               serder=serder,
                               diger=saider,
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
            #tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateReply(aid=aid, serder=serder, diger=kwargs["diger"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64


if __name__ == "__main__":
    test_broker()
    test_broker_nontrans()
    test_broker_trans()
