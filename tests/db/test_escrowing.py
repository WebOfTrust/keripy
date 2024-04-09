# -*- encoding: utf-8 -*-
"""
tests.db.escrowing module

"""
from keri import kering

from keri import core
from keri.core import coring, eventing, serdering

from keri.app import habbing

from keri.core.eventing import SealEvent
from keri.db import escrowing, dbing, subing
from keri.help import helping
from keri.vdr import credentialing, viring


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
    salter = core.Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'

    with dbing.openLMDB() as brokerdb, \
         habbing.openHby(name="wes", base="test", salt=salt) as wesHby, \
         habbing.openHab(name="pal") as (hby, hab):

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()
        rsr = issuer.tever.state()  # registry state RegStateRecord
        rpy = eventing.reply(route="/tsn/registry/" + issuer.regk, data=rsr._asdict())

        wesHab = wesHby.makeHab(name="wes", isith='1', icount=1, transferable=False)
        bork = escrowing.Broker(db=brokerdb, subkey="test")

        dts = helping.nowIso8601()
        typ = "test"

        ked = rpy.ked
        pre = ked['a']['i']
        aid = "EBWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"

        serder = serdering.SerderKERI(sad=ked)
        rrsr = viring.RegStateRecord._fromdict(ked["a"])  # reply RegStateRecord
        #tserder = serdering.SerderKERI(sad=ked["a"])

        saider, _ = coring.Saider.saidify(sad=ked, kind=coring.Serials.json, label=coring.Saids.d)
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
            #tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateReply(aid=aid, serder=serder, saider=kwargs["saider"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=kering.OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64


def test_broker_trans():

    with dbing.openLMDB() as brokerdb, \
         habbing.openHby(name="bob", base="test") as bobHby, \
         habbing.openHab(name="pal") as (hby, hab):

        regery = credentialing.Regery(hby=hby, name=hab.name, temp=True)
        issuer = regery.makeRegistry(prefix=hab.pre, name=hab.name)
        rseal = SealEvent(issuer.regk, "0", issuer.regd)._asdict()
        hab.interact(data=[rseal])
        seqner = coring.Seqner(sn=hab.kever.sn)
        issuer.anchorMsg(pre=issuer.regk,
                         regd=issuer.regd,
                         seqner=seqner,
                         saider=coring.Saider(qb64=hab.kever.serder.said))
        regery.processEscrows()
        rsr = issuer.tever.state() # registry state RegStateRecord
        rpy = eventing.reply(route="/tsn/registry/" + issuer.regk, data=rsr._asdict())
        bobHab = bobHby.makeHab(name="bob", isith='1', icount=1, transferable=True)

        bork = escrowing.Broker(db=brokerdb, subkey="test")
        dts = helping.nowIso8601()
        typ = "test"
        ked = rpy.ked

        pre = issuer.regk
        aid = "EwWY7LU2xwp0d4IhCvz1etbuv2iwcgBEigKJWnd-0Whs"
        serder = serdering.SerderKERI(sad=ked)
        rrsr = viring.RegStateRecord._fromdict(ked["a"])  # reply RegStateRecord
        #tserder = serdering.SerderKERI(sad=ked["a"])
        saider, _ = coring.Saider.saidify(sad=ked, kind=coring.Serials.json, label=coring.Saids.d)
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
            #tser = coring.Serder(ked=kwargs["serder"].ked["a"])
            bork.updateReply(aid=aid, serder=serder, saider=kwargs["saider"], dater=dater)

        bork.processEscrowState(typ=typ, processReply=process, extype=kering.OutOfOrderError)

        assert bork.escrowdb.get(keys=("test", saider.qb64, aid)) == []
        assert bork.serderdb.get(keys=(saider.qb64,)).raw == serder.raw
        assert bork.saiderdb.get(keys=(pre, aid)).qb64 == saider.qb64


if __name__ == "__main__":
    test_broker()
    test_broker_nontrans()
    test_broker_trans()
