# -*- encoding: utf-8 -*-
"""
tests.vdr.test_credentialing module

"""
from keri import kering

from keri.app import keeping
from keri.core import serdering
from keri.core import eventing as keventing
from keri.core.coring import Number, Saider, Diger
from keri.db import basing
from keri.vdr.credentialing import Regery, Registrar

from tests.vdr import buildHab


def test_tpwe():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        registrar = Registrar(hby=hby, rgy=rgy, counselor=None)

        prefixer = hab.kever.prefixer
        rnum = Number(num=0)

        # incept: inject into tpwe, verify present
        reg_inc = rgy.makeRegistry(name="tpwe_inc", prefix=hab.pre, noBackers=True)
        number_inc = Number(num=hab.kever.sner.num)
        diger_inc = Diger(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_inc.regk, rnum.huge),
                           val=(prefixer, number_inc, diger_inc))
        assert len(rgy.reger.tpwe.get(keys=(reg_inc.regk, rnum.huge))) == 1

        # issue: anchor vcp so iss is valid, inject into tpwe
        reg_iss = rgy.makeRegistry(name="tpwe_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rnum_iss = Number(numh=iss.ked["s"])
        rgy.reger.tpwe.add(keys=(vcdig, rnum_iss.huge),
                           val=(prefixer, Number(num=hab.kever.sner.num), Diger(qb64=hab.kever.serder.said)))
        assert len(rgy.reger.tpwe.get(keys=(vcdig, rnum_iss.huge))) == 1

        # revoke: anchor vcp+iss, inject rev into tpwe, verify number value
        reg_rev = rgy.makeRegistry(name="tpwe_rev", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = keventing.SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=iss2,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rev = reg_rev.revoke(said=vcdig)
        rnum_rev = Number(numh=rev.ked["s"])
        expected_kel_sn = hab.kever.sner.num
        rgy.reger.tpwe.add(keys=(vcdig, rnum_rev.huge),
                           val=(prefixer, Number(num=expected_kel_sn), Diger(qb64=hab.kever.serder.said)))
        entries = rgy.reger.tpwe.get(keys=(vcdig, rnum_rev.huge))
        assert len(entries) == 1
        _, num_obj, _ = entries[0]
        assert num_obj.num == expected_kel_sn

        # processWitnessEscrow drains tpwe and seeds tede
        reg_pwe = rgy.makeRegistry(name="pwe_drain", prefix=hab.pre, noBackers=True)
        number_pwe = Number(num=hab.kever.sner.num)
        diger_pwe = Diger(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rnum.huge),
                           val=(prefixer, number_pwe, diger_pwe))
        registrar.processWitnessEscrow()

        assert rgy.reger.tpwe.get(keys=(reg_pwe.regk, rnum.huge)) == []
        assert len(rgy.reger.tede.get(keys=(reg_pwe.regk, rnum.huge))) == 1

        # processWitnessEscrow is a no-op when tpwe is empty
        registrar.processWitnessEscrow()  # must not raise


def test_tmse():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    # tmse is populated correctly (inject and verify entries)
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=hab.kever.sner.num)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # incept
        reg_inc = rgy.makeRegistry(name="tmse_inc", prefix=hab.pre, noBackers=True)
        rgy.reger.tmse.add(keys=(reg_inc.regk, rnum.huge, reg_inc.regd),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(reg_inc.regk, rnum.huge, reg_inc.regd))) == 1

        # issue
        reg_iss = rgy.makeRegistry(name="tmse_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rnum_iss = Number(numh=iss.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rnum_iss.huge, iss.said),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rnum_iss.huge, iss.said))) == 1

        # revoke
        reg_rev = rgy.makeRegistry(name="tmse_rev", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = keventing.SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=iss2,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rev = reg_rev.revoke(said=vcdig)
        rnum_rev = Number(numh=rev.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rnum_rev.huge, rev.said),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rnum_rev.huge, rev.said))) == 1

    # processMultisigEscrow is a no-op when counselor.complete is False
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _NeverComplete:
            def complete(self, *a, **kw): return False

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_NeverComplete())
        reg = rgy.makeRegistry(name="tmse_noop", prefix=hab.pre, noBackers=True)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) != []
        assert rgy.reger.tede.get(keys=(reg.regk, rnum.huge)) == []

    # processMultisigEscrow drains tmse and seeds tede when complete
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        registrar = Registrar(
            hby=hby,
            rgy=rgy,
            counselor=type("C", (), {"complete": lambda self, *a, **kw: True})()
        )

        reg = rgy.makeRegistry(name="tmse_drain", prefix=hab.pre, noBackers=True)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) == []
        assert len(rgy.reger.tede.get(keys=(reg.regk, rnum.huge))) == 1

    # processMultisigEscrow drops entry on ValidationError
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _RaisesValidation:
            def complete(self, *a, **kw): raise kering.ValidationError("bad")

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_RaisesValidation())
        reg = rgy.makeRegistry(name="tmse_valerr", prefix=hab.pre, noBackers=True)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) == []


def test_tede():
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        registrar = Registrar(
            hby=hby,
            rgy=rgy,
            counselor=type("C", (), {"complete": lambda self, *a, **kw: True})()
        )

        prefixer = hab.kever.prefixer
        diger_hab = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # processWitnessEscrow seeds tede with correct values
        reg_pwe = rgy.makeRegistry(name="tede_pwe", prefix=hab.pre, noBackers=True)
        number_pwe = Number(num=hab.kever.sner.num)

        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))
        registrar.processWitnessEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_pwe.regk, rnum.huge))) == 1

        # getItemIter is the read path used by processDisseminationEscrow
        found = False
        for (regk, _), triple in rgy.reger.tede.getItemIter():
            if regk == reg_pwe.regk:
                found = True
        assert found, "tede.getItemIter yielded no entry for our regk"

        # processMultisigEscrow seeds tede with correct values
        reg_ms = rgy.makeRegistry(name="tede_ms", prefix=hab.pre, noBackers=True)
        number_ms = Number(num=7)  # distinct value to tell apart from number_pwe

        rgy.reger.tmse.add(keys=(reg_ms.regk, rnum.huge, reg_ms.regd),
                           val=(prefixer, number_ms, diger_hab))
        registrar.processMultisigEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_ms.regk, rnum.huge))) == 1

        registrar.counselor = type("C", (), {"complete": lambda self, *a, **kw: False})()

        # processDisseminationEscrow is a no-op when tels has no digest
        reg_noop = rgy.makeRegistry(name="diss_noop", prefix=hab.pre, noBackers=True)
        rgy.reger.tede.add(keys=(reg_noop.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))

        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_noop.regk, rnum.huge)) != []

        # processDisseminationEscrow drains tede, writes ctel, publishes
        # anchor reg_drain so tels has a digest at sn=0
        reg_drain = rgy.makeRegistry(name="diss_drain", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_drain.vcp.pre, s=reg_drain.vcp.ked["s"], d=reg_drain.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_drain.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rgy.reger.tede.add(keys=(reg_drain.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))

        before = len(registrar.witPub.msgs)
        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_drain.regk, rnum.huge)) == []
        assert rgy.reger.ctel.get(keys=(reg_drain.regk, rnum.huge)) is not None
        assert len(registrar.witPub.msgs) == before + 1


def test_escrow_suber_klas():
    SN = 42

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=SN)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # tpwe
        reg_tpwe = rgy.makeRegistry(name="klas_tpwe", prefix=hab.pre, noBackers=True)
        rgy.reger.tpwe.add(keys=(reg_tpwe.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tpwe.get(keys=(reg_tpwe.regk, rnum.huge))
        assert items, "tpwe entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tpwe.getItemIter():
            if regk == reg_tpwe.regk:
                found = True
        assert found, "tpwe getItemIter yielded nothing"

        # tmse
        reg_tmse = rgy.makeRegistry(name="klas_tmse", prefix=hab.pre, noBackers=True)
        rgy.reger.tmse.add(keys=(reg_tmse.regk, rnum.huge, reg_tmse.regd),
                           val=(prefixer, number, diger))

        items = rgy.reger.tmse.get(keys=(reg_tmse.regk, rnum.huge, reg_tmse.regd))
        assert items, "tmse entry missing"

        found = False
        for (regk, _, _), triple in rgy.reger.tmse.getItemIter():
            if regk == reg_tmse.regk:
                found = True
        assert found, "tmse getItemIter yielded nothing"

        # tede
        reg_tede = rgy.makeRegistry(name="klas_tede", prefix=hab.pre, noBackers=True)
        rgy.reger.tede.add(keys=(reg_tede.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tede.get(keys=(reg_tede.regk, rnum.huge))
        assert items, "tede entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tede.getItemIter():
            if regk == reg_tede.regk:
                found = True
        assert found, "tede getItemIter yielded nothing"


if __name__ == "__main__":
    test_tpwe()
    test_tmse()
    test_tede()
    test_escrow_suber_klas()
