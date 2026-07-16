# -*- encoding: utf-8 -*-
"""
tests.vdr.test_credentialing module

"""
from keri.kering import Ilks, ValidationError, Vrsn_1_0, Vrsn_2_0, Kinds

from keri.core import Number, Saider, Diger, SerderKERI, SealEvent, TraitDex

from keri.app import openKS
from keri.db import openDB
from keri.vdr import Credentialer, Regery, Registrar
from keri.vdr.eventing import incept

from tests.vdr import buildHab

from tests.common import KWA


def test_v1_registry_version_across_lifecycle_with_v2_identifier():
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, version=Vrsn_2_0, kind=Kinds.json)
        for registry_type in ("standard", "signify"):
            rgy = Regery(hby=hby, name=registry_type, temp=True)
            try:
                if registry_type == "standard":
                    registry = rgy.makeRegistry(
                        name="legacy",
                        prefix=hab.pre,
                        noBackers=True,
                        version=Vrsn_1_0,
                        kind=Kinds.json,
                    )
                    vcp = registry.vcp
                else:
                    vcp = incept(
                        pre=hab.pre,
                        cnfg=[TraitDex.NoBackers],
                        version=Vrsn_1_0,
                        kind=Kinds.json,
                    )
                    registry = rgy.makeSignifyRegistry(
                        name="legacy",
                        prefix=hab.pre,
                        regser=vcp,
                    )

                credentialer = Credentialer(
                    hby=hby,
                    rgy=rgy,
                    registrar=None,
                    verifier=None,
                )
                credentialer.validate = lambda creder: True

                def create_credential():
                    return credentialer.create(
                        regname="legacy",
                        recp=None,
                        schema="EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                        source=None,
                        rules=None,
                        data={"name": "Test"},
                    )

                creder = create_credential()
                assert creder.pvrsn == Vrsn_1_0
                assert creder.sad["ri"] == registry.regk

                seal = SealEvent(i=registry.regk, s="0", d=registry.regd)
                msg = hab.interact(
                    data=[seal._asdict()],
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                anchor = SerderKERI(raw=msg)
                rgy.tvy.processEvent(
                    serder=vcp,
                    seqner=Number(num=anchor.sn),
                    saider=Saider(qb64=anchor.said),
                )

                if registry_type == "standard":
                    rgy.regs.clear()
                    rgy.loadRegistries()
                    registry = rgy.registryByName("legacy")

                creder = create_credential()
                assert creder.pvrsn == Vrsn_1_0
                assert creder.sad["ri"] == registry.regk

                iserder = registry.issue(said=creder.said)
                assert iserder.pvrsn == Vrsn_1_0
                assert iserder.ilk == Ilks.iss
            finally:
                rgy.close()


def test_tpwe():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)
        registrar = Registrar(hby=hby, rgy=rgy, counselor=None)

        prefixer = hab.kever.prefixer
        rnum = Number(num=0)

        # incept: inject into tpwe, verify present
        reg_inc = rgy.makeRegistry(name="tpwe_inc", prefix=hab.pre, noBackers=True, **KWA)
        number_inc = Number(num=hab.kever.sner.num)
        diger_inc = Diger(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_inc.regk, rnum.huge),
                           val=(prefixer, number_inc, diger_inc))
        assert len(rgy.reger.tpwe.get(keys=(reg_inc.regk, rnum.huge))) == 1

        # issue: anchor vcp so iss is valid, inject into tpwe
        reg_iss = rgy.makeRegistry(name="tpwe_iss", prefix=hab.pre, noBackers=True, **KWA)
        rseal = SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rnum_iss = Number(numh=iss.ked["s"])
        rgy.reger.tpwe.add(keys=(vcdig, rnum_iss.huge),
                           val=(prefixer, Number(num=hab.kever.sner.num), Diger(qb64=hab.kever.serder.said)))
        assert len(rgy.reger.tpwe.get(keys=(vcdig, rnum_iss.huge))) == 1

        # revoke: anchor vcp+iss, inject rev into tpwe, verify number value
        reg_rev = rgy.makeRegistry(name="tpwe_rev", prefix=hab.pre, noBackers=True, **KWA)
        rseal = SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
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
        reg_pwe = rgy.makeRegistry(name="pwe_drain", prefix=hab.pre, noBackers=True, **KWA)
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
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=hab.kever.sner.num)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # incept
        reg_inc = rgy.makeRegistry(name="tmse_inc", prefix=hab.pre, noBackers=True, **KWA)
        rgy.reger.tmse.add(keys=(reg_inc.regk, rnum.huge, reg_inc.regd),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(reg_inc.regk, rnum.huge, reg_inc.regd))) == 1

        # issue
        reg_iss = rgy.makeRegistry(name="tmse_iss", prefix=hab.pre, noBackers=True, **KWA)
        rseal = SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rnum_iss = Number(numh=iss.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rnum_iss.huge, iss.said),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rnum_iss.huge, iss.said))) == 1

        # revoke
        reg_rev = rgy.makeRegistry(name="tmse_rev", prefix=hab.pre, noBackers=True, **KWA)
        rseal = SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=iss2,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rev = reg_rev.revoke(said=vcdig)
        rnum_rev = Number(numh=rev.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rnum_rev.huge, rev.said),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rnum_rev.huge, rev.said))) == 1

    # processMultisigEscrow is a no-op when counselor.complete is False
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _NeverComplete:
            def complete(self, *a, **kw): return False

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_NeverComplete())
        reg = rgy.makeRegistry(name="tmse_noop", prefix=hab.pre, noBackers=True, **KWA)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) != []
        assert rgy.reger.tede.get(keys=(reg.regk, rnum.huge)) == []

    # processMultisigEscrow drains tmse and seeds tede when complete
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)

        registrar = Registrar(
            hby=hby,
            rgy=rgy,
            counselor=type("C", (), {"complete": lambda self, *a, **kw: True})()
        )

        reg = rgy.makeRegistry(name="tmse_drain", prefix=hab.pre, noBackers=True, **KWA)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) == []
        assert len(rgy.reger.tede.get(keys=(reg.regk, rnum.huge))) == 1

    # processMultisigEscrow drops entry on ValidationError
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _RaisesValidation:
            def complete(self, *a, **kw): raise ValidationError("bad")

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_RaisesValidation())
        reg = rgy.makeRegistry(name="tmse_valerr", prefix=hab.pre, noBackers=True, **KWA)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) == []


def test_tede():
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
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
        reg_pwe = rgy.makeRegistry(name="tede_pwe", prefix=hab.pre, noBackers=True, **KWA)
        number_pwe = Number(num=hab.kever.sner.num)

        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))
        registrar.processWitnessEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_pwe.regk, rnum.huge))) == 1

        # getTopItemIter is the read path used by processDisseminationEscrow
        found = False
        for (regk, _), triple in rgy.reger.tede.getTopItemIter():
            if regk == reg_pwe.regk:
                found = True
        assert found, "tede.getTopItemIter yielded no entry for our regk"

        # processMultisigEscrow seeds tede with correct values
        reg_ms = rgy.makeRegistry(name="tede_ms", prefix=hab.pre, noBackers=True, **KWA)
        number_ms = Number(num=7)  # distinct value to tell apart from number_pwe

        rgy.reger.tmse.add(keys=(reg_ms.regk, rnum.huge, reg_ms.regd),
                           val=(prefixer, number_ms, diger_hab))
        registrar.processMultisigEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_ms.regk, rnum.huge))) == 1

        registrar.counselor = type("C", (), {"complete": lambda self, *a, **kw: False})()

        # processDisseminationEscrow is a no-op when tels has no digest
        reg_noop = rgy.makeRegistry(name="diss_noop", prefix=hab.pre, noBackers=True, **KWA)
        rgy.reger.tede.add(keys=(reg_noop.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))

        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_noop.regk, rnum.huge)) != []

        # processDisseminationEscrow drains tede, writes ctel, publishes
        # anchor reg_drain so tels has a digest at sn=0
        reg_drain = rgy.makeRegistry(name="diss_drain", prefix=hab.pre, noBackers=True, **KWA)
        rseal = SealEvent(i=reg_drain.vcp.pre, s=reg_drain.vcp.ked["s"], d=reg_drain.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True, gvrsn=Vrsn_1_0, **KWA)
        rotser = SerderKERI(raw=rot)
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

    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr, **KWA)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=SN)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # tpwe
        reg_tpwe = rgy.makeRegistry(name="klas_tpwe", prefix=hab.pre, noBackers=True, **KWA)
        rgy.reger.tpwe.add(keys=(reg_tpwe.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tpwe.get(keys=(reg_tpwe.regk, rnum.huge))
        assert items, "tpwe entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tpwe.getTopItemIter():
            if regk == reg_tpwe.regk:
                found = True
        assert found, "tpwe getTopItemIter yielded nothing"

        # tmse
        reg_tmse = rgy.makeRegistry(name="klas_tmse", prefix=hab.pre, noBackers=True, **KWA)
        rgy.reger.tmse.add(keys=(reg_tmse.regk, rnum.huge, reg_tmse.regd),
                           val=(prefixer, number, diger))

        items = rgy.reger.tmse.get(keys=(reg_tmse.regk, rnum.huge, reg_tmse.regd))
        assert items, "tmse entry missing"

        found = False
        for (regk, _, _), triple in rgy.reger.tmse.getTopItemIter():
            if regk == reg_tmse.regk:
                found = True
        assert found, "tmse getTopItemIter yielded nothing"

        # tede
        reg_tede = rgy.makeRegistry(name="klas_tede", prefix=hab.pre, noBackers=True, **KWA)
        rgy.reger.tede.add(keys=(reg_tede.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tede.get(keys=(reg_tede.regk, rnum.huge))
        assert items, "tede entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tede.getTopItemIter():
            if regk == reg_tede.regk:
                found = True
        assert found, "tede getTopItemIter yielded nothing"


if __name__ == "__main__":
    test_tpwe()
    test_tmse()
    test_tede()
    test_escrow_suber_klas()
