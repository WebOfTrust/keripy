# -*- encoding: utf-8 -*-
"""
tests.vdr.test_credentialing module

"""
from keri import kering

from keri.app import keeping
from keri.core import coring, serdering
from keri.core import eventing as keventing
from keri.core.coring import Seqner, Saider
from keri.db import basing
from keri.db.dbing import snKey, dgKey
from keri.vdr.credentialing import Regery, Registrar

from tests.vdr import buildHab


def test_tpwe():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        # counselor is only used in the GroupHab (multisig) path; never called here
        registrar = Registrar(hby=hby, rgy=rgy, counselor=None)

        prefixer = hab.kever.prefixer
        rseq = Seqner(sn=0)

        # incept: inject into tpwe, verify present
        reg_inc = rgy.makeRegistry(name="tpwe_inc", prefix=hab.pre, noBackers=True)
        seqner_inc = Seqner(sn=hab.kever.sner.num)
        saider_inc = Saider(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_inc.regk, rseq.qb64),
                           val=(prefixer, seqner_inc, saider_inc))
        assert len(rgy.reger.tpwe.get(keys=(reg_inc.regk, rseq.qb64))) == 1, \
            "tpwe should have an entry after incept"

        # issue: anchor vcp so iss is valid, inject into tpwe
        reg_iss = rgy.makeRegistry(name="tpwe_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rseq_iss = Seqner(snh=iss.ked["s"])
        rgy.reger.tpwe.add(keys=(vcdig, rseq_iss.qb64),
                           val=(prefixer, Seqner(sn=hab.kever.sner.num), Saider(qb64=hab.kever.serder.said)))
        assert len(rgy.reger.tpwe.get(keys=(vcdig, rseq_iss.qb64))) == 1, \
            "tpwe should have an entry after issue"

        # revoke: anchor vcp+iss, inject rev into tpwe, verify seqner value
        reg_rev = rgy.makeRegistry(name="tpwe_rev", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = keventing.SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=iss2,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rev = reg_rev.revoke(said=vcdig)
        rseq_rev = Seqner(snh=rev.ked["s"])
        expected_kel_sn = hab.kever.sner.num
        rgy.reger.tpwe.add(keys=(vcdig, rseq_rev.qb64),
                           val=(prefixer, Seqner(sn=expected_kel_sn), Saider(qb64=hab.kever.serder.said)))
        entries = rgy.reger.tpwe.get(keys=(vcdig, rseq_rev.qb64))
        assert len(entries) == 1, "tpwe should have an entry after revoke"
        _, seq_obj, _ = entries[0]
        assert seq_obj.sn == expected_kel_sn

        # processWitnessEscrow drains tpwe and seeds tede
        reg_pwe = rgy.makeRegistry(name="pwe_drain", prefix=hab.pre, noBackers=True)
        seqner_pwe = Seqner(sn=hab.kever.sner.num)
        saider_pwe = Saider(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rseq.qb64),
                           val=(prefixer, seqner_pwe, saider_pwe))
        registrar.processWitnessEscrow()

        assert rgy.reger.tpwe.get(keys=(reg_pwe.regk, rseq.qb64)) == [], \
            "tpwe entry should be removed after processWitnessEscrow"
        assert len(rgy.reger.tede.get(keys=(reg_pwe.regk, rseq.qb64))) == 1, \
            "tede should be seeded by processWitnessEscrow"

        # processWitnessEscrow is a no-op when tpwe is empty
        registrar.processWitnessEscrow()  # must not raise


def test_tmse():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    # tmse is populated correctly (inject and verify entries)
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=hab.kever.sner.num)
        saider = Saider(qb64=hab.kever.serder.said)
        rseq = Seqner(sn=0)

        # incept
        reg_inc = rgy.makeRegistry(name="tmse_inc", prefix=hab.pre, noBackers=True)
        rgy.reger.tmse.add(keys=(reg_inc.regk, rseq.qb64, reg_inc.regd),
                           val=(prefixer, seqner, saider))
        assert len(rgy.reger.tmse.get(keys=(reg_inc.regk, rseq.qb64, reg_inc.regd))) == 1, \
            "tmse should have an entry after multisig incept"

        # issue
        reg_iss = rgy.makeRegistry(name="tmse_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rseq_iss = Seqner(snh=iss.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rseq_iss.qb64, iss.said),
                           val=(prefixer, seqner, saider))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rseq_iss.qb64, iss.said))) == 1, \
            "tmse should have an entry after multisig issue"

        # revoke
        reg_rev = rgy.makeRegistry(name="tmse_rev", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = keventing.SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=iss2,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rev = reg_rev.revoke(said=vcdig)
        rseq_rev = Seqner(snh=rev.ked["s"])
        rgy.reger.tmse.add(keys=(vcdig, rseq_rev.qb64, rev.said),
                           val=(prefixer, seqner, saider))
        assert len(rgy.reger.tmse.get(keys=(vcdig, rseq_rev.qb64, rev.said))) == 1, \
            "tmse should have an entry after multisig revoke"

    # processMultisigEscrow is a no-op when counselor.complete is False
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _NeverComplete:
            def complete(self, *a, **kw): return False

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_NeverComplete())
        reg = rgy.makeRegistry(name="tmse_noop", prefix=hab.pre, noBackers=True)
        rseq = Seqner(sn=0)
        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=1)
        saider = Saider(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rseq.qb64, reg.regd), val=(prefixer, seqner, saider))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rseq.qb64, reg.regd)) != [], \
            "tmse entry must remain when counselor.complete is False"
        assert rgy.reger.tede.get(keys=(reg.regk, rseq.qb64)) == []

    # processMultisigEscrow drains tmse and seeds tede when complete
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _AlwaysComplete:
            def complete(self, *a, **kw): return True

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_AlwaysComplete())
        reg = rgy.makeRegistry(name="tmse_drain", prefix=hab.pre, noBackers=True)
        rseq = Seqner(sn=0)
        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=1)
        saider = Saider(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rseq.qb64, reg.regd), val=(prefixer, seqner, saider))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rseq.qb64, reg.regd)) == [], \
            "tmse entry should be removed when counselor.complete is True"
        assert len(rgy.reger.tede.get(keys=(reg.regk, rseq.qb64))) == 1, \
            "tede should be seeded after processMultisigEscrow"

    # processMultisigEscrow drops entry on ValidationError
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _RaisesValidation:
            def complete(self, *a, **kw): raise kering.ValidationError("bad")

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_RaisesValidation())
        reg = rgy.makeRegistry(name="tmse_valerr", prefix=hab.pre, noBackers=True)
        rseq = Seqner(sn=0)
        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=1)
        saider = Saider(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rseq.qb64, reg.regd), val=(prefixer, seqner, saider))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rseq.qb64, reg.regd)) == [], \
            "tmse entry should be dropped on ValidationError"


def test_tede():
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _AlwaysComplete:
            def complete(self, *a, **kw): return True

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_AlwaysComplete())

        prefixer = hab.kever.prefixer
        saider_hab = Saider(qb64=hab.kever.serder.said)
        rseq = Seqner(sn=0)

        # processWitnessEscrow seeds tede with correct values
        reg_pwe = rgy.makeRegistry(name="tede_pwe", prefix=hab.pre, noBackers=True)
        seqner_pwe = Seqner(sn=hab.kever.sner.num)

        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rseq.qb64), val=(prefixer, seqner_pwe, saider_hab))
        registrar.processWitnessEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_pwe.regk, rseq.qb64))) == 1

        # getItemIter is the read path used by processDisseminationEscrow
        found = False
        for (regk, _), triple in rgy.reger.tede.getItemIter():
            if regk == reg_pwe.regk:
                found = True
        assert found, "tede.getItemIter yielded no entry for our regk"

        # processMultisigEscrow seeds tede with correct values
        reg_ms = rgy.makeRegistry(name="tede_ms", prefix=hab.pre, noBackers=True)
        seqner_ms = Seqner(sn=7)  # distinct value to tell apart from seqner_pwe

        rgy.reger.tmse.add(keys=(reg_ms.regk, rseq.qb64, reg_ms.regd),
                           val=(prefixer, seqner_ms, saider_hab))
        registrar.processMultisigEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_ms.regk, rseq.qb64))) == 1

        # switch counselor so processMultisigEscrow stops draining on subsequent calls
        class _NeverComplete:
            def complete(self, *a, **kw): return False

        registrar.counselor = _NeverComplete()

        # processDisseminationEscrow is a no-op when tels has no digest
        reg_noop = rgy.makeRegistry(name="diss_noop", prefix=hab.pre, noBackers=True)
        rgy.reger.tede.add(keys=(reg_noop.regk, rseq.qb64), val=(prefixer, seqner_pwe, saider_hab))

        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_noop.regk, rseq.qb64)) != [], \
            "tede entry must remain when tels has no digest for the sn"

        # processDisseminationEscrow drains tede, writes ctel, publishes
        # anchor reg_drain so tels has a digest at sn=0
        reg_drain = rgy.makeRegistry(name="diss_drain", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_drain.vcp.pre, s=reg_drain.vcp.ked["s"], d=reg_drain.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_drain.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        rgy.reger.tede.add(keys=(reg_drain.regk, rseq.qb64), val=(prefixer, seqner_pwe, saider_hab))

        before = len(registrar.witPub.msgs)
        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_drain.regk, rseq.qb64)) == [], \
            "tede entry should be removed after dissemination"
        assert rgy.reger.ctel.get(keys=(reg_drain.regk, rseq.qb64)) is not None, \
            "ctel should have an entry after dissemination"
        assert len(registrar.witPub.msgs) == before + 1, \
            "witPub.msgs should receive one message after dissemination"


def test_escrow_suber_klas():
    SN = 42

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=SN)
        saider = Saider(qb64=hab.kever.serder.said)
        rseq = Seqner(sn=0)

        # tpwe
        reg_tpwe = rgy.makeRegistry(name="klas_tpwe", prefix=hab.pre, noBackers=True)
        rgy.reger.tpwe.add(keys=(reg_tpwe.regk, rseq.qb64), val=(prefixer, seqner, saider))

        items = rgy.reger.tpwe.get(keys=(reg_tpwe.regk, rseq.qb64))
        assert items, "tpwe entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tpwe.getItemIter():
            if regk == reg_tpwe.regk:
                found = True
        assert found, "tpwe getItemIter yielded nothing"

        # tmse
        reg_tmse = rgy.makeRegistry(name="klas_tmse", prefix=hab.pre, noBackers=True)
        rgy.reger.tmse.add(keys=(reg_tmse.regk, rseq.qb64, reg_tmse.regd),
                           val=(prefixer, seqner, saider))

        items = rgy.reger.tmse.get(keys=(reg_tmse.regk, rseq.qb64, reg_tmse.regd))
        assert items, "tmse entry missing"

        found = False
        for (regk, _, _), triple in rgy.reger.tmse.getItemIter():
            if regk == reg_tmse.regk:
                found = True
        assert found, "tmse getItemIter yielded nothing"

        # tede
        reg_tede = rgy.makeRegistry(name="klas_tede", prefix=hab.pre, noBackers=True)
        rgy.reger.tede.add(keys=(reg_tede.regk, rseq.qb64), val=(prefixer, seqner, saider))

        items = rgy.reger.tede.get(keys=(reg_tede.regk, rseq.qb64))
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
    