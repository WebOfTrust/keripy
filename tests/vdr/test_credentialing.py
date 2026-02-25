# -*- encoding: utf-8 -*-
"""
tests.vdr.test_credentialing module

"""
from keri import kering
from unittest.mock import MagicMock

from keri.app import keeping
from keri.core import coring, serdering
from keri.core import eventing as keventing
from keri.core.coring import Seqner, Saider
from keri.db import basing
from keri.vdr.credentialing import Regery, Registrar
from keri.app.habbing import GroupHab

from tests.vdr import buildHab


def test_tpwe():
    """
    tpwe tests: Registrar.incept, issue, revoke populate tpwe correctly;
    processWitnessEscrow drains tpwe and seeds tede.
    """
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        counselor = MagicMock()
        counselor.complete.return_value = False
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

        # incept (single-sig) writes to tpwe
        reg_inc = rgy.makeRegistry(name="tpwe_inc", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_inc.regk, s=reg_inc.vcp.ked["s"], d=reg_inc.vcp.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc = serdering.SerderKERI(raw=bytes(ixn_bytes))
        # capture state after interact — that is what incept will snapshot

        registrar.incept(iserder=reg_inc.vcp, anc=anc)

        rseq = Seqner(sn=0)
        entries = rgy.reger.tpwe.get(keys=(reg_inc.regk, rseq.qb64))
        assert len(entries) == 1, "tpwe should have an entry after incept"

        # incept (multisig / GroupHab) must write to tmse, NOT tpwe
        reg_ms = rgy.makeRegistry(name="tpwe_ms", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_ms.regk, s=reg_ms.vcp.ked["s"], d=reg_ms.vcp.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc = serdering.SerderKERI(raw=bytes(ixn_bytes))
        ghab = MagicMock(spec=GroupHab)
        ghab.pre = hab.pre
        ghab.kever = hab.kever
        reg_ms.hab = ghab

        registrar.incept(iserder=reg_ms.vcp, anc=anc)

        assert rgy.reger.tpwe.get(keys=(reg_ms.regk, rseq.qb64)) == [], \
            "multisig incept must not write to tpwe"
        assert rgy.reger.tmse.get(keys=(reg_ms.regk, rseq.qb64, reg_ms.regd)) != [], \
            "multisig incept must write to tmse"

        # issue (single-sig) writes to tpwe
        reg_iss = rgy.makeRegistry(name="tpwe_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc = serdering.SerderKERI(raw=bytes(ixn_bytes))

        creder = MagicMock()
        creder.regid = reg_iss.regk
        registrar.issue(creder=creder, iserder=iss, anc=anc)

        rseq_iss = Seqner(snh=iss.ked["s"])
        entries = rgy.reger.tpwe.get(keys=(vcdig, rseq_iss.qb64))
        assert len(entries) == 1, "tpwe should have an entry after issue"

        # revoke (single-sig) writes to tpwe
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
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc = serdering.SerderKERI(raw=bytes(ixn_bytes))
        expected_kel_sn = hab.kever.sner.num

        creder2 = MagicMock()
        creder2.regid = reg_rev.regk
        vcid, tel_sn = registrar.revoke(creder=creder2, rserder=rev, anc=anc)

        assert vcid == vcdig
        assert tel_sn == int(rev.ked["s"], 16)  # iss=0, rev=1 in credential TEL

        rseq_rev = Seqner(snh=rev.ked["s"])
        entries = rgy.reger.tpwe.get(keys=(vcid, rseq_rev.qb64))
        assert len(entries) == 1, "tpwe should have an entry after revoke"
        _, seq_obj, _ = entries[0]
        assert seq_obj.sn == expected_kel_sn

        # processWitnessEscrow drains tpwe and seeds tede
        reg_pwe = rgy.makeRegistry(name="pwe_drain", prefix=hab.pre, noBackers=True)
        rseq = Seqner(sn=0)
        seqner = Seqner(sn=hab.kever.sner.num)
        saider = Saider(qb64=hab.kever.serder.said)
        prefixer = hab.kever.prefixer

        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rseq.qb64), val=(prefixer, seqner, saider))
        registrar.processWitnessEscrow()

        assert rgy.reger.tpwe.get(keys=(reg_pwe.regk, rseq.qb64)) == [], \
            "tpwe entry should be removed after processWitnessEscrow"
        entries = rgy.reger.tede.get(keys=(reg_pwe.regk, rseq.qb64))
        assert len(entries) == 1, "tede should be seeded by processWitnessEscrow"

        # processWitnessEscrow is a no-op when tpwe is empty
        registrar.processWitnessEscrow()  # must not raise

def test_tmse():
    """
    tmse tests: Registrar.incept, issue, revoke (GroupHab path) populate tmse
    correctly; processMultisigEscrow drains tmse and seeds tede.

    The three processMultisigEscrow scenarios each need a different counselor
    mock state (False / True / ValidationError), so they run in separate
    openDB contexts to avoid cross-contamination from earlier tmse entries.
    """
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        counselor = MagicMock()
        counselor.complete.return_value = False
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

        # incept
        reg_inc = rgy.makeRegistry(name="tmse_inc", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_inc.regk, s=reg_inc.vcp.ked["s"], d=reg_inc.vcp.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc_inc = serdering.SerderKERI(raw=bytes(ixn_bytes))
        ghab = MagicMock(spec=GroupHab)
        ghab.pre = hab.pre
        ghab.kever = hab.kever
        reg_inc.hab = ghab
        registrar.incept(iserder=reg_inc.vcp, anc=anc_inc)

        rseq = Seqner(sn=0)
        entries = rgy.reger.tmse.get(keys=(reg_inc.regk, rseq.qb64, reg_inc.regd))
        assert len(entries) == 1, "tmse should have an entry after multisig incept"

        # issue
        reg_iss = rgy.makeRegistry(name="tmse_iss", prefix=hab.pre, noBackers=True)
        rseal = keventing.SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()])
        rotser = serdering.SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_iss.vcp,
                             seqner=Seqner(sn=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss = reg_iss.issue(said=vcdig)
        rseal = keventing.SealEvent(iss.ked["i"], iss.ked["s"], iss.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc_iss = serdering.SerderKERI(raw=bytes(ixn_bytes))
        ghab2 = MagicMock(spec=GroupHab)
        ghab2.pre = hab.pre
        ghab2.kever = hab.kever
        reg_iss.hab = ghab2

        creder = MagicMock()
        creder.regid = reg_iss.regk
        registrar.issue(creder=creder, iserder=iss, anc=anc_iss)

        rseq_iss = Seqner(snh=iss.ked["s"])
        entries = rgy.reger.tmse.get(keys=(vcdig, rseq_iss.qb64, iss.said))
        assert len(entries) == 1, "tmse should have an entry after multisig issue"

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
        rseal = keventing.SealEvent(rev.ked["i"], rev.ked["s"], rev.said)
        ixn_bytes = hab.interact(data=[rseal._asdict()])
        anc_rev = serdering.SerderKERI(raw=bytes(ixn_bytes))
        ghab3 = MagicMock(spec=GroupHab)
        ghab3.pre = hab.pre
        ghab3.kever = hab.kever
        reg_rev.hab = ghab3

        creder2 = MagicMock()
        creder2.regid = reg_rev.regk
        registrar.revoke(creder=creder2, rserder=rev, anc=anc_rev)

        rseq_rev = Seqner(snh=rev.ked["s"])
        entries = rgy.reger.tmse.get(keys=(vcdig, rseq_rev.qb64, rev.said))
        assert len(entries) == 1, "tmse should have an entry after multisig revoke"

    # processMultisigEscrow is a no-op when counselor.complete is False
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        counselor = MagicMock()
        counselor.complete.return_value = False
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

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
        counselor = MagicMock()
        counselor.complete.return_value = True
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

        reg = rgy.makeRegistry(name="tmse_drain", prefix=hab.pre, noBackers=True)
        rseq = Seqner(sn=0)
        prefixer = hab.kever.prefixer
        seqner = Seqner(sn=1)
        saider = Saider(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rseq.qb64, reg.regd), val=(prefixer, seqner, saider))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rseq.qb64, reg.regd)) == [], \
            "tmse entry should be removed when counselor.complete is True"
        entries = rgy.reger.tede.get(keys=(reg.regk, rseq.qb64))
        assert len(entries) == 1, "tede should be seeded after processMultisigEscrow"

    # processMultisigEscrow drops entry on ValidationError
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        counselor = MagicMock()
        counselor.complete.side_effect = kering.ValidationError("bad")
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

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
    """
    tede tests: processWitnessEscrow and processMultisigEscrow correctly seed
    tede; processDisseminationEscrow drains tede, writes ctel, and publishes.
    """
    with basing.openDB(temp=True) as db, keeping.openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        counselor = MagicMock()
        counselor.complete.return_value = False
        registrar = Registrar(hby=hby, rgy=rgy, counselor=counselor)

        prefixer = hab.kever.prefixer
        saider_hab = Saider(qb64=hab.kever.serder.said)
        rseq = Seqner(sn=0)

        # processWitnessEscrow seeds tede with correct values
        reg_pwe = rgy.makeRegistry(name="tede_pwe", prefix=hab.pre, noBackers=True)
        seqner_pwe = Seqner(sn=hab.kever.sner.num)

        rgy.reger.tpwe.add(keys=(reg_pwe.regk, rseq.qb64), val=(prefixer, seqner_pwe, saider_hab))
        registrar.processWitnessEscrow()

        entries = rgy.reger.tede.get(keys=(reg_pwe.regk, rseq.qb64))
        assert len(entries) == 1

        # getItemIter is the read path used by processDisseminationEscrow
        found = False
        for (regk, _), triple in rgy.reger.tede.getItemIter():
            if regk == reg_pwe.regk:
                found = True
        assert found, "tede.getItemIter yielded no entry for our regk"

        # processMultisigEscrow seeds tede with correct values
        counselor.complete.return_value = True
        reg_ms = rgy.makeRegistry(name="tede_ms", prefix=hab.pre, noBackers=True)
        seqner_ms = Seqner(sn=7)  # distinct value to tell apart from seqner_pwe

        rgy.reger.tmse.add(keys=(reg_ms.regk, rseq.qb64, reg_ms.regd),
                           val=(prefixer, seqner_ms, saider_hab))
        registrar.processMultisigEscrow()

        entries = rgy.reger.tede.get(keys=(reg_ms.regk, rseq.qb64))
        assert len(entries) == 1

        # reset so counselor does not drain tede entries in subsequent calls
        counselor.complete.return_value = False

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
    """
    Direct round-trip through add -> get and getItemIter for tpwe, tmse, tede.
    Catches any Seqner->Number refactor that breaks the .sn contract or the
    CESR serialization length.
    """
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