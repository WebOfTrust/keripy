# -*- encoding: utf-8 -*-
"""
tests.vdr.test_credentialing module

"""
from keri.kering import Ilks, ValidationError, Vrsn_1_0, Vrsn_2_0, Kinds, Roles

from keri.core import (Number, Saider, Diger, SerderKERI, SealEvent, TraitDex,
                       Seqner, Aggor, Noncer, MtrDex, Saids, Prefixer, Parser)

from keri.acdc import acdcagg
from keri.acdc.messaging import acgSchemaDefault
from keri.app import openKS, openHab, StreamPoster, ForwardHandler, Mailboxer
from keri.db import openDB, openLMDB
from keri.help import helping
from keri.peer import Exchanger
from keri.vc import credential
from keri.vdr import Credentialer, Regery, Registrar, sendArtifacts
from keri.vdr.credentialing import sendCredential
from keri.vdr.eventing import incept

from tests.vdr import buildHab



def test_v1_registry_version_across_lifecycle_with_v2_identifier(monkeypatch):
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
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

                def create_credential(source=None):
                    return credentialer.create(
                        regname="legacy",
                        recp=None,
                        schema="EAllThM1rLBSMZ_ozM1uAnFvSfC0N1jaQ42aKU5sCZ5Q",
                        source=source,
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

                seal = SealEvent(i=iserder.pre, s="0", d=iserder.said)
                anchor = SerderKERI(raw=hab.interact(data=[seal._asdict()]))
                rgy.tvy.processEvent(serder=iserder, seqner=Number(num=anchor.sn),
                                     saider=Saider(qb64=anchor.said))
                rgy.reger.logCred(creder, Prefixer(qb64=hab.pre),
                                  Number(num=anchor.sn), Diger(qb64=anchor.said))
                source = creder
                source_iss = iserder
                creder = create_credential(source=dict(d="", source=dict(
                    n=source.said, s=source.schema)))
                iserder = registry.issue(said=creder.said)
                seal = SealEvent(i=iserder.pre, s="0", d=iserder.said)
                anchor = SerderKERI(raw=hab.interact(data=[seal._asdict()]))
                rgy.tvy.processEvent(serder=iserder, seqner=Number(num=anchor.sn),
                                     saider=Saider(qb64=anchor.said))
                rgy.reger.logCred(creder, Prefixer(qb64=hab.pre),
                                  Number(num=anchor.sn), Diger(qb64=anchor.said))
                monkeypatch.setattr(hab, "endsFor", lambda pre: {
                    Roles.witness: {hab.pre: {}}
                })
                postman = StreamPoster(hby=hby, hab=hab, recp=hab.pre,
                                       topic="credential", version=Vrsn_2_0)
                sendCredential(hby, hab, rgy.reger, postman, creder, hab.pre)
                with openLMDB(cls=Mailboxer, name="artifacts") as mbx:
                    exc = Exchanger(hby=hby, handlers=[ForwardHandler(hby=hby, mbx=mbx)])
                    parser = Parser(kvy=hby.kvy, exc=exc, version=Vrsn_2_0)
                    for evt in postman.evts:
                        parser.parse(ims=bytearray(evt["serder"].raw + evt["attachment"]))
                        assert exc.complete(evt["serder"].said)
                    carried = {}
                    for _, _, msg in mbx.cloneTopicIter(topic=f"{hab.pre}/credential"):
                        child = Parser().parse(ims=bytearray(msg), processive=False)[0]
                        carried[child.serder.said] = child
                    for tel in (vcp, source_iss, iserder):
                        assert carried[tel.said].serder.raw == tel.raw
                        assert len(carried[tel.said].sscs) == 1
                    for credential in (source, creder):
                        assert carried[credential.said].serder.raw == credential.raw
                        assert len(carried[credential.said].ssts) == 1
            finally:
                rgy.close()


def test_tpwe():
    vcdig = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"

    with openDB(temp=True) as db, openKS(temp=True) as kpr:
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)
        registrar = Registrar(hby=hby, rgy=rgy, counselor=None)

        prefixer = hab.kever.prefixer
        rnum = Number(num=0)

        # incept: inject into tpwe, verify present
        reg_inc = rgy.makeRegistry(name="tpwe_inc", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        number_inc = Number(num=hab.kever.sner.num)
        diger_inc = Diger(qb64=hab.kever.serder.said)
        rgy.reger.tpwe.add(keys=(reg_inc.regk, rnum.huge),
                           val=(prefixer, number_inc, diger_inc))
        assert len(rgy.reger.tpwe.get(keys=(reg_inc.regk, rnum.huge))) == 1

        # issue: anchor vcp so iss is valid, inject into tpwe
        reg_iss = rgy.makeRegistry(name="tpwe_iss", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
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
        reg_rev = rgy.makeRegistry(name="tpwe_rev", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
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
        reg_pwe = rgy.makeRegistry(name="pwe_drain", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
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
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=hab.kever.sner.num)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # incept
        reg_inc = rgy.makeRegistry(name="tmse_inc", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rgy.reger.tmse.add(keys=(reg_inc.regk, rnum.huge, reg_inc.regd),
                           val=(prefixer, number, diger))
        assert len(rgy.reger.tmse.get(keys=(reg_inc.regk, rnum.huge, reg_inc.regd))) == 1

        # issue
        reg_iss = rgy.makeRegistry(name="tmse_iss", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(i=reg_iss.vcp.pre, s=reg_iss.vcp.ked["s"], d=reg_iss.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
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
        reg_rev = rgy.makeRegistry(name="tmse_rev", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(i=reg_rev.vcp.pre, s=reg_rev.vcp.ked["s"], d=reg_rev.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
        rotser = SerderKERI(raw=rot)
        rgy.tvy.processEvent(serder=reg_rev.vcp,
                             seqner=Number(num=rotser.sn),
                             saider=Saider(qb64=rotser.said))
        iss2 = reg_rev.issue(said=vcdig)
        rseal = SealEvent(iss2.ked["i"], iss2.ked["s"], iss2.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
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
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _NeverComplete:
            def complete(self, *a, **kw): return False

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_NeverComplete())
        reg = rgy.makeRegistry(name="tmse_noop", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
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
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        registrar = Registrar(
            hby=hby,
            rgy=rgy,
            counselor=type("C", (), {"complete": lambda self, *a, **kw: True})()
        )

        reg = rgy.makeRegistry(name="tmse_drain", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
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
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        class _RaisesValidation:
            def complete(self, *a, **kw): raise ValidationError("bad")

        registrar = Registrar(hby=hby, rgy=rgy, counselor=_RaisesValidation())
        reg = rgy.makeRegistry(name="tmse_valerr", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rnum = Number(num=0)
        prefixer = hab.kever.prefixer
        number = Number(num=1)
        diger = Diger(qb64=hab.kever.serder.said)

        rgy.reger.tmse.add(keys=(reg.regk, rnum.huge, reg.regd), val=(prefixer, number, diger))
        registrar.processMultisigEscrow()

        assert rgy.reger.tmse.get(keys=(reg.regk, rnum.huge, reg.regd)) == []


def test_tede():
    with openDB(temp=True) as db, openKS(temp=True) as kpr:
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
        reg_pwe = rgy.makeRegistry(name="tede_pwe", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
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
        reg_ms = rgy.makeRegistry(name="tede_ms", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        number_ms = Number(num=7)  # distinct value to tell apart from number_pwe

        rgy.reger.tmse.add(keys=(reg_ms.regk, rnum.huge, reg_ms.regd),
                           val=(prefixer, number_ms, diger_hab))
        registrar.processMultisigEscrow()

        assert len(rgy.reger.tede.get(keys=(reg_ms.regk, rnum.huge))) == 1

        registrar.counselor = type("C", (), {"complete": lambda self, *a, **kw: False})()

        # processDisseminationEscrow is a no-op when tels has no digest
        reg_noop = rgy.makeRegistry(name="diss_noop", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rgy.reger.tede.add(keys=(reg_noop.regk, rnum.huge), val=(prefixer, number_pwe, diger_hab))

        registrar.processDisseminationEscrow()

        assert rgy.reger.tede.get(keys=(reg_noop.regk, rnum.huge)) != []

        # processDisseminationEscrow drains tede, writes ctel, publishes
        # anchor reg_drain so tels has a digest at sn=0
        reg_drain = rgy.makeRegistry(name="diss_drain", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rseal = SealEvent(i=reg_drain.vcp.pre, s=reg_drain.vcp.ked["s"], d=reg_drain.vcp.said)
        rot = hab.rotate(data=[rseal._asdict()], framed=True)
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
        hby, hab = buildHab(db, kpr)
        rgy = Regery(hby=hby, name="test", temp=True)

        prefixer = hab.kever.prefixer
        number = Number(num=SN)
        diger = Diger(qb64=hab.kever.serder.said)
        rnum = Number(num=0)

        # tpwe
        reg_tpwe = rgy.makeRegistry(name="klas_tpwe", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rgy.reger.tpwe.add(keys=(reg_tpwe.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tpwe.get(keys=(reg_tpwe.regk, rnum.huge))
        assert items, "tpwe entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tpwe.getTopItemIter():
            if regk == reg_tpwe.regk:
                found = True
        assert found, "tpwe getTopItemIter yielded nothing"

        # tmse
        reg_tmse = rgy.makeRegistry(name="klas_tmse", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
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
        reg_tede = rgy.makeRegistry(name="klas_tede", prefix=hab.pre, noBackers=True, version=Vrsn_1_0, kind=Kinds.json)
        rgy.reger.tede.add(keys=(reg_tede.regk, rnum.huge), val=(prefixer, number, diger))

        items = rgy.reger.tede.get(keys=(reg_tede.regk, rnum.huge))
        assert items, "tede entry missing"

        found = False
        for (regk, _), triple in rgy.reger.tede.getTopItemIter():
            if regk == reg_tede.regk:
                found = True
        assert found, "tede getTopItemIter yielded nothing"


class CapturingPoster:
    """Minimal stand-in for forwarding.StreamPoster that records what was queued.

    ``sendArtifacts`` only ever calls ``postman.send(serder=, attachment=)``, so
    recording those calls is enough to assert which KELs and TELs were streamed,
    without standing up witnesses or end role authorizations for a recipient.
    """

    def __init__(self):
        self.msgs = []

    def send(self, serder, attachment=None):
        self.msgs.append((serder, attachment))

    @property
    def pres(self):
        """list: qb64 prefix of every event serder queued."""
        return [serder.pre for serder, _ in self.msgs]


def _sendArtifactsSetup(hby, ian):
    """Add an issuee and a recipient AID plus an anchored registry for ian.

    ``sendArtifacts`` resolves both the issuer's and the issuee's KEL out of the
    one ``hby.db``, so ian (issuer), han (issuee) and vic (recipient) all live in
    the same Habery.

    Returns:
        tuple (Hab, Hab, Regery, Registry): (han, vic, rgy, registry)
    """
    han = hby.makeHab(name="han", transferable=True)
    vic = hby.makeHab(name="vic", transferable=True)

    rgy = Regery(hby=hby, name="ian", temp=True)
    registry = rgy.makeRegistry(prefix=ian.pre, name="ian",
                                version=Vrsn_1_0, kind=Kinds.json)
    rseal = SealEvent(registry.regk, "0", registry.regd)._asdict()
    ian.interact(data=[rseal], framed=True)
    registry.anchorMsg(pre=registry.regk, regd=registry.regd,
                       seqner=Seqner(sn=ian.kever.sn),
                       saider=Diger(qb64=ian.kever.serder.said))
    rgy.processEscrows()

    return han, vic, rgy, registry


def _aggregateCredential(ian, registry, rgy, issueeAid):
    """Build an aggregative ('acg') credential and issue its SAID into ian's TEL.

    For an aggregate ACDC the issuee lives at ``.sad["A"][1]["i"]`` rather than at
    ``.sad["a"]["i"]``, so ``.attrib`` is None and ``.iseaid`` is the only way to
    resolve the issuee -- exactly the case an attributive-only lookup mishandles.
    """
    raws = [b'aggsendartifact' + b'%0x' % (i) for i in range(3)]
    nonces = [Noncer(raw=r).qb64 for r in raws]
    # element 0 is the AGID placeholder; element 1 carries the issuee (i).
    ael = ['', dict(d='', u=nonces[0], i=issueeAid),
           dict(d='', u=nonces[1], over21=True)]
    aggor = Aggor(ael=ael, makify=True, kind=Kinds.json)
    sschema, _ = acgSchemaDefault(kind=Kinds.json)  # SAID string, not the block
    agg = acdcagg(israid=ian.pre, uuid=nonces[2], regid=registry.regk,
                  schema=sschema, aggregate=aggor.ael, kind=Kinds.json)

    iss = registry.issue(said=agg.said)
    rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
    ian.interact(data=[rseal], framed=True)
    registry.anchorMsg(pre=iss.pre, regd=iss.said,
                       seqner=Seqner(sn=ian.kever.sn),
                       saider=Diger(qb64=ian.kever.serder.said))
    rgy.processEscrows()
    return agg


def test_send_artifacts_aggregate_issuee():
    """sendArtifacts resolves an aggregate ('acg') credential's issuee via .iseaid.

    sendArtifacts reached the issuee through ``'i' in creder.attrib``, but
    ``creder.attrib`` is None for an aggregate credential, so the membership test
    raised ``TypeError`` and the issuee's KEL was never streamed -- an aggregate
    credential could not be granted through this path at all. It must instead
    resolve the issuee via ``.iseaid``, identically to an attributive credential.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef') as (hby, ian):
        han, vic, rgy, registry = _sendArtifactsSetup(hby, ian)

        agg = _aggregateCredential(ian, registry, rgy, han.pre)
        assert agg.attrib is None            # aggregate: no 'a' section
        assert agg.iseaid == han.pre         # issuee resolves from A[1].i
        assert agg.israid == ian.pre

        # Before the fix this raised TypeError on ``'i' in creder.attrib`` (None).
        postman = CapturingPoster()
        sendArtifacts(hby, rgy.reger, postman, agg, vic.pre)

        pres = postman.pres
        assert ian.pre in pres               # issuer KEL
        assert han.pre in pres               # issuee KEL, resolved via .iseaid
        assert registry.regk in pres         # management TEL
        assert agg.said in pres              # credential TEL


def test_send_artifacts_attributive_issuee():
    """sendArtifacts streams an attributive credential's issuee KEL, unchanged.

    The no-regression companion to test_send_artifacts_aggregate_issuee: for an
    attributive credential ``.iseaid`` is ``.attrib['i']``, so routing through it
    leaves this path's behavior identical.
    """
    schema = "EAv8omZ-o3Pk45h72_WnIpt6LTWNzc8hmLjeblpxB9vz"
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef') as (hby, ian):
        han, vic, rgy, registry = _sendArtifactsSetup(hby, ian)

        data = dict(d="", i=han.pre, dt=helping.nowIso8601(), over21=True)
        _, data = Saider.saidify(sad=data, code=MtrDex.Blake3_256, label=Saids.d)
        creder = credential(issuer=ian.pre, schema=schema, data=data,
                            status=registry.regk, rules={},
                            version=Vrsn_1_0, kind=Kinds.json)

        iss = registry.issue(said=creder.said)
        rseal = SealEvent(iss.pre, "0", iss.said)._asdict()
        ian.interact(data=[rseal], framed=True)
        registry.anchorMsg(pre=iss.pre, regd=iss.said,
                           seqner=Seqner(sn=ian.kever.sn),
                           saider=Diger(qb64=ian.kever.serder.said))
        rgy.processEscrows()

        assert creder.attrib["i"] == han.pre
        assert creder.iseaid == creder.attrib["i"]

        postman = CapturingPoster()
        sendArtifacts(hby, rgy.reger, postman, creder, vic.pre)

        pres = postman.pres
        assert ian.pre in pres
        assert han.pre in pres
        assert registry.regk in pres
        assert creder.said in pres


def test_send_artifacts_issuee_is_recipient():
    """sendArtifacts skips the issuee KEL when the issuee is the recipient.

    The ``isse != recp`` guard is unaffected by resolving the issuee via .iseaid.
    """
    with openHab(name="ian", temp=True, salt=b'0123456789abcdef') as (hby, ian):
        han, vic, rgy, registry = _sendArtifactsSetup(hby, ian)

        agg = _aggregateCredential(ian, registry, rgy, han.pre)

        postman = CapturingPoster()
        sendArtifacts(hby, rgy.reger, postman, agg, han.pre)

        pres = postman.pres
        assert ian.pre in pres
        assert han.pre not in pres           # recipient already holds its own KEL


if __name__ == "__main__":
    test_tpwe()
    test_tmse()
    test_tede()
    test_escrow_suber_klas()
