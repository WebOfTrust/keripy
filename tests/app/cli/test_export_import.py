# -*- encoding: utf-8 -*-
"""
tests.app.cli.test_export_import module

Late-joiner state-sync workflow coverage.
"""
import io
import os
from contextlib import contextmanager

from keri import core
from keri.app import directing, grouping, habbing
from keri.app.cli.commands import import_ as import_cmd
from keri.app.cli.commands.vc import export as export_cmd
from keri.core import coring, eventing, parsing, serdering
from keri.vdr import credentialing


SALT = core.Salter(raw=b'0123456789abcdef').qb64
CLI_BASE = "test-state-sync"


def isolatedBase(tmp_path):
    """Return a command-addressable base namespace unique to this pytest test."""
    return f"{CLI_BASE}-{tmp_path.parent.name}-{tmp_path.name}"


def closeRegery(rgy, clear=True):
    reger = getattr(rgy, "reger", None)
    if reger is not None and (reger.opened or clear):
        reger.close(clear=clear)


def closeHby(hby, clear=True):
    if hby is not None:
        cf = getattr(hby, "cf", None)
        hby.close(clear=clear)
        if clear and cf is not None:
            cf.close(clear=True)


@contextmanager
def pushd(path):
    """Temporarily run file-writing command helpers from path."""
    cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cwd)


def completeGroupEvent(hby, ghab, seqner, saider):
    """Drive the local counselor/escrows until a group event is committed."""
    counselor = grouping.Counselor(hby=hby)
    prefixer = coring.Prefixer(qb64=ghab.pre)
    counselor.start(ghab=ghab, prefixer=prefixer, seqner=seqner, saider=saider)

    # These tests have no witnesses/mailboxes; local escrow pumping is enough.
    for _ in range(8):
        hby.kvy.processEscrows()
        counselor.processEscrows()
        if counselor.complete(prefixer=prefixer, seqner=seqner, saider=saider):
            return

    raise AssertionError(f"group event {ghab.pre}:{seqner.sn} did not complete")


@contextmanager
def openLateJoinerMultisig(prefix="late-joiner", base=None, group="multisig", salt=SALT):
    """Create a two-store late-joiner multisig fixture.

    The source store starts with a one-member group that has already committed to
    member 2 as future rotation material. The body may create registry and
    credential state before calling addLateJoiner(), leaving the late store
    without that VC state until export/import runs.
    """
    if base is None:
        raise ValueError("openLateJoinerMultisig requires a per-test base")

    with (habbing.openHby(name=f"{prefix}-source", base=base, temp=False, clear=True, salt=salt) as source,
          habbing.openHby(name=f"{prefix}-late", base=base, temp=False, clear=True, salt=salt) as late):
        try:
            member1 = source.makeHab(name="m1", icount=1, isith="1", ncount=1, nsith="1")
            member2 = late.makeHab(name="m2", icount=1, isith="1", ncount=1, nsith="1")

            # The first member knows the future rotating member; the late member remains otherwise empty.
            parsing.Parser().parse(ims=bytearray(member2.makeOwnEvent(sn=0)), kvy=source.kvy, local=True)
            groupHab = source.makeGroupHab(group=group,
                                           mhab=member1,
                                           smids=[member1.pre],
                                           rmids=[member1.pre, member2.pre],
                                           isith="1",
                                           nsith="2",
                                           toad=0,
                                           wits=[])
            completeGroupEvent(source,
                               groupHab,
                               seqner=coring.Seqner(sn=0),
                               saider=coring.Saider(qb64=groupHab.pre))

            def addLateJoiner():
                """Promote member 2 to a 2-of-2 group without importing VC state."""
                member1.rotate()
                member2.rotate()
                parsing.Parser().parse(ims=bytearray(member2.makeOwnEvent(sn=1)), kvy=source.kvy, local=True)

                smids = [member1.pre, member2.pre]
                rmids = [member1.pre, member2.pre]
                merfers = [member1.kever.verfers[0], member2.kever.verfers[0]]
                migers = [member1.kever.ndigers[0], member2.kever.ndigers[0]]
                seqner = coring.Seqner(sn=groupHab.kever.sn + 1)
                rot = groupHab.rotate(smids=smids,
                                      rmids=rmids,
                                      isith="2",
                                      nsith="2",
                                      toad=0,
                                      cuts=[],
                                      adds=[],
                                      verfers=merfers,
                                      digers=migers)
                rserder = serdering.SerderKERI(raw=rot)
                sigers = member2.mgr.sign(rserder.raw,
                                          verfers=member2.kever.verfers,
                                          indexed=True,
                                          indices=[1])
                # Member 2 signs the promotion without importing prior registry or credential state.
                msg = eventing.messagize(serder=rserder, sigers=sigers)
                parsing.Parser().parse(ims=bytearray(msg), kvy=source.kvy, local=True)
                completeGroupEvent(source, groupHab, seqner=seqner, saider=coring.Saider(qb64=rserder.said))

                for msgs in (member1.replay(), member2.replay(), groupHab.replay()):
                    parsing.Parser().parse(ims=bytearray(msgs), kvy=late.kvy, local=True)

                # Join only the group KEL locally; registry and credential state must still come from import.
                return late.joinGroupHab(groupHab.pre, group=group, mhab=member2, smids=smids, rmids=rmids)

            yield (source, member1, groupHab), (late, member2), addLateJoiner
        finally:
            closeHby(late)
            closeHby(source)


def exportStateBundle(name, base, alias, bundleDir):
    """Export a full state-sync bundle for alias into bundleDir using ExportDoer."""
    bundleDir.mkdir()
    with pushd(bundleDir):
        doer = export_cmd.ExportDoer(name=name,
                                     alias=alias,
                                     base=base,
                                     bran=None,
                                     said=None,
                                     tels=True,
                                     kels=True,
                                     chains=True,
                                     files=True,
                                     allRegs=True,
                                     allCreds=True)
        directing.runController(doers=[doer])
        assert doer.hby is None
        assert doer.rgy is None
        assert doer.hab is None


def test_import_late_joiner_multisig_registry_and_credential(tmp_path, seeder, helpers):
    # Purpose: exercise the production late-joiner state-sync path end to end.
    # Member 1 creates registry/credential state before member 2 joins, then member 2 imports a real export bundle.
    with openLateJoinerMultisig(prefix="late-state-sync", base=isolatedBase(tmp_path)) as (
            (source, member1, groupHab),
            (late, member2),
            addLateJoiner):
        source_rgy = late_rgy = None
        try:
            # perform work with the first member that the second member will not see after joining
            seeder.seedSchema(source.db)
            seeder.seedSchema(late.db)
            source_rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            source_rgy, issuer = helpers.makeRegistry(source, groupHab, name="late-reg", rgy=source_rgy)
            creder, *_ = helpers.issueCredential(source,
                                                 groupHab,
                                                 issuer=issuer,
                                                 subject=dict(LEI="late-joiner"),
                                                 rgy=source_rgy)

            assert late.habByName("multisig") is None
            # Now add late joining member who won't see registry or credentials from prior to join
            lateGroup = addLateJoiner()
            assert lateGroup.pre == groupHab.pre
            assert lateGroup.smids == [member1.pre, member2.pre]
            assert lateGroup.rmids == [member1.pre, member2.pre]

            # Prove the late member has the group but not the pre-join registry mapping yet.
            late_rgy = credentialing.Regery(hby=late, name=late.name, base=late.base)
            assert late_rgy.reger.regs.get(keys=issuer.regk) is None
            closeRegery(late_rgy, clear=False)
            late_rgy = None

            # set up for export/import
            bundle = tmp_path / "late-state-bundle"
            source_name, source_base = source.name, source.base
            late_name, late_base = late.name, late.base
            group_pre = groupHab.pre
            smids = list(lateGroup.smids)
            closeRegery(source_rgy, clear=False)
            source_rgy = None
            # ExportDoer and ImportDoer must reopen command-addressable stores by name/base.
            closeHby(source, clear=False)
            closeHby(late, clear=False)

            # perform export/import
            exportStateBundle(name=source_name, base=source_base, alias="multisig", bundleDir=bundle)

            doer = import_cmd.ImportDoer(name=late_name,
                                         base=late_base,
                                         bran=None,
                                         cesrIn=str(bundle))
            directing.runController(doers=[doer])
            assert doer.hby is None
            assert doer.rgy is None
            doer.close()

            imported_rgy = None
            with habbing.openHby(name=late_name, base=late_base, temp=False, clear=False, salt=SALT) as imported_hby:
                try:
                    imported_rgy = credentialing.Regery(hby=imported_hby, name=late_name, base=late_base)
                    importedGroup = imported_hby.habByName("multisig")
                    assert importedGroup.pre == group_pre
                    assert importedGroup.smids == smids
                    regrec = imported_rgy.reger.regs.get(keys=issuer.regk)
                    assert regrec.registryKey == issuer.regk
                    assert regrec.prefix == group_pre
                    assert issuer.regk in imported_rgy.reger.tevers
                    imported, *_ = imported_rgy.reger.cloneCred(said=creder.said)
                    assert imported.raw == creder.raw
                finally:
                    closeRegery(imported_rgy, clear=False)
        finally:
            closeRegery(source_rgy)
            closeRegery(late_rgy)
            closeHby(source)
            closeHby(late)


def test_export_stdout_import_stdin_registry_and_credential(tmp_path, capsys, monkeypatch, seeder, helpers):
    # Purpose: exercise shell-style `kli vc export ... | kli import ...` without a file bundle.
    # This verifies the default stdout export and stdin import path with one registry and one credential.
    with openLateJoinerMultisig(prefix="late-stream-sync", base=isolatedBase(tmp_path)) as (
            (source, member1, groupHab),
            (late, member2),
            addLateJoiner):
        source_rgy = late_rgy = None
        try:
            # perform work with the first member that the second member will not see after joining
            seeder.seedSchema(source.db)
            seeder.seedSchema(late.db)
            source_rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            source_rgy, issuer = helpers.makeRegistry(source, groupHab, name="stream-reg", rgy=source_rgy)
            creder, *_ = helpers.issueCredential(source,
                                                 groupHab,
                                                 issuer=issuer,
                                                 subject=dict(LEI="stream"),
                                                 rgy=source_rgy)

            # Now add late joining member who won't see registry or credentials from prior to join
            lateGroup = addLateJoiner()

            # Prove the late member has the group but not the pre-join registry mapping yet.
            late_rgy = credentialing.Regery(hby=late, name=late.name, base=late.base)
            assert late_rgy.reger.regs.get(keys=issuer.regk) is None
            closeRegery(late_rgy, clear=False)
            late_rgy = None

            # set up for stdout export/stdin import
            source_name, source_base = source.name, source.base
            late_name, late_base = late.name, late.base
            group_pre = groupHab.pre
            smids = list(lateGroup.smids)
            closeRegery(source_rgy, clear=False)
            source_rgy = None
            # ExportDoer and ImportDoer must reopen command-addressable stores by name/base.
            closeHby(source, clear=False)
            closeHby(late, clear=False)

            # perform export/import through the default stream path
            capsys.readouterr()
            exportDoer = export_cmd.ExportDoer(name=source_name,
                                               alias="multisig",
                                               base=source_base,
                                               bran=None,
                                               said=None,
                                               tels=True,
                                               kels=True,
                                               chains=True,
                                               files=False,
                                               allRegs=True,
                                               allCreds=True)
            directing.runController(doers=[exportDoer])
            assert exportDoer.hby is None
            assert exportDoer.rgy is None
            assert exportDoer.hab is None
            cesr = capsys.readouterr().out
            assert issuer.regk in cesr
            assert creder.said in cesr

            # Simulate a shell pipe without starting a subprocess; ImportDoer reads sys.stdin.buffer.
            stdin = io.TextIOWrapper(io.BytesIO(cesr.encode("utf-8")), encoding="utf-8")
            monkeypatch.setattr("sys.stdin", stdin)
            importDoer = import_cmd.ImportDoer(name=late_name,
                                               base=late_base,
                                               bran=None,
                                               cesrIn=None)
            directing.runController(doers=[importDoer])
            assert importDoer.hby is None
            assert importDoer.rgy is None
            importDoer.close()

            # Reopen the imported store and verify the streamed CESR materialized locally.
            imported_rgy = None
            with habbing.openHby(name=late_name, base=late_base, temp=False, clear=False, salt=SALT) as imported_hby:
                try:
                    imported_rgy = credentialing.Regery(hby=imported_hby, name=late_name, base=late_base)
                    importedGroup = imported_hby.habByName("multisig")
                    assert importedGroup.pre == group_pre
                    assert importedGroup.smids == smids
                    regrec = imported_rgy.reger.regs.get(keys=issuer.regk)
                    assert regrec.registryKey == issuer.regk
                    assert regrec.prefix == group_pre
                    assert issuer.regk in imported_rgy.reger.tevers
                    imported, *_ = imported_rgy.reger.cloneCred(said=creder.said)
                    assert imported.raw == creder.raw
                finally:
                    closeRegery(imported_rgy, clear=False)
        finally:
            closeRegery(source_rgy)
            closeRegery(late_rgy)
            closeHby(source)
            closeHby(late)
