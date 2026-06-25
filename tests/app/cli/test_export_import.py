# -*- encoding: utf-8 -*-
"""
tests.app.cli.test_export_import module

Late-joiner state-sync workflow coverage.
"""
import io

from keri import core
from keri.app import directing, habbing
from keri.app.cli.commands import import_ as import_cmd
from keri.app.cli.commands.vc import export as export_cmd
from keri.vdr import credentialing
from tests.app import openLateJoinerMultisig


TMP_BASE_PATH = "test-state-sync"


def exportStateBundle(name, base, alias, bundleDir, helpers):
    """
    Test helper that exports a full set of .cesr files (state-sync bundle)
    for alias into bundleDir using ExportDoer.
    """
    bundleDir.mkdir()
    with helpers.pushd(bundleDir):
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


def assertCredentialImportComplete(reger, creder):
    def assertIndexContains(index, key, said):
        saiders = index.get(keys=(key,))
        assert saiders is not None
        assert said in {saider.qb64 for saider in saiders}

    # cloneCred() proves the ACDC body was logged; these indexes prove the
    # verifier completed and made the credential visible to normal wallet queries.
    assert reger.saved.get(keys=(creder.said,)) is not None
    assertIndexContains(reger.issus, creder.issuer, creder.said)
    assertIndexContains(reger.subjs, creder.attrib["i"], creder.said)
    assertIndexContains(reger.schms, creder.schema, creder.said)

    # Empty credential escrows prove the import resolved registry, schema, and
    # chain dependencies instead of leaving the ACDC merely logged for later.
    assert reger.mre.get(keys=(creder.said,)) is None
    assert reger.mce.get(keys=(creder.said,)) is None
    assert reger.mse.get(keys=(creder.said,)) is None


def test_import_late_joiner_multisig_registry_and_credential(tmp_path, seeder, helpers):
    # Purpose: exercise the production late-joiner state-sync path end to end.
    with openLateJoinerMultisig(helpers, prefix="late-state-sync",
                                base=helpers.isolatedBase(TMP_BASE_PATH, tmp_path)) as (
            (srcHby, member1, groupHab),
            (lateHby, member2),
            addLateJoiner):
        source_rgy = late_rgy = None
        try:
            # Perform work with the first member that the second member will not see after joining.
            seeder.seedSchema(srcHby.db)
            seeder.seedSchema(lateHby.db)
            source_rgy = credentialing.Regery(hby=srcHby, name=srcHby.name, base=srcHby.base)
            source_rgy, issuer = helpers.makeRegistry(srcHby, groupHab, name="late-reg", rgy=source_rgy)
            creder, *_ = helpers.issueCredential(srcHby,
                                                 groupHab,
                                                 issuer=issuer,
                                                 subject=dict(LEI="late-joiner"),
                                                 rgy=source_rgy)

            assert lateHby.habByName("multisig") is None
            lateGroup = addLateJoiner()
            assert lateGroup.pre == groupHab.pre
            assert lateGroup.smids == [member1.pre, member2.pre]
            assert lateGroup.rmids == [member1.pre, member2.pre]

            # Prove the late member has the group but not the pre-join registry mapping yet.
            late_rgy = credentialing.Regery(hby=lateHby, name=lateHby.name, base=lateHby.base)
            assert late_rgy.reger.regs.get(keys=issuer.regk) is None
            helpers.closeRegery(late_rgy, clear=False)
            late_rgy = None

            bundle = tmp_path / "late-state-bundle"
            source_name, source_base = srcHby.name, srcHby.base
            late_name, late_base = lateHby.name, lateHby.base
            group_pre = groupHab.pre
            smids = list(lateGroup.smids)
            helpers.closeRegery(source_rgy, clear=False)
            source_rgy = None
            # ExportDoer and ImportDoer must reopen command-addressable stores by name/base.
            helpers.closeHby(srcHby, clear=False)
            helpers.closeHby(lateHby, clear=False)

            exportStateBundle(name=source_name,
                              base=source_base,
                              alias="multisig",
                              bundleDir=bundle,
                              helpers=helpers)

            doer = import_cmd.ImportDoer(name=late_name,
                                         base=late_base,
                                         bran=None,
                                         cesrIn=str(bundle))
            directing.runController(doers=[doer])
            assert doer.hby is None
            assert doer.rgy is None
            doer.close()

            imported_rgy = None
            with habbing.openHby(name=late_name, base=late_base, temp=False, clear=False,
                                 salt=core.Salter(raw=b'0123456789abcdef').qb64) as imported_hby:
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
                    assertCredentialImportComplete(imported_rgy.reger, creder)
                finally:
                    helpers.closeRegery(imported_rgy, clear=False)
        finally:
            helpers.closeRegery(source_rgy)
            helpers.closeRegery(late_rgy)
            helpers.closeHby(srcHby)
            helpers.closeHby(lateHby)


def test_export_stdout_import_stdin_registry_and_credential(tmp_path, capsys, monkeypatch, seeder, helpers):
    # Purpose: exercise shell-style `kli vc export ... | kli import ...` without a file bundle.
    with openLateJoinerMultisig(helpers, prefix="late-stream-sync",
                                base=helpers.isolatedBase(TMP_BASE_PATH, tmp_path)) as (
            (source, member1, groupHab),
            (late, member2),
            addLateJoiner):
        source_rgy = late_rgy = None
        try:
            # Perform work with the first member that the second member will not see after joining.
            seeder.seedSchema(source.db)
            seeder.seedSchema(late.db)
            source_rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            source_rgy, issuer = helpers.makeRegistry(source, groupHab, name="stream-reg", rgy=source_rgy)
            creder, *_ = helpers.issueCredential(source,
                                                 groupHab,
                                                 issuer=issuer,
                                                 subject=dict(LEI="stream"),
                                                 rgy=source_rgy)

            lateGroup = addLateJoiner()

            # Prove the late member has the group but not the pre-join registry mapping yet.
            late_rgy = credentialing.Regery(hby=late, name=late.name, base=late.base)
            assert late_rgy.reger.regs.get(keys=issuer.regk) is None
            helpers.closeRegery(late_rgy, clear=False)
            late_rgy = None

            source_name, source_base = source.name, source.base
            late_name, late_base = late.name, late.base
            group_pre = groupHab.pre
            smids = list(lateGroup.smids)
            helpers.closeRegery(source_rgy, clear=False)
            source_rgy = None
            # ExportDoer and ImportDoer must reopen command-addressable stores by name/base.
            helpers.closeHby(source, clear=False)
            helpers.closeHby(late, clear=False)

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

            imported_rgy = None
            with habbing.openHby(name=late_name, base=late_base, temp=False, clear=False,
                                 salt=core.Salter(raw=b'0123456789abcdef').qb64) as imported_hby:
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
                    assertCredentialImportComplete(imported_rgy.reger, creder)
                finally:
                    helpers.closeRegery(imported_rgy, clear=False)
        finally:
            helpers.closeRegery(source_rgy)
            helpers.closeRegery(late_rgy)
            helpers.closeHby(source)
            helpers.closeHby(late)
