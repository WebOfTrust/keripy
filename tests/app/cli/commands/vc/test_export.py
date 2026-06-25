# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.vc.test_export module
"""
from contextlib import contextmanager

from keri import core
from keri.app import directing, habbing
from keri.app.cli.commands.vc import export as export_cmd
from keri.vdr import credentialing


CLI_BASE = "test-vc-export"


@contextmanager
def openExportDoer(*args, **kwa):
    """Open ExportDoer for direct method tests and close command-owned resources."""
    doer = None
    try:
        doer = export_cmd.ExportDoer(*args, **kwa)
        yield doer
    finally:
        if doer is not None:
            doer.close()


def test_export_credentials_full_sets_related_flags(tmp_path, seeder, helpers):
    # Purpose: keep parser-to-doer flag expansion honest for the new full state-sync export options.
    with habbing.openHby(name="export-flags", base=helpers.isolatedBase(CLI_BASE, tmp_path),
                         temp=False, clear=True, salt=core.Salter(raw=b'0123456789abcdef').qb64) as source:
        doer = None
        try:
            source.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            seeder.seedSchema(source.db)
            helpers.closeHby(source, clear=False)

            args = export_cmd.parser.parse_args(["--name", source.name,
                                                 "--base", source.base,
                                                 "--alias", "issuer",
                                                 "--full",
                                                 "--all-registries",
                                                 "--all-credentials",
                                                 "--include-revoked"])

            doers = export_cmd.export_credentials(args)
            assert len(doers) == 1
            doer = doers[0]
            assert doer.tels is True
            assert doer.kels is True
            assert doer.chains is True
            assert doer.allRegs is True
            assert doer.allCreds is True
            assert doer.inclRev is True

            doer.close()
            assert doer.hby is None
            assert doer.rgy is None
            assert doer.hab is None
            doer.close()
        finally:
            if doer is not None:
                doer.close()
            helpers.closeHby(source)


def test_export_selection_revocation_and_registry_file_branches(tmp_path, seeder, helpers):
    # Purpose: verify ExportDoer selects the right registry and credential material for file bundles.
    with habbing.openHby(name="export-selection", base=helpers.isolatedBase(CLI_BASE, tmp_path),
                         temp=False, clear=True, salt=core.Salter(raw=b'0123456789abcdef').qb64) as source:
        rgy = None
        try:
            hab = source.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            other = source.makeHab(name="other", icount=1, isith="1", ncount=1, nsith="1")
            seeder.seedSchema(source.db)
            rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            rgy, active_issuer = helpers.makeRegistry(source, hab, name="active", rgy=rgy)
            active, *_ = helpers.issueCredential(source, hab, issuer=active_issuer,
                                                 subject=dict(LEI="active"), rgy=rgy)
            rgy, revoked_issuer = helpers.makeRegistry(source, hab, name="revoked", rgy=rgy)
            revoked, *_ = helpers.issueCredential(source, hab, issuer=revoked_issuer,
                                                  subject=dict(LEI="revoked"), revoked=True, rgy=rgy)
            other_reg = rgy.makeRegistry(prefix=other.pre, name="other", noBackers=True)
            helpers.closeRegery(rgy, clear=False)
            helpers.closeHby(source, clear=False)

            def acdcPath(out, creder):
                return out / f"{creder.said}-acdc.cesr"

            def telPath(out, pre):
                return out / f"{pre}-tel.cesr"

            def kelPath(out, pre):
                return out / f"{pre}-kel.cesr"

            def runExport(dirname, **kwa):
                out = tmp_path / dirname
                out.mkdir()
                opts = dict(name=source.name,
                            alias="issuer",
                            base=source.base,
                            bran=None,
                            said=None,
                            tels=False,
                            kels=False,
                            chains=False,
                            files=True)
                opts.update(kwa)
                with helpers.pushd(out):
                    doer = export_cmd.ExportDoer(**opts)
                    directing.runController(doers=[doer])
                    assert doer.hby is None
                    assert doer.rgy is None
                    assert doer.hab is None
                return out

            default = runExport("default")
            assert acdcPath(default, active).exists()
            assert not acdcPath(default, revoked).exists()

            include_revoked = runExport("include-revoked", inclRev=True)
            assert acdcPath(include_revoked, active).exists()
            assert acdcPath(include_revoked, revoked).exists()

            all_regs = runExport("all-regs", allRegs=True, kels=True)
            assert telPath(all_regs, active_issuer.regk).exists()
            assert telPath(all_regs, revoked_issuer.regk).exists()
            assert kelPath(all_regs, hab.pre).exists()
            assert not telPath(all_regs, other_reg.regk).exists()
            assert not acdcPath(all_regs, active).exists()

            regs_and_creds = runExport("regs-and-creds", allRegs=True, allCreds=True, tels=True, kels=True)
            assert telPath(regs_and_creds, active_issuer.regk).exists()
            assert telPath(regs_and_creds, active.said).exists()
            assert acdcPath(regs_and_creds, active).exists()
            assert not acdcPath(regs_and_creds, revoked).exists()

            selected = runExport("selected", said=active.said)
            assert acdcPath(selected, active).exists()
            assert not acdcPath(selected, revoked).exists()
        finally:
            helpers.closeRegery(rgy)
            helpers.closeHby(source)


def test_export_output_file_and_stdout_paths(tmp_path, capsys, seeder, helpers):
    # Purpose: cover the two operator-facing output modes for exported KEL/TEL/ACDC material.
    with habbing.openHby(name="export-paths", base=helpers.isolatedBase(CLI_BASE, tmp_path),
                         temp=False, clear=True, salt=core.Salter(raw=b'0123456789abcdef').qb64) as source:
        rgy = None
        try:
            hab = source.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            seeder.seedSchema(source.db)
            rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            rgy, issuer = helpers.makeRegistry(source, hab, rgy=rgy)
            creder, *_ = helpers.issueCredential(source, hab, issuer=issuer,
                                                 subject=dict(LEI="254900OPPU84GM83MG36"), rgy=rgy)
            helpers.closeRegery(rgy, clear=False)
            helpers.closeHby(source, clear=False)

            with openExportDoer(name=source.name, alias="issuer", base=source.base, bran=None,
                                said=None, tels=False, kels=False, chains=False, files=False) as doer:
                doer.outputTEL(issuer.regk)
                doer.outputKEL(hab.pre)
                doer.outputCred(creder.said)
                out = capsys.readouterr().out
                assert issuer.regk in out
                assert hab.pre in out
                assert creder.said in out

                doer.files = True
                with helpers.pushd(tmp_path):
                    doer.outputTEL(issuer.regk)
                    doer.outputKEL(hab.pre)
                    doer.outputCred(creder.said)
                assert (tmp_path / f"{issuer.regk}-tel.cesr").read_text()
                assert (tmp_path / f"{hab.pre}-kel.cesr").read_text()
                assert (tmp_path / f"{creder.said}-acdc.cesr").read_bytes()
        finally:
            helpers.closeRegery(rgy)
            helpers.closeHby(source)


def test_export_output_credential_related_material_and_chain_branches(tmp_path, capsys, seeder, helpers):
    # Purpose: verify a credential export can include issuer KELs, registry/credential TELs, and chained ACDCs.
    with habbing.openHby(name="export-chain-source", base=helpers.isolatedBase(CLI_BASE, tmp_path),
                         temp=False, clear=True, salt=core.Salter(raw=b'0123456789abcdef').qb64) as source:
        rgy = None
        try:
            hab = source.makeHab(name="issuer", icount=1, isith="1", ncount=1, nsith="1")
            seeder.seedSchema(source.db)
            rgy = credentialing.Regery(hby=source, name=source.name, base=source.base)
            rgy, child_issuer = helpers.makeRegistry(source, hab, name="child", rgy=rgy)
            child, *_ = helpers.issueCredential(source, hab, issuer=child_issuer,
                                                subject=dict(LEI="child"), rgy=rgy)
            rgy, root_issuer = helpers.makeRegistry(source, hab, name="root", rgy=rgy)
            root, *_ = helpers.issueCredential(source, hab,
                                               issuer=root_issuer,
                                               subject=dict(LEI="root"),
                                               source={"d": child.said,
                                                       "child": {"n": child.said},
                                                       "o": "ignored"},
                                               rgy=rgy)
            helpers.closeRegery(rgy, clear=False)
            helpers.closeHby(source, clear=False)

            with openExportDoer(name=source.name, alias="issuer", base=source.base, bran=None,
                                said=None, tels=True, kels=True, chains=True, files=False) as doer:
                doer.outputCred(root.said)

                out = capsys.readouterr().out
                assert hab.pre in out
                assert child.regi in out
                assert child.said in out
                assert root.regi in out
                assert root.said in out
        finally:
            helpers.closeRegery(rgy)
            helpers.closeHby(source)
