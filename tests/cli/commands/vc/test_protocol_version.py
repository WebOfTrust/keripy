"""CLI version selection reaches real anchors, evidence, and IPEX parsing."""
import importlib

import pytest

from keri.app import openHab
from keri.core import Parser, Schemer
from keri.kering import Kinds, Version, Vrsn_1_0, Vrsn_2_0
from keri.vdr import Regery

registry_cmd = importlib.import_module("keri.cli.commands.vc.registry.incept")
create_cmd = importlib.import_module("keri.cli.commands.vc.create")
list_cmd = importlib.import_module("keri.cli.commands.ipex.list")
grant_cmd = importlib.import_module("keri.cli.commands.ipex.grant")
admit_cmd = importlib.import_module("keri.cli.commands.ipex.admit")


def advance_once(doer, method):
    """Enter the real command then stop at its asynchronous completion wait."""
    task = getattr(doer, method)(tymth=lambda: 0.0)
    next(task)
    next(task)
    return task


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
@pytest.mark.parametrize("est_only", [False, True], ids=["interaction", "rotation"])
def test_registry_and_credential_anchor_versions(monkeypatch, version, est_only):
    """The CLI creates signed anchors in the selected version without default drift."""
    selected = version or Version
    with openHab(name="issuer", temp=True, version=Vrsn_1_0) as (hby, hab):
        rgy = Regery(hby=hby, name="issuer", temp=True)
        tasks = []
        wires = []
        try:
            def setup(**kwargs):
                """Reuse only the test-owned storage while checking option propagation."""
                assert kwargs["version"] == version
                hby.version = selected
                return hby

            monkeypatch.setattr(registry_cmd, "setupHby", setup)
            monkeypatch.setattr(create_cmd.existing, "setupHby", setup)
            monkeypatch.setattr(registry_cmd, "Regery", lambda **kwargs: rgy)
            monkeypatch.setattr(create_cmd, "Regery", lambda **kwargs: rgy)
            # Record actual signed bytes rather than replacing anchor construction.
            anchor = hab.rotate if est_only else hab.interact
            def capture(**kwargs):
                """Keep normal key-state mutation and retain its public wire result."""
                wire = anchor(**kwargs)
                wires.append((wire, list(hab.kever.verfers)))
                return wire
            monkeypatch.setattr(hab, "rotate" if est_only else "interact", capture)
            argv = ["--name", "issuer", "--alias", "issuer", "--registry-name", "registry"]
            if version is not None:
                argv.extend(["--version", f"{version.major}.{version.minor}"])
            if est_only:
                argv.extend(["--establishment-only", "true"])
            args = registry_cmd.parser.parse_args(argv)
            doer, = args.handler(args)
            tasks.append(advance_once(doer, "inceptDo"))
            registry = rgy.registryByName("registry")
            assert registry.vcp.pvrsn == Vrsn_1_0
            # A minimal real JSON schema isolates version behavior from business fields.
            schema = Schemer(sed={"$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "type": "object"})
            hby.db.schema.pin(keys=schema.said, val=schema)
            argv = ["--name", "issuer", "--alias", "issuer", "--registry-name", "registry",
                    "--schema", schema.said, "--data", "{}"]
            if version is not None:
                argv.extend(["--version", f"{version.major}.{version.minor}"])
            args = create_cmd.parser.parse_args(argv)
            issuer, = args.handler(args)
            tasks.append(advance_once(issuer, "createDo"))
            assert issuer.creder.pvrsn == Vrsn_1_0
            assert len(wires) == 2
            for wire, verfers in wires:
                frame, = Parser(version=selected).parse(ims=bytearray(wire), processive=False)
                assert frame.serder.pvrsn == selected
                siger, = frame.sigers
                assert verfers[siger.index].verify(siger.raw, frame.serder.raw)
        finally:
            for task in tasks:
                task.close()
            rgy.reger.close(clear=True)


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
def test_ipex_list_parser_selects_genus(monkeypatch, version):
    """The actual mailbox parser accepts the selected signed reply encoding."""
    from keri.core import exchange
    selected = version or Version
    with openHab(name="reader", temp=True, version=selected) as (hby, hab):
        rgy = Regery(hby=hby, name="reader", temp=True)
        try:
            def setup(**kwargs):
                """Avoid persistent paths while retaining the command's real parser."""
                assert kwargs["version"] == version
                return hby
            monkeypatch.setattr(list_cmd, "setupHby", setup)
            monkeypatch.setattr(list_cmd, "Regery", lambda **kwargs: rgy)
            argv = ["--name", "reader", "--alias", "reader", "--poll"]
            if version is not None:
                argv.extend(["--version", f"{version.major}.{version.minor}"])
            args = list_cmd.parser.parse_args(argv)
            doer, = args.handler(args)
            serder = exchange(sender=hab.pre, route="/ipex/admit", version=selected, kind=Kinds.json)
            wire = hab.endorse(serder, last=False, framed=True, gvrsn=selected)
            frame, = doer.mbx.parser.parse(ims=bytearray(wire), processive=False)
            assert frame.serder.said == serder.said
            assert doer.mbx.parser.version == selected
        finally:
            rgy.reger.close(clear=True)


def seed_credential(hby, hab, rgy):
    """Store a real anchored v1 registry and issuance for command replay tests."""
    from keri.core import Diger, Number, Prefixer, Saider, SealEvent
    from keri.vc import credential
    registry = rgy.makeRegistry(name="registry", prefix=hab.pre, version=Vrsn_1_0, kind=Kinds.json)
    serder = registry.vcp
    hab.interact(data=[SealEvent(serder.pre, serder.snh, serder.said)._asdict()], version=hab.kever.serder.pvrsn)
    registry.anchorMsg(pre=serder.pre, regd=serder.said, seqner=Number(num=hab.kever.sn),
                       saider=Diger(qb64=hab.kever.serder.said))
    rgy.processEscrows()
    schema = Schemer(sed={"$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "type": "object"})
    hby.db.schema.pin(keys=schema.said, val=schema)
    creder = credential(issuer=hab.pre, recipient=hab.pre, schema=schema.said, status=registry.regk,
                        data={}, version=Vrsn_1_0, kind=Kinds.json)
    issuance = registry.issue(said=creder.said)
    hab.interact(data=[SealEvent(issuance.pre, issuance.snh, issuance.said)._asdict()], version=hab.kever.serder.pvrsn)
    registry.anchorMsg(pre=issuance.pre, regd=issuance.said, seqner=Number(num=hab.kever.sn),
                       saider=Diger(qb64=hab.kever.serder.said))
    rgy.processEscrows()
    # Admission is outside this command-emission test; proof records contain real TEL seals.
    rgy.reger.creds.pin(keys=(creder.said,), val=creder)
    rgy.reger.cancs.pin(keys=(creder.said,), val=(Prefixer(qb64=issuance.pre), Number(num=issuance.sn), Diger(qb64=issuance.said)))
    rgy.reger.saved.pin(keys=(creder.said,), val=Saider(qb64=creder.said))
    return creder


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
def test_grant_and_admit_emission_boundary(monkeypatch, version):
    """V1 CLI messages carry parseable evidence; legacy grant still rejects v2."""
    selected = version or Version
    queued = []

    class Poster:
        """Capture the actual serializer output at the network delivery seam."""
        def __init__(self, **kwargs):
            """Retain the selected transport genus for independent parsing below."""
            self.version = kwargs.get("version") or kwargs["hby"].version

        def send(self, serder, attachment=None, *, gvrsn=None):
            """Retain bytes exactly as the command would hand them to transport."""
            queued.append((serder, bytes(attachment or b""), gvrsn or self.version))

        def deliver(self):
            """No socket is required to inspect the completed public wire message."""
            return []

    with openHab(name="issuer", temp=True, version=selected) as (hby, hab):
        rgy = Regery(hby=hby, name="issuer", temp=True)
        tasks = []
        try:
            creder = seed_credential(hby, hab, rgy)
            def setup(**kwargs):
                """Reuse the real fixture and check CLI option propagation."""
                assert kwargs["version"] == version
                return hby
            monkeypatch.setattr(grant_cmd, "setupHby", setup)
            monkeypatch.setattr(admit_cmd.existing, "setupHby", setup)
            monkeypatch.setattr(grant_cmd.credentialing, "Regery", lambda **kwargs: rgy)
            monkeypatch.setattr(admit_cmd, "Regery", lambda **kwargs: rgy)
            monkeypatch.setattr(grant_cmd, "StreamPoster", Poster)
            monkeypatch.setattr(admit_cmd, "StreamPoster", Poster)
            argv = ["--name", "issuer", "--alias", "issuer", "--said", creder.said, "--recipient", hab.pre]
            if version is not None:
                argv.extend(["--version", f"{version.major}.{version.minor}"])
            args = grant_cmd.parser.parse_args(argv)
            grant, = args.handler(args)
            if selected == Vrsn_2_0:
                # V2 grants use a different protocol API; this legacy CLI limitation is unchanged.
                with pytest.raises(ValueError, match="specialExchange not supported in version 2"):
                    advance_once(grant, "grantDo")
                assert queued == []
                return
            tasks.append(advance_once(grant, "grantDo"))
            assert queued
            for serder, attachment, genus in queued:
                frame, = Parser(version=genus).parse(ims=bytearray(serder.raw + attachment), processive=False)
                assert frame.serder.said == serder.said
                assert genus == Vrsn_1_0
            exn = queued[-1][0]
            assert exn.ked["r"] == "/ipex/grant"
            from keri.core import SerderACDC, SerderKERI
            assert SerderACDC(sad=exn.ked["e"]["acdc"]).raw == creder.raw
            assert SerderKERI(sad=exn.ked["e"]["anc"]).raw == hab.kever.serder.raw
            signature, = frame.tsgs[0][3]
            assert hab.kever.verfers[signature.index].verify(signature.raw, exn.raw)
            # The real stored grant drives the actual admit generator and serializer.
            args = admit_cmd.parser.parse_args(["--name", "issuer", "--alias", "issuer", "--said", exn.said,
                                                "--version", "1.0"])
            admit, = args.handler(args)
            tasks.append(advance_once(admit, "admitDo"))
            reply, attachment, genus = queued[-1]
            frame, = Parser(version=genus).parse(ims=bytearray(reply.raw + attachment), processive=False)
            assert frame.serder.ked["r"] == "/ipex/admit"
            assert frame.serder.ked["p"] == exn.said
            assert genus == Vrsn_1_0
            signature, = frame.tsgs[0][3]
            assert hab.kever.verfers[signature.index].verify(signature.raw, reply.raw)
        finally:
            for task in tasks:
                task.close()
            rgy.reger.close(clear=True)


@pytest.mark.parametrize("genus", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
def test_source_proofs_preserve_selected_genus(genus):
    """Deep credential evidence honors an override without changing default proof bytes."""
    from keri.vc import credential
    with openHab(name="issuer", temp=True, version=Vrsn_1_0) as (hby, hab):
        rgy = Regery(hby=hby, name="issuer", temp=True)
        try:
            parent = seed_credential(hby, hab, rgy)
            child = credential(issuer=hab.pre, schema=parent.schema, data={},
                               source={"d": "", "source": {"n": parent.said}},
                               version=Vrsn_1_0, kind=Kinds.json)
            (source, proof), = rgy.reger.sources(hby.db, child, gvrsn=genus)
            frame, = Parser(version=genus or Vrsn_1_0).parse(
                ims=bytearray(source.raw + proof), processive=False)
            assert frame.serder.raw == parent.raw
            assert len(frame.ssts) == 1
            assert frame.ssts[0][0].qb64 == parent.said
        finally:
            rgy.reger.close(clear=True)
