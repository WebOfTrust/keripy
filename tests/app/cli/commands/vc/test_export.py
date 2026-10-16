"""Credential exports select one attachment genus without rewriting SAD bodies."""
import importlib

import pytest

from keri.app import openHab
from keri.core import Diger, Number, Parser
from keri.kering import Kinds, Version, Vrsn_1_0, Vrsn_2_0
from keri.vc import credential
from keri.vdr import Regery

exporting = importlib.import_module("keri.cli.commands.vc.export")


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0])
def test_export_selects_genus_for_kel_and_credential(monkeypatch, capsys, version):
    """The real export command emits independently parseable KEL and proof bytes."""
    selected = version or Version
    with openHab(name="exporter", temp=True, version=selected) as (hby, hab):
        rgy = Regery(hby=hby, name="exporter", temp=True)
        try:
            # Seed stored proof records; export reads them without credential admission.
            creder = credential(issuer=hab.pre, schema=hab.pre,
                                data=dict(d="", i=hab.pre), version=Vrsn_1_0, kind=Kinds.json)
            rgy.reger.creds.pin(keys=(creder.said,), val=creder)
            rgy.reger.cancs.pin(keys=(creder.said,),
                               val=(hab.kever.prefixer, Number(num=0), Diger(qb64=hab.pre)))
            def setup(**kwargs):
                """Keep command startup inside the test-owned Habery."""
                assert kwargs["version"] == version
                return hby
            monkeypatch.setattr(exporting, "setupHby", setup)
            monkeypatch.setattr(exporting, "Regery", lambda **kwargs: rgy)
            argv = ["--name", "exporter", "--alias", "exporter", "--said", creder.said, "--kels"]
            if version is not None:
                argv.extend(["--version", f"{version.major}.{version.minor}"])
            args = exporting.parser.parse_args(argv)
            doer, = args.handler(args)
            capsys.readouterr()
            doer.outputCred(creder.said)
            wire = capsys.readouterr().out.encode()
            frames = Parser(version=selected).parse(ims=bytearray(wire), processive=False)
            assert [frame.serder.said for frame in frames] == [hab.pre, creder.said]
            assert frames[-1].serder.raw == creder.raw
        finally:
            rgy.reger.close(clear=True)
