import os

import multicommand
import pytest

from keri.app import directing, habbing
from keri.app.cli import commands
from keri.app.cli.common import existing
from keri.core import coring
from keri.kering import ValidationError

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_standalone_kli_commands(helpers, capsys):
    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False

    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["init", "--name", "test", "--nopasscode", "--salt", habbing.SALT])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHby("test") as hby:
        assert os.path.isdir(hby.db.path) is True

    args = parser.parse_args(["incept", "--name", "test", "--alias", "non-trans", "--file",
                              os.path.join(TEST_DIR, "non-transferable-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    # Create non-transferable identifier
    with existing.existingHab(name="test", alias="non-trans") as (hby, hab):
        assert hab.pre == "BjzVSYRS7pWuKLbo_FBqDB2RYnMmbdDo8RG1TDVz_L0o"

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "non-trans"])
    assert args.handler is not None
    doers = args.handler(args)

    # Attempt to rotate a non-transferable identifier
    with pytest.raises(ValueError):
        directing.runController(doers=doers)

    # Create transferable identifier
    args = parser.parse_args(["incept", "--name", "test", "--alias", "trans", "--file",
                              os.path.join(TEST_DIR, "transferable-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans"])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"
        assert hab.kever.sn == 1

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"
        assert hab.kever.sn == 2
        assert hab.kever.ilk == coring.Ilks.rot
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EoXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EyR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    args = parser.parse_args(["interact", "--name", "test", "--alias", "trans", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"
        assert hab.kever.sn == 3
        assert hab.kever.ilk == coring.Ilks.ixn
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EoXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EyR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    rotate_args = ["rotate", "--name", "test", "--alias", "trans", "--next-count", "3", "--sith", "2"]
    args = parser.parse_args(rotate_args)
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"
        assert hab.kever.sn == 4
        assert hab.kever.ilk == coring.Ilks.rot
        assert hab.kever.tholder.sith == "1"

    args = parser.parse_args(rotate_args)
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg"
        assert hab.kever.sn == 5
        assert hab.kever.ilk == coring.Ilks.rot
        assert hab.kever.tholder.sith == "2"
        assert [verfer.qb64 for verfer in hab.kever.verfers] == ['DJpmnuJqalZJ-wgDZzJkm9Y7sKZKQi9eaie7uPcTXVjw',
                                                                 'DT9U0mqDhv_vE_7FU02DQ2a22m0ZWuRPDtI0q1VI0kmA',
                                                                 'DQzBSXe7yYn5xbFKdF4DStB6wiBnxIWgenRTZbKJmNG0']

    # Skipping sign and verify, they rely on console output.

    # Establishment Only
    args = parser.parse_args(["incept", "--name", "test", "--alias", "est-only", "--file",
                              os.path.join(TEST_DIR, "estonly-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == "ErzV_sZ8iC-mKOFN7dknxnXSISU3hvlUZr7TMcJs7JsY"
        assert hab.kever.sn == 0

    args = parser.parse_args(["interact", "--name", "test", "--alias", "est-only", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    with pytest.raises(ValidationError):
        directing.runController(doers=doers)

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "est-only"])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == "ErzV_sZ8iC-mKOFN7dknxnXSISU3hvlUZr7TMcJs7JsY"
        assert hab.kever.sn == 1
        assert hab.kever.ilk == coring.Ilks.rot

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "est-only", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == "ErzV_sZ8iC-mKOFN7dknxnXSISU3hvlUZr7TMcJs7JsY"
        assert hab.kever.sn == 2
        assert hab.kever.ilk == coring.Ilks.rot
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EoXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EyR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    # Clear output buffer so far
    capsys.readouterr()
    args = parser.parse_args(["sign", "--name", "test", "--alias", "trans", "--text", "this is test data to sign"])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)

    capsigs = capsys.readouterr()
    assert capsigs.out == ('1. '
                           'AAFU6Ij62eelYGQzIGJ7WhmQdsjYw6lhOb0_rDH4kALIsX9iEFdw4Uqi2CAiWsGraMe3NNYMLbaHAJ86hDOsIGCA\n'
                           '2. '
                           'ABxq2LNAhwiez2o8bFexl_qBWlvQjqOKi6Km-gK_J6tXZzyKs7TEB39-5mu7vIGkB36A9IQ2qswu--119E9bK4Bg\n'
                           '3. '
                           'ACi5faVb-zjOGNutRmZKT1kLv_9ZsPH383BWNZSetgho4hId5rxErvze2tNWDgiqonKhHuUzl0n9I__KgcTyscDg\n')

    args = parser.parse_args(["verify", "--name", "test", "--alias", "trans", "--prefix",
                              "EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg", "--text", "this is test data to sign",
                              "--signature",
                              "AAFU6Ij62eelYGQzIGJ7WhmQdsjYw6lhOb0_rDH4kALIsX9iEFdw4Uqi2CAiWsGraMe3NNYMLbaHAJ86hDOsIGCA"
                              ])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)

    capsigs = capsys.readouterr()
    assert capsigs.out == 'Signature 1 is valid.\n'

    args = parser.parse_args(["status", "--name", "test", "--alias", "trans"])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)
    capsigs = capsys.readouterr()
    assert capsigs.out == ('Identifier: EdSWKic0jXrzhG2mfCsdwWBOxIhnufSJjMT53YmCq8Pg\n'
                           'Seq No:\t5\n'
                           '\n'
                           'Witnesses:\n'
                           'Count:\t\t0\n'
                           'Receipts:\t0\n'
                           'Threshold:\t0\n'
                           '\n'
                           'Public Keys:\t\n'
                           '\t1. DJpmnuJqalZJ-wgDZzJkm9Y7sKZKQi9eaie7uPcTXVjw\n'
                           '\t2. DT9U0mqDhv_vE_7FU02DQ2a22m0ZWuRPDtI0q1VI0kmA\n'
                           '\t3. DQzBSXe7yYn5xbFKdF4DStB6wiBnxIWgenRTZbKJmNG0\n'
                           '\n')

    args = parser.parse_args(["escrow", "--name", "test"])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)
    capesc = capsys.readouterr()
    assert capesc.out == ('{\n'
                          '  "out-of-order-events": [],\n'
                          '  "partially-witnessed-events": [],\n'
                          '  "partially-signed-events": [],\n'
                          '  "likely-duplicitous-events": [],\n'
                          '  "missing-registry-escrow": [],\n'
                          '  "missing-issuer-escrow": [],\n'
                          '  "broken-chain-escrow": [],\n'
                          '  "missing-schema-escrow": []\n'
                          '}\n')
