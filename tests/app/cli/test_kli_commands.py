import os
import shutil

import multicommand
import pytest
import time
from hio.base import doing, tyming

from keri.app import habbing, indirecting, configing, directing
from keri.app.cli import commands
from keri.app.cli.common import existing
from keri.core import coring
from keri.kering import ValidationError

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def remove_test_dirs(name):
    if os.path.exists(f'/usr/local/var/keri/db/{name}'):
        shutil.rmtree(f'/usr/local/var/keri/db/{name}')
    if os.path.exists(f'/usr/local/var/keri/ks/{name}'):
        shutil.rmtree(f'/usr/local/var/keri/ks/{name}')
    if os.path.exists(f'/usr/local/var/keri/reg/{name}'):
        shutil.rmtree(f'/usr/local/var/keri/reg/{name}')
    if os.path.exists(f'/usr/local/var/keri/cf/{name}.json'):
        os.remove(f'/usr/local/var/keri/cf/{name}.json')


def test_standalone_kli_commands():
    remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False

    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["init", "--name", "test", "--nopasscode"])
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
                              "@"+os.path.join(TEST_DIR, "anchor.json")])
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
                              "@"+os.path.join(TEST_DIR, "anchor.json")])
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

    rotate_args = ["rotate", "--name", "test", "--alias", "trans",  "--next-count", "3", "--sith", "2"]
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
                              "@"+os.path.join(TEST_DIR, "anchor.json")])
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
                              "@"+os.path.join(TEST_DIR, "anchor.json")])
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


def test_kel_commands():
    remove_test_dirs("witness-test")

    for name in ["wan", "wil", "wes", "test"]:
        if os.path.exists('/usr/local/var/keri/db/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/db/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/ks/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/ks/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/cf/{}.json'.format(name)):
            os.remove('/usr/local/var/keri/cf/{}.json'.format(name))

    wancf = configing.Configer(name="wan", headDirPath="config", temp=False, reopen=True, clear=False)
    wilcf = configing.Configer(name="wil", headDirPath="config", temp=False, reopen=True, clear=False)
    wescf = configing.Configer(name="wes", headDirPath="config", temp=False, reopen=True, clear=False)

    with habbing.openHby(name="wan", salt=coring.Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf) as wanHby, \
            habbing.openHby(name="wil", salt=coring.Salter(raw=b'will-the-witness').qb64, temp=False,
                            cf=wilcf) as wilHby, \
            habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64, temp=False,
                            cf=wescf) as wesHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        inceptor = CommandDoer(doers=[])
        doers = wanDoers + wilDoers + wesDoers + [inceptor]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running thru the KEL `kli` commands for incepting, rotating and
    creating interaction events.

    """

    def __init__(self, doers, **kwa):

        super(CommandDoer, self).__init__(doers=doers, **kwa)
