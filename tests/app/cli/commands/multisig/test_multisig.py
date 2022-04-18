# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.multisig

"""

import os
import shutil

import multicommand
import time
from hio.base import doing, tyming

from keri.app import configing, habbing, indirecting
from keri.app.cli import commands
from keri.app.cli.common import existing
from keri.core import coring
from keri.db import dbing

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(TEST_DIR, "mtest")


def test_multisig_commands(helpers):
    helpers.remove_test_dirs("witness-test")

    for name in ["wan", "wil", "wes", "bob", "alice"]:
        if os.path.exists('/usr/local/var/keri/db/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/db/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/ks/{}'.format(name)):
            shutil.rmtree('/usr/local/var/keri/ks/{}'.format(name))
        if os.path.exists('/usr/local/var/keri/cf/{}.json'.format(name)):
            os.remove('/usr/local/var/keri/cf/{}.json'.format(name))

    wancf = configing.Configer(name="wan", headDirPath=CONFIG, temp=False, reopen=True,
                               clear=False)
    wilcf = configing.Configer(name="wil", headDirPath=CONFIG, temp=False, reopen=True,
                               clear=False)
    wescf = configing.Configer(name="wes", headDirPath=CONFIG, temp=False, reopen=True,
                               clear=False)

    with habbing.openHby(name="wan", salt=coring.Salter(raw=b'wann-the-witness').qb64, temp=False, cf=wancf) \
            as wanHby, \
            habbing.openHby(name="wil", salt=coring.Salter(raw=b'will-the-witness').qb64, temp=False,
                            cf=wilcf) as wilHby, \
            habbing.openHby(name="wes", salt=coring.Salter(raw=b'wess-the-witness').qb64, temp=False,
                            cf=wescf) as wesHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        test = TestDoer()
        doers = wanDoers + wilDoers + wesDoers + [test]

        limit = 30.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (test.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

    with existing.existingHby(name="bob") as hby:
        hab = hby.habByName("multisig")
        assert hab is not None

        assert hab.kever.ilk == coring.Ilks.icp
        assert [verfer.qb64 for verfer in hab.kever.verfers] == ["DM4YIQ6dC5bSeLyj8TIjOiin7oBYETrvblutThl32LMY",
                                                                 "DqVUUKxRHuE0a8Sw1q4eWvcaevfAxLR57k4QTJ-wK0Cg"]
        dgkey = dbing.dgKey(hab.kever.serder.preb, hab.kever.serder.saidb)
        wigs = hab.db.getWigs(dgkey)
        assert len(wigs) == 3


class TestDoer(doing.DoDoer):
    """ Test scenario of kli command for multisig credential issuance. """

    def __init__(self):

        super(TestDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        # Create Bob's keystore
        cmd = CommandDoer(command=["init", "--name", "bob", "--nopasscode", "--salt", "0AMDEyMzQ1Njc4OWxtbm9wcQ",
                                   "--config-dir", CONFIG, "--config-file", "demo-witness-oobis"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Create Alice's keystore
        cmd = CommandDoer(command=["init", "--name", "alice", "--nopasscode", "--salt", "0AMDEyMzQ1Njc4OWdoaWpsaw",
                                   "--config-dir", CONFIG, "--config-file", "demo-witness-oobis"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Incept Bob's local identifier
        cmd = CommandDoer(command=["incept", "--name", "bob", "--alias", "bob", "--file",
                                   os.path.join(TEST_DIR, "multisig-1-sample.json")])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Incept Alice's local identifier
        cmd = CommandDoer(command=["incept", "--name", "alice", "--alias", "alice", "--file",
                                   os.path.join(TEST_DIR, "multisig-2-sample.json")])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Exchange OOBIs
        cmd = CommandDoer(command=["oobi", "resolve", "--name", "bob", "--oobi-alias", "alice", "--oobi",
                                   "http://127.0.0.1:5642/oobi/EynzmnYakI31lffGDwO3AzRJo5fl52js8CjGpinduKuo/witness/"
                                   "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"])
        self.extend([cmd])
        while not cmd.done:
            yield

        cmd = CommandDoer(command=["oobi", "resolve", "--name", "alice", "--oobi-alias", "bob", "--oobi",
                                   "http://127.0.0.1:5642/oobi/E6dQZYOHx6zYwDQPOWP7siSmuCq-TkcpvX4Y6aPRWbJI/witness/"
                                   "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Create multisig identifier
        bob = CommandDoer(command=["multisig", "incept", "--name", "bob", "--alias", "bob", "--group",
                                   "multisig", "--file", os.path.join(TEST_DIR, "mtest-sample.json")])
        alice = CommandDoer(command=["multisig", "incept", "--name", "alice", "--alias", "alice", "--group",
                                     "multisig", "--file", os.path.join(TEST_DIR, "mtest-sample.json")])
        self.extend([bob, alice])
        while not bob.done and not alice.done:
            yield

        return True


class CommandDoer(doing.DoDoer):
    """
    DoDoer for running a single command-line command by initializing
    the doers for that command and executing them until they complete.

    """

    def __init__(self, command, **kwa):
        self.command = command
        super(CommandDoer, self).__init__(doers=[doing.doify(self.cmdDo)], **kwa)

    def cmdDo(self, tymth, tock=0.0):
        """  Execute single command from .command by parsing and executing the resulting doers """

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        parser = multicommand.create_parser(commands)
        args = parser.parse_args(self.command)
        assert args.handler is not None
        doers = args.handler(args)

        self.extend(doers)

        while True:
            done = True
            for doer in doers:
                if not doer.done:
                    done = False

            if done:
                break
            yield self.tock

        return True
