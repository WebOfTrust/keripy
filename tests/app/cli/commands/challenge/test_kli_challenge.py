import os
import time
import secrets

from hio.base import doing, tyming

from tests import conftest
from keri.app import habbing, indirecting, configing
from keri.core import coring

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(TEST_DIR)


def test_kli_challenge_commands(helpers, capsys, seeder):

    wanCf = configing.Configer(name="wan",
                               reopen=True,
                               clear=False,
                               headDirPath=CONFIG)
    wilCf = configing.Configer(name="wil",
                               reopen=True,
                               clear=False,
                               headDirPath=CONFIG)
    wesCf = configing.Configer(name="wes",
                               reopen=True,
                               clear=False,
                               headDirPath=CONFIG)

    with habbing.openHby(name="wan", temp=True, cf=wanCf, salt=coring.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", temp=True, cf=wilCf,
                            salt=coring.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", temp=True, cf=wesCf,
                            salt=coring.Salter(raw=b'wess-the-witness').qb64) as wesHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        base = secrets.token_urlsafe(8)
        test = ChallengeDoer(base, capsys)
        doers = wanDoers + wilDoers + wesDoers + [test]

        limit = 20.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (test.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

        assert test.done is True

        helpers.remove_test_dirs(base)


class ChallengeDoer(doing.DoDoer):
    """ Test scenario of kli command for challenge / response. """

    def __init__(self, base, capsys):
        self.base = base
        self.capsys = capsys

        super(ChallengeDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        # Create Bob's keystore
        cmd = conftest.CommandDoer(command=["init", "--name", "bob", "--nopasscode", "--base", self.base, "--salt",
                                            "0AMDEyMzQ1Njc4OWxtbm9wcQ", "--config-dir", CONFIG, "--config-file",
                                            "demo-witness-oobis"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Create Alice's keystore
        cmd = conftest.CommandDoer(command=["init", "--name", "alice", "--nopasscode",  "--base", self.base, "--salt",
                                            "0AMDEyMzQ1Njc4OWdoaWpsaw", "--config-dir", CONFIG, "--config-file",
                                            "demo-witness-oobis"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Incept Bob's local identifier
        cmd = conftest.CommandDoer(command=["incept", "--name", "bob", "--alias", "bob",  "--base", self.base, "--file",
                                            os.path.join(TEST_DIR, "bob.json")])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Incept Alice's local identifier
        cmd = conftest.CommandDoer(command=["incept", "--name", "alice", "--alias", "alice", "--base", self.base,
                                            "--file", os.path.join(TEST_DIR, "alice.json")])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Exchange OOBIs
        cmd = conftest.CommandDoer(command=["oobi", "resolve", "--name", "bob", "--alias", "bob",
                                            "--base", self.base, "--oobi-alias", "alice", "--oobi",
                                            "http://127.0.0.1:5642/oobi/EQP2gB4liBrxKyLLbc7fiNwReTw1Hp3s77hBlkYK3bTw"
                                            "/witness/B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw"])
        self.extend([cmd])
        while not cmd.done:
            yield

        cmd = conftest.CommandDoer(command=["oobi", "resolve", "--name", "alice", "--alias", "alice",
                                            "--base", self.base, "--oobi-alias", "bob", "--oobi",
                                            "http://127.0.0.1:5642/oobi/EE5g9tVrweyzV_g9tjVCPeutTuXSoW1NCqlBfYI8FHlM"
                                            "/witness/B6KBd3GmnWvjcmE775zNRPCsJfOhasjBbyLjUpYOWvyw"])
        self.extend([cmd])
        while not cmd.done:
            yield

        # Alice is going to challenge Bob:
        self.capsys.readouterr()

        cmd = conftest.CommandDoer(command=["challenge", "generate", "-o", "string"])
        self.extend([cmd])
        while not cmd.done:
            yield

        response = self.capsys.readouterr()
        words = response.out.removesuffix("\n")
        cmd = conftest.CommandDoer(command=["challenge", "respond", "--name", "bob", "--alias", "bob",  "--base",
                                            self.base, "--recipient", "alice", "--words", f"\"{words.split(' ')}\""]
                                   )
        self.extend([cmd])
        while not cmd.done:
            yield

        cmd = conftest.CommandDoer(command=["challenge", "verify", "--name", "alice", "--alias", "alice",  "--base",
                                            self.base, "--signer", "bob", "--words", f"\"{words.split(' ')}\""]
                                   )
        self.extend([cmd])
        while not cmd.done:
            yield
        response = self.capsys.readouterr()

        assert "Signer bob successfully responded to challenge words:" in response.out
        assert f"\"{words.split(' ')}\"" in response.out
        return True
