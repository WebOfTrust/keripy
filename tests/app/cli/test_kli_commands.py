import json
import logging
import os

import multicommand
import pytest


from keri.kering import ValidationError, AuthError

from keri import core, help
from keri.core import coring

from keri.app import directing, habbing

from keri.app.cli import commands
from keri.app.cli.common import existing
from keri.app.cli.commands.witness import start as witness_start


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_standalone_kli_commands(helpers, capsys):
    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False

    parser = multicommand.create_parser(commands)
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    args = parser.parse_args(["init", "--name", "test", "--nopasscode", "--salt", salt])
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
        assert hab.pre == 'BI81UmEUu6Vrii26PxQagwdkWJzJm3Q6PERtUw1c_y9K'

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "non-trans"])
    assert args.handler is not None
    doers = args.handler(args)

    # Attempt to rotate a non-transferable identifier
    with pytest.raises(ValueError):
        directing.runController(doers=doers)

    # Create transferable identifier
    args = parser.parse_args(["incept", "--name", "test", "--alias", "trans", "--transferable", "--file",
                              os.path.join(TEST_DIR, "transferable-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    xpre = 'EF0bnfg4smFm9Q_OKlKUYRRQctGhTBWUU3rXf7zuA9GU'  # 'EORLw1VyVyBqNCHMUTYctinMDCba9o6Ut-34YFpiLBFK'
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans"])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 1

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 2
        assert hab.kever.ilk == coring.Ilks.rot
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    args = parser.parse_args(["interact", "--name", "test", "--alias", "trans", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 3
        assert hab.kever.ilk == coring.Ilks.ixn
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    rotate_args = ["rotate", "--name", "test", "--alias", "trans", "--next-count", "3", "--nsith", "2"]
    args = parser.parse_args(rotate_args)
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 4
        assert hab.kever.ilk == coring.Ilks.rot
        assert hab.kever.tholder.sith == "1"

    args = parser.parse_args(rotate_args)
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 5
        assert hab.kever.ilk == coring.Ilks.rot
        assert hab.kever.tholder.sith == "2"
        assert [verfer.qb64 for verfer in hab.kever.verfers] == ['DCaZp7iampWSfsIA2cyZJvWO7CmSkIvXmonu7j3E11Y8',
                                                                 'DE_VNJqg4b_7xP-xVNNg0NmttptGVrkTw7SNKtVSNJJg',
                                                                 'DEMwUl3u8mJ-cWxSnReA0rQesIgZ8SFoHp0U2WyiZjRt']

    # Skipping sign and verify, they rely on console output.

    # Establishment Only
    args = parser.parse_args(["incept", "--name", "test", "--alias", "est-only", "--transferable", "--file",
                              os.path.join(TEST_DIR, "estonly-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    epre = 'EMZ09JgN6Kr_rZH4Q7SovW-bxYXjiQX2XdSIQYpZnHsJ'
    with existing.existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == epre
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
        assert hab.pre == epre
        assert hab.kever.sn == 1
        assert hab.kever.ilk == coring.Ilks.rot

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "est-only", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)
    with existing.existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == epre
        assert hab.kever.sn == 2
        assert hab.kever.ilk == coring.Ilks.rot
        anchor = hab.kever.serder.ked["a"]
        assert anchor == [
            {'i': 'EAXJtG-Ek349v43ztpFdRXozyP7YnALdB0DdCEanlHmg',
             's': 0,
             'd': 'EAR75fE1ZmuCSfDwKPfbLowUWLqqi0ZX4502DLIo857Q'
             }
        ]

    # Clear output buffer so far
    capsys.readouterr()
    args = parser.parse_args(["sign", "--name", "test", "--alias", "trans", "--text", "this is test data to sign"])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)

    #"ErzV_sZ8iC-mKOFN7dknxnXSISU3hvlUZr7TMcJs7JsY"

    capsigs = capsys.readouterr()
    assert capsigs.out == ('1. '
                           'AAAVToiPrZ56VgZDMgYntaGZB2yNjDqWE5vT-sMfiQAsixf2IQV3DhSqLYICJawatox7c01gwttocAnzqEM6wgYI\n'
                           '2. '
                           'ABDGrYs0CHCJ7PajxsV7GX-oFaW9COo4qLoqb6Ar8nq1dnPIqztMQHf37ma7u8gaQHfoD0hDaqzC777XX0T1srgG\n'
                           '3. '
                           'ACCLl9pVv7OM4Y261GZkpPWQu__1mw8ffzcFY1lJ62CGjiEh3mvESu_N7a01YOCKqicqEe5TOXSf0j_8qBxPKxwO\n')

    args = parser.parse_args(["verify", "--name", "test", "--alias", "trans",
                              "--prefix",
                              'EF0bnfg4smFm9Q_OKlKUYRRQctGhTBWUU3rXf7zuA9GU',
                              "--text",
                              "this is test data to sign",
                              "--signature",
                              'AAAVToiPrZ56VgZDMgYntaGZB2yNjDqWE5vT-sMfiQAsixf2IQV3DhSqLYICJawatox7c01gwttocAnzqEM6wgYI'
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
    assert capsigs.out == ('Alias: \ttrans\n'
                           'Identifier: EF0bnfg4smFm9Q_OKlKUYRRQctGhTBWUU3rXf7zuA9GU\n'
                           'Seq No:\t5\n'
                           '\n'
                           'Witnesses:\n'
                           'Count:\t\t0\n'
                           'Receipts:\t0\n'
                           'Threshold:\t0\n'
                           '\n'
                           'Public Keys:\t\n'
                           '\t1. DCaZp7iampWSfsIA2cyZJvWO7CmSkIvXmonu7j3E11Y8\n'
                           '\t2. DE_VNJqg4b_7xP-xVNNg0NmttptGVrkTw7SNKtVSNJJg\n'
                           '\t3. DEMwUl3u8mJ-cWxSnReA0rQesIgZ8SFoHp0U2WyiZjRt\n'
                           '\n')

    args = parser.parse_args(["escrow", "list", "--name", "test"])
    assert args.handler is not None
    doers = args.handler(args)
    directing.runController(doers=doers)
    capesc = capsys.readouterr()
    escrows = ("""{
              "unverified-receipts": 0,
              "verified-receipts": 0,
              "out-of-order-events": [],
              "partially-witnessed-events": [],
              "partially-signed-events": [],
              "likely-duplicitous-events": [],
              "unverified-event-indexed-couples": 0,
              "query-not-found": 0,
              "partially-delegated-events": 0,
              "reply": 0,
              "failed-oobi": 0,
              "group-partial-witness": 0,
              "group-delegate": 0,
              "delegated-partial-witness": 0,
              "group-partial-signed": 0,
              "exchange-partial-signed": 0,
              "delegated-unanchored": 0,
              "tel-out-of-order": 0,
              "tel-partially-witnessed": 0,
              "tel-anchorless": 0,
              "missing-registry-escrow": [],
              "broken-chain-escrow": [],
              "missing-schema-escrow": [],
              "tel-missing-signature": 0,
              "tel-partial-witness-escrow": 0,
              "tel-multisig": 0,
              "tel-event-dissemination": 0,
              "registry-missing-anchor": 0,
              "registry-out-of-order": 0,
              "credential-missing-registry": 0,
              "credential-missing-anchor": 0,
              "credential-out-of-order": 0
            }
        """)
    assert json.loads(capesc.out) == json.loads(escrows)




def test_incept_and_rotate_opts(helpers, capsys):
    """
    Tests using the command line arguments for incept and the file argument for rotate
    """
    helpers.remove_test_dirs("test-opts")
    assert os.path.isdir("/usr/local/var/keri/ks/test-opts") is False

    parser = multicommand.create_parser(commands)
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    args = parser.parse_args(["init", "--name", "test-opts", "--nopasscode", "--salt", salt])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHby("test-opts") as hby:
        assert os.path.isdir(hby.db.path) is True

    args = parser.parse_args(["incept", "--name", "test-opts", "--alias", "trans-args", "--transferable"])
    assert args.handler is not None
    # Attempt to incept without required arg isith
    with pytest.raises(ValueError):
        args.handler(args)

    # Incept with command line arguments
    args = parser.parse_args(["incept", "--name", "test-opts", "--alias", "trans-args", "--transferable",
                              "--isith", "1", "--icount", "1", "--nsith", "1", "--ncount", "1", "--toad", "0"])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    # Rotate with file
    args = parser.parse_args(["rotate", "--name", "test-opts", "--alias", "trans-args",
                              "--file",
                              os.path.join(TEST_DIR, "rotate-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)


# --- kli witness start logging & startup behavior (WebOfTrust/keripy#238) ---

def _parse(argv):
    return multicommand.create_parser(commands).parse_args(argv)


def test_launch_normalizes_loglevel(monkeypatch):
    """launch() must turn a lowercase --loglevel into a numeric level (the .upper()
    fix); without it getLevelName('debug') returns the string 'Level debug', which
    silently breaks level filtering."""
    # ogler is a process-global singleton; snapshot so this test does not leak its
    # level into later tests (monkeypatch restores on teardown).
    monkeypatch.setattr(help.ogler, "level", help.ogler.level)
    monkeypatch.setattr(witness_start, "runWitness", lambda **kw: None)

    args = _parse(["witness", "start", "--alias", "wit", "--loglevel", "debug"])
    args.handler(args)  # -> launch(args)

    assert help.ogler.level == logging.DEBUG


def test_run_failure_is_logged_and_hby_closed(helpers, monkeypatch):
    """A failure during setup/run (e.g. a port-bind error from setupWitness) must be
    logged at CRITICAL (visible at the default --loglevel) AND the Habery closed in
    the finally block, so no stale LMDB lock is left behind."""
    name = "bug238witerr"
    helpers.remove_test_dirs(name)

    logged = []
    monkeypatch.setattr(witness_start.logger, "critical",
                        lambda *a, **k: logged.append((a, k)))

    closed = []
    real_close = habbing.Habery.close

    def spy_close(self, clear=False):
        closed.append(True)
        return real_close(self, clear=clear)
    monkeypatch.setattr(habbing.Habery, "close", spy_close)

    def _boom(**kw):
        raise RuntimeError("cannot create http server on port 5631")
    monkeypatch.setattr(witness_start.indirecting, "setupWitness", _boom)

    try:
        # unencrypted keystore path (aeid is None) so no passcode is required;
        # configFile=None matches what the CLI passes (launch -> args.configFile)
        with pytest.raises(RuntimeError):
            witness_start.runWitness(name=name, base="", alias="wit", bran="", configFile=None)

        assert logged, "startup failure must be logged at CRITICAL"
        assert "failed" in logged[0][0][0]
        assert closed, "Habery must be closed in the finally block on failure"
    finally:
        helpers.remove_test_dirs(name)


def test_encrypted_keystore_non_tty_fails_fast(helpers, monkeypatch):
    """Starting an encrypted keystore with no passcode on a non-TTY must fail fast
    with a logged AuthError instead of stalling on an interactive getpass prompt."""
    name = "bug238witenc"

    # ensure TTY false regardless of how the test harness started
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    # Defensive: getpass must never be called on a non-TTY start
    def _boom(*a, **k):
        raise AssertionError("getpass must not be called on a non-TTY start")
    monkeypatch.setattr("keri.app.cli.common.existing.getpass.getpass", _boom)

    helpers.remove_test_dirs(name)
    try:
        # create an encrypted keystore so that aeid is set
        hby = habbing.Habery(name=name, base="", bran="0123456789abcdefghijk", temp=False)
        hby.close()

        with pytest.raises(AuthError, match="passcode required"):
            witness_start.runWitness(name=name, base="", alias="wit", bran="", configFile=None)
    finally:
        helpers.remove_test_dirs(name)


def test_witness_start_non_tty_wrong_passcode_raises(helpers, monkeypatch):
    """A non-TTY witness start with the wrong passcode must raise rather than
    re-prompting (noPrompt propagates into setupHby)."""
    name = "bug238witwrong"
    correct = "0123456789abcdefghijk"
    wrong = "abcdefghijk0123456789"

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    # launch() sets ogler.level from --loglevel on the shared logger; restore it so a
    # DEBUG level does not leak into later tests.
    saved_level = help.ogler.level
    helpers.remove_test_dirs(name)
    try:
        hby = habbing.Habery(name=name, base="", bran=correct, temp=False)
        hby.close()

        args = _parse(["witness", "start", "--name", name, "--alias", "wit",
                       "--passcode", wrong, "--loglevel", "debug"])
        # noPrompt guard re-raises the original AuthError ("Last seed missing"),
        # not the retry-exhausted "too many attempts" error.
        with pytest.raises(AuthError, match="Last seed missing"):
            args.handler(args)
    finally:
        help.ogler.level = saved_level
        help.ogler.getLogger()  # re-apply restored level to the shared logger
        helpers.remove_test_dirs(name)




