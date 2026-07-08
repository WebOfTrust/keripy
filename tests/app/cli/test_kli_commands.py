import logging
import os
from collections import deque
from types import SimpleNamespace
import multicommand
import pytest


from hio.help import ogler

from keri.kering import Ilks, Kinds, ValidationError, Vrsn_1_0, AuthError
from keri.core import Salter

from keri.app import runController, habbing
from keri.cli.commands.witness import start as witness_start
from keri.cli.commands import init as init_command
from keri.cli.commands.delegate import request as delegate_request_command
from keri.cli.commands.multisig import continue_ as multisig_continue_command

from keri.cli import commands
from keri.cli.common import existingHab, existingHby


TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_standalone_kli_commands(helpers, capsys):
    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False

    parser = multicommand.create_parser(commands)
    salt = Salter(raw=b'0123456789abcdef').qb64
    args = parser.parse_args(["init", "--name", "test", "--nopasscode", "--salt", salt])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)

    with existingHby("test") as hby:
        assert os.path.isdir(hby.db.path) is True

    args = parser.parse_args(["incept", "--name", "test", "--alias", "non-trans", "--file",
                              os.path.join(TEST_DIR, "non-transferable-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)

    # Create non-transferable identifier
    with existingHab(name="test", alias="non-trans") as (hby, hab):
        assert hab.pre == 'BI81UmEUu6Vrii26PxQagwdkWJzJm3Q6PERtUw1c_y9K'

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "non-trans"])
    assert args.handler is not None
    doers = args.handler(args)

    # Attempt to rotate a non-transferable identifier
    with pytest.raises(ValueError):
        runController(doers=doers)

    # Create transferable identifier
    args = parser.parse_args(["incept", "--name", "test", "--alias", "trans", "--transferable", "--file",
                              os.path.join(TEST_DIR, "transferable-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)

    xpre = 'EF0bnfg4smFm9Q_OKlKUYRRQctGhTBWUU3rXf7zuA9GU'  # 'EORLw1VyVyBqNCHMUTYctinMDCba9o6Ut-34YFpiLBFK'
    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans"])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)
    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 1

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "trans", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)
    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 2
        assert hab.kever.ilk == Ilks.rot
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

    runController(doers=doers)
    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 3
        assert hab.kever.ilk == Ilks.ixn
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

    runController(doers=doers)

    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 4
        assert hab.kever.ilk == Ilks.rot
        assert hab.kever.tholder.sith == "1"

    args = parser.parse_args(rotate_args)
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)

    with existingHab(name="test", alias="trans") as (hby, hab):
        assert hab.pre == xpre
        assert hab.kever.sn == 5
        assert hab.kever.ilk == Ilks.rot
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

    runController(doers=doers)

    epre = 'EMZ09JgN6Kr_rZH4Q7SovW-bxYXjiQX2XdSIQYpZnHsJ'
    with existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == epre
        assert hab.kever.sn == 0

    args = parser.parse_args(["interact", "--name", "test", "--alias", "est-only", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)

    with pytest.raises(ValidationError):
        runController(doers=doers)

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "est-only"])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)
    with existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == epre
        assert hab.kever.sn == 1
        assert hab.kever.ilk == Ilks.rot

    args = parser.parse_args(["rotate", "--name", "test", "--alias", "est-only", "--data",
                              "@" + os.path.join(TEST_DIR, "anchor.json")])
    assert args.handler is not None
    doers = args.handler(args)
    runController(doers=doers)
    with existingHab(name="test", alias="est-only") as (hby, hab):
        assert hab.pre == epre
        assert hab.kever.sn == 2
        assert hab.kever.ilk == Ilks.rot
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
    runController(doers=doers)

    #"ErzV_sZ8iC-mKOFN7dknxnXSISU3hvlUZr7TMcJs7JsY"

    capsigs = capsys.readouterr()
    assert capsigs.out == ('1. '
                           'AAAVToiPrZ56VgZDMgYntaGZB2yNjDqWE5vT-sMfiQAsixf2IQV3DhSqLYICJawatox7c01gwttocAnzqEM6wgYI\n'
                           '2. '
                           'ABDGrYs0CHCJ7PajxsV7GX-oFaW9COo4qLoqb6Ar8nq1dnPIqztMQHf37ma7u8gaQHfoD0hDaqzC777XX0T1srgG\n'
                           '3. '
                           'ACCLl9pVv7OM4Y261GZkpPWQu__1mw8ffzcFY1lJ62CGjiEh3mvESu_N7a01YOCKqicqEe5TOXSf0j_8qBxPKxwO\n')

    args = parser.parse_args(["verify", "--name", "test",
                              "--prefix",
                              'EF0bnfg4smFm9Q_OKlKUYRRQctGhTBWUU3rXf7zuA9GU',
                              "--text",
                              "this is test data to sign",
                              "--signature",
                              'AAAVToiPrZ56VgZDMgYntaGZB2yNjDqWE5vT-sMfiQAsixf2IQV3DhSqLYICJawatox7c01gwttocAnzqEM6wgYI'
                              ])
    assert args.handler is not None
    doers = args.handler(args)
    runController(doers=doers)

    capsigs = capsys.readouterr()
    assert capsigs.out == 'Signature 1 is valid.\n'

    args = parser.parse_args(["status", "--name", "test", "--alias", "trans"])
    assert args.handler is not None
    doers = args.handler(args)
    runController(doers=doers)
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


    """
    src/keri/cli/commands/escrow/list.py

    def escrows(tymth, tock=0.0, **opts):
    _ = yield tock

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    escrow = args.escrow

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            reger = Reger(name=hby.name, db=hby.db, temp=False)


    Calls:

    keri/db/dbing.py  LMDBer.reopen()

    self.env = lmdb.open(self.path, max_dbs=self.MaxNamedDBs, map_size=self.MapSize,
                      mode=self.perm, readonly=self.readonly)

    Raises:

    lmdb.Error: The environment '/usr/local/var/keri/reg/test' is already open in this process.

    From the LMDB docs:
    It is a serious error to have open the same LMDB file in the same process
    at the same time. Failure to heed this may lead to data corruption and interpreter crash.

    This was not tightly checked in LMDB < 2.0

    Changelog for LMDB 2.0.0

    - **Duplicate environment path rejection (#230).** Opening the same LMDB path
    twice in one process now raises lmdb.Error instead of silently proceeding
    to a likely segfault. This will surface latent bugs in code that
    accidentally opened the same environment twice.

    This test by design intentionally violates this constraint on LMDB. Therefore
    it needs to be rewritten.


    """
    #args = parser.parse_args(["escrow", "list", "--name", "test"])
    #assert args.handler is not None
    #doers = args.handler(args)
    #directing.runController(doers=doers)
    #capesc = capsys.readouterr()
    #result = json.loads(capesc.out)
    #assert result["out-of-order-events"] == []
    #assert result["partially-witnessed-events"] == []
    #assert result["partially-signed-events"] == []
    #assert result["likely-duplicitous-events"] == []
    #assert result["partially-delegated-events"] == []
    #assert result["query-not-found"] == []
    #assert result["misfits"] == []
    #assert result["missing-registry-escrow"] == []
    #assert result["broken-chain-escrow"] == []
    #assert result["missing-schema-escrow"] == []
    #assert result["tel-partial-witness-escrow"] == []
    #assert result["group-partially-signed-events"] == []
    #assert result["group-delegated-events"] == []
    #assert result["group-partially-witnessed-events"] == []
    #assert result["escrowed-partially-signed-exchange"] == []
    #assert result["escrowed-exchange-datetime"] == []
    #assert result["delegated-partially-witnessed-events"] == []
    #assert result["delegated-unverified-events"] == []
    #assert result["delegated-partially-unduplicated-backer"] == []
    #assert result["reply-escrow"] == []
    #assert result["delegable-events"] == {"count": 0}
    #assert result["unverified-delegated-events"] == {"count": 0}
    #assert result["escrowed-oobi"] == {"count": 0}
    #assert result["unverified-receipt-escrow"] == {"count": 0}
    #assert result["unverified-witness-escrow"] == {"count": 0}
    #assert result["unverified-transferable-receipt-escrow"] == {"count": 0}


def test_incept_and_rotate_opts(helpers, capsys):
    """
    Tests using the command line arguments for incept and the file argument for rotate
    """
    helpers.remove_test_dirs("test-opts")
    assert os.path.isdir("/usr/local/var/keri/ks/test-opts") is False

    parser = multicommand.create_parser(commands)
    salt = Salter(raw=b'0123456789abcdef').qb64
    args = parser.parse_args(["init", "--name", "test-opts", "--nopasscode", "--salt", salt])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)

    with existingHby("test-opts") as hby:
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

    runController(doers=doers)

    # Rotate with file
    args = parser.parse_args(["rotate", "--name", "test-opts", "--alias", "trans-args",
                              "--file",
                              os.path.join(TEST_DIR, "rotate-sample.json")])
    assert args.handler is not None
    doers = args.handler(args)

    runController(doers=doers)


def test_init_passes_explicit_version_to_habery_and_oobiery(monkeypatch):
    captured = {}

    class FakeTable:
        def __init__(self, count=0, items=()):
            self._count = count
            self._items = list(items)

        def cnt(self):
            return self._count

        def getTopItemIter(self, keys=b''):
            return iter(self._items)

    class FakeHabery:
        def __init__(self, *args, version=None, **kwargs):
            captured["habery_version"] = version
            self.ks = SimpleNamespace(path="/tmp/fake-ks")
            self.db = SimpleNamespace(
                path="/tmp/fake-db",
                oobis=FakeTable(count=1),
                roobi=FakeTable(count=1, items=[
                    (("http://127.0.0.1:5642/oobi/fake/controller",),
                     SimpleNamespace(state=init_command.Result.resolved))
                ]),
                woobi=FakeTable(),
                wkas=FakeTable(),
            )
            self.mgr = SimpleNamespace(aeid=None)

        def close(self):
            captured["closed"] = True

    class FakeRegery:
        def __init__(self, *args, **kwargs):
            self.reger = SimpleNamespace(path="/tmp/fake-reg")

    class FakeOobiery:
        def __init__(self, hby, version=None):
            captured["oobiery_version"] = version
            self.doers = []

    monkeypatch.setattr(init_command, "Habery", FakeHabery)
    monkeypatch.setattr(init_command, "Regery", FakeRegery)
    monkeypatch.setattr(init_command, "Oobiery", FakeOobiery)

    parser = multicommand.create_parser(commands)
    salt = Salter(raw=b"0123456789abcdef").qb64
    args = parser.parse_args([
        "init",
        "--name", "test-init-version",
        "--nopasscode",
        "--salt", salt,
        "--version", "1.0",
    ])

    runController(doers=args.handler(args))

    assert captured["habery_version"] == Vrsn_1_0
    assert captured["oobiery_version"] == Vrsn_1_0
    assert captured["closed"] is True


def test_delegate_request_passes_explicit_version_to_counselor_delegate_request_exn_and_forwarding(monkeypatch):
    captured = {}

    class FakeGroupHab:
        def __init__(self):
            self.pre = "group-pre"
            self.kever = SimpleNamespace(delpre="delegator-pre")
            self.mhab = SimpleNamespace(pre="member-pre")
            self.smids = ["member-pre"]

        def msgOwnEvent(self, sn):
            captured["event_sn"] = sn
            return bytearray(b"fake-event")

    class FakeHabery:
        def __init__(self):
            self.hab = FakeGroupHab()
            self.db = SimpleNamespace(
                gdee=SimpleNamespace(get=lambda keys: [(SimpleNamespace(sn=3), SimpleNamespace())]),
            )

        def habByName(self, alias):
            if alias == "group":
                return self.hab
            return None

    class FakeHaberyDoer:
        def __init__(self, habery):
            self.habery = habery

    class FakeWitnessInquisitor:
        def __init__(self, hby):
            self.hby = hby

    class FakePoster:
        def __init__(self, hby, version=None, kind=None):
            captured["poster_version"] = version
            captured["poster_kind"] = kind
            self.cues = deque()

        def send(self, **kwa):
            captured.setdefault("postman_sends", []).append(kwa)
            said = getattr(kwa["serder"], "said", None)
            if said is not None:
                self.cues.append(dict(said=said))

    class FakeCounselor:
        def __init__(self, hby, version=None, kind=None):
            captured["counselor_version"] = version
            captured["counselor_kind"] = kind

    class FakeSerderKERI:
        def __init__(self, raw):
            self.size = 0
            self.said = "event-said"

    def fake_delegate_request_exn(hab, delpre, evt, aids, version=None, kind=None):
        captured["delegate_request"] = dict(hab=hab, delpre=delpre, evt=evt, aids=aids,
                                            version=version, kind=kind)
        return SimpleNamespace(said="exn-said"), b"fake-atc"

    monkeypatch.setattr(delegate_request_command, "setupHby", lambda **kwa: FakeHabery())
    monkeypatch.setattr(delegate_request_command, "HaberyDoer", FakeHaberyDoer)
    monkeypatch.setattr(delegate_request_command, "WitnessInquisitor", FakeWitnessInquisitor)
    monkeypatch.setattr(delegate_request_command, "Poster", FakePoster)
    monkeypatch.setattr(delegate_request_command, "Counselor", FakeCounselor)
    monkeypatch.setattr(delegate_request_command, "SerderKERI", FakeSerderKERI)
    monkeypatch.setattr(delegate_request_command, "delegateRequestExn", fake_delegate_request_exn)
    monkeypatch.setattr(delegate_request_command, "GroupHab", FakeGroupHab)

    args = delegate_request_command.parser.parse_args([
        "--name", "test-request-version",
        "--alias", "group",
        "--version", "1.0",
    ])
    doer = delegate_request_command.request(args)[0]
    doer.remove = lambda doers: None

    dog = doer.requestDo(lambda: 0.0)
    next(dog)
    next(dog)
    with pytest.raises(StopIteration):
        next(dog)

    assert captured["poster_version"] == Vrsn_1_0
    assert captured["poster_kind"] == Kinds.json
    assert captured["counselor_version"] == Vrsn_1_0
    assert captured["counselor_kind"] == Kinds.json
    assert captured["delegate_request"]["version"] == Vrsn_1_0
    assert captured["delegate_request"]["kind"] == Kinds.json
    assert captured["delegate_request"]["aids"] == ["member-pre"]
    assert [send["dest"] for send in captured["postman_sends"]] == ["delegator-pre", "delegator-pre"]


def test_multisig_continue_passes_explicit_version_to_counselor_mailbox_and_query(monkeypatch):
    captured = {}

    class FakeHab:
        def __init__(self):
            self.pre = "multisig-pre"
            self.kever = SimpleNamespace(delpre="delegator-pre")

    class FakeHabery:
        def __init__(self):
            self.hab = FakeHab()
            self.db = SimpleNamespace(
                gdee=SimpleNamespace(get=lambda keys: [(SimpleNamespace(numh="7", qb64="7"),
                                                       SimpleNamespace(qb64="dig"))]),
                cgms=SimpleNamespace(get=lambda keys: "complete"),
            )

        def habByName(self, alias):
            if alias == "group":
                return self.hab
            return None

    class FakeCounselor:
        def __init__(self, hby, version=None, kind=None):
            captured["counselor_version"] = version
            captured["counselor_kind"] = kind

    class FakeWitnessInquisitor:
        def __init__(self, hby):
            self.hby = hby

        def query(self, **kwa):
            captured["query"] = kwa

    class FakeMailboxDirector:
        def __init__(self, hby, topics, **kwa):
            captured["mailbox_topics"] = topics
            captured["mailbox_kwargs"] = kwa

    monkeypatch.setattr(multisig_continue_command, "setupHby", lambda **kwa: FakeHabery())
    monkeypatch.setattr(multisig_continue_command, "Counselor", FakeCounselor)
    monkeypatch.setattr(multisig_continue_command, "WitnessInquisitor", FakeWitnessInquisitor)
    monkeypatch.setattr(multisig_continue_command, "MailboxDirector", FakeMailboxDirector)
    monkeypatch.setattr(multisig_continue_command, "printIdentifier",
                        lambda hby, pre: captured.setdefault("printed", []).append(pre))

    args = multisig_continue_command.parser.parse_args([
        "--name", "test-continue-version",
        "--alias", "group",
        "--version", "1.0",
    ])
    doer = multisig_continue_command.handler(args)[0]
    doer.remove = lambda doers: None

    dog = doer.recover(lambda: 0.0)
    next(dog)
    with pytest.raises(StopIteration):
        next(dog)

    assert captured["counselor_version"] == Vrsn_1_0
    assert captured["counselor_kind"] == Kinds.json
    assert captured["mailbox_kwargs"] == dict(version=Vrsn_1_0, gvrsn=Vrsn_1_0, kind=Kinds.json)
    assert captured["query"] == dict(src="multisig-pre",
                                     pre="delegator-pre",
                                     anchor=dict(i="multisig-pre", s="7", d="dig"),
                                     version=Vrsn_1_0,
                                     gvrsn=Vrsn_1_0,
                                     kind=Kinds.json)
    assert captured["printed"] == ["multisig-pre"]


def test_run_witness_closes_boot_keeper_before_reopen(monkeypatch):
    """Regression: runWitness must close the boot Keeper before Habery re-opens
    the same keystore, otherwise LMDB raises 'LMDB Environment is already open'
    on Linux.  See WebOfTrust/keripy#1367.
    """
    close_called = False
    original_init = witness_start.Keeper.__init__

    class SpyKeeper(witness_start.Keeper):
        def __init__(self, *args, **kwargs):
            original_init(self, *args, **kwargs)

        def close(self, clear=False):
            nonlocal close_called
            close_called = True
            super().close(clear=clear)

    stopped = False

    def fake_run(doers, expire=0.0):
        nonlocal stopped
        stopped = True

    monkeypatch.setattr(witness_start, 'Keeper', SpyKeeper)
    monkeypatch.setattr(witness_start, 'runController', fake_run)
    monkeypatch.setattr(witness_start, 'setupWitness', lambda **kw: [])

    witness_start.runWitness(name='test-spy-keeper', base='', bran='0123456789abcdefghijk',
                             tcp=5631, http=5632, expire=0.0)

    assert close_called, "Keeper.close() was never called before Habery re-open"
    assert stopped, "runController was never reached"


# --- kli witness start logging & startup behavior (WebOfTrust/keripy#238) ---

def _parse(argv):
    return multicommand.create_parser(commands).parse_args(argv)


def test_witness_start_arg_parsing():
    """--logdir is the current option; --logfile is retained as a deprecated alias."""
    args = _parse(["witness", "start", "--alias", "wit",
                   "--loglevel", "debug", "--logdir", "/tmp/wlogs"])
    assert args.handler is not None
    assert args.loglevel == "debug"
    assert args.logdir == "/tmp/wlogs"
    assert args.logfile is None

    args = _parse(["witness", "start", "--alias", "wit"])
    assert args.loglevel == "CRITICAL"
    assert args.logdir is None
    assert args.logfile is None


def test_launch_normalizes_loglevel_and_logdir(monkeypatch, tmp_path):
    """launch() must turn a lowercase --loglevel into a numeric level (the .upper()
    fix) and route --logdir straight to ogler.headDirPath."""
    # ogler is a process-global singleton; snapshot so this test does not leak
    # its level/headDirPath into later tests (monkeypatch restores on teardown).
    monkeypatch.setattr(ogler, "level", ogler.level)
    monkeypatch.setattr(ogler, "headDirPath", ogler.headDirPath)

    captured = {}
    monkeypatch.setattr(witness_start, "runWitness", lambda **kw: captured.update(kw))

    args = _parse(["witness", "start", "--alias", "wit",
                   "--loglevel", "debug", "--logdir", str(tmp_path)])
    args.handler(args)  # -> launch(args)

    # Without .upper(), getLevelName("debug") returns the string "Level debug",
    # which silently breaks level filtering. It must be the numeric DEBUG level.
    assert ogler.level == logging.DEBUG
    assert ogler.headDirPath == str(tmp_path)
    assert captured["alias"] == "wit"


def test_launch_logfile_extracts_dirname(monkeypatch, tmp_path):
    """The deprecated --logfile must contribute only its *directory* as the log
    dir (hio derives the filename from --name), never the file path itself."""
    monkeypatch.setattr(ogler, "level", ogler.level)
    monkeypatch.setattr(ogler, "headDirPath", ogler.headDirPath)
    monkeypatch.setattr(witness_start, "runWitness", lambda **kw: None)

    logfile = tmp_path / "witness.log"
    args = _parse(["witness", "start", "--alias", "wit", "--logfile", str(logfile)])
    args.handler(args)

    assert ogler.headDirPath == str(tmp_path)


def test_logfile_emits_deprecation_warning(monkeypatch, capsys, tmp_path):
    """Passing the deprecated --logfile must print a deprecation notice to stderr
    (visible regardless of --loglevel); using the current --logdir must not."""
    monkeypatch.setattr(ogler, "level", ogler.level)
    monkeypatch.setattr(ogler, "headDirPath", ogler.headDirPath)
    monkeypatch.setattr(witness_start, "runWitness", lambda **kw: None)

    args = _parse(["witness", "start", "--alias", "wit",
                   "--logfile", str(tmp_path / "witness.log")])
    args.handler(args)
    assert "deprecated" in capsys.readouterr().err, "expected a --logfile deprecation notice"

    args = _parse(["witness", "start", "--alias", "wit", "--logdir", str(tmp_path)])
    args.handler(args)
    assert "deprecated" not in capsys.readouterr().err


def test_run_failure_is_logged_and_hby_closed(helpers, monkeypatch):
    """A failure during setup/run (e.g. a port-bind RuntimeError from setupWitness)
    must be logged at CRITICAL (visible at the default --loglevel) AND the Habery
    closed in the finally block, so no stale LMDB lock is left behind."""
    name = "bug238witerr"
    helpers.remove_test_dirs(name)

    # set up CRITICAL logger so we can assert its contents
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
    monkeypatch.setattr(witness_start, "setupWitness", _boom)

    try:
        # unencrypted keystore path (aeid is None) so no passcode is required
        with pytest.raises(RuntimeError):
            witness_start.runWitness(name=name, base="", alias="wit", bran="")

        assert logged, "startup failure must be logged at CRITICAL"
        assert "failed" in logged[0][0][0]
        assert closed, "Habery must be closed in the finally block on failure"
    finally:
        helpers.remove_test_dirs(name)


def test_encrypted_keystore_non_tty_fails_fast(helpers, monkeypatch):
    """Starting encrypted keystore with no passcode on a non-TTY must fail fast with no prompt"""
    name = "bug238witenc"

    # ensure TTY false regardless of test harness start (sometimes IDE starts set TTY=True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    # Defensive raise on getpass, testing that we never call it for this test since no TTY
    def _boom(*a, **k):
        raise AssertionError("getpass must not be called on a non-TTY start")
    monkeypatch.setattr("keri.cli.common.existing.getpass.getpass", _boom)

    helpers.remove_test_dirs(name)
    try:
        # create an encrypted keystore so that aeid is set
        hby = habbing.Habery(name=name, base="", bran="0123456789abcdefghijk", temp=False)
        hby.close()

        with pytest.raises(AuthError, match="passcode required"):
            witness_start.runWitness(name=name, base="", alias="wit", bran="")
    finally:
        helpers.remove_test_dirs(name)


def test_witness_start_non_tty_wrong_passcode_raises(helpers, monkeypatch):
    """When starting a witness with no TTY and with wrong passcode, should err."""
    name = "bug238witwrong"
    correct = "0123456789abcdefghijk"
    wrong = "thisisasecretpasscode"

    # ensure TTY false regardless of test harness start (sometimes IDE starts set TTY=True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    helpers.remove_test_dirs(name)
    try:
        # Create keystore with correct passcode to later trigger noPrompt + wrong passcode err
        hby = habbing.Habery(name=name, base="", bran=correct, temp=False)
        hby.close()

        args = _parse(["witness", "start", "--name", name, "--alias", "wit",
                       "--passcode", wrong,
                       "--loglevel", "debug", "--logdir", "/tmp/wlogs"])
        with pytest.raises(AuthError, match="Last seed missing"):
            args.handler(args)
    finally:
        helpers.remove_test_dirs(name)

