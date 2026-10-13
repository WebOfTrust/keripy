import os
import importlib

import pytest

from hio.base import doing
from hio.help import decking

from keri.app import openHby, runController
from keri.core import Parser, SerderKERI
from keri.kering import Roles, Version, Vrsn_1_0, Vrsn_2_0


# imported with import_module since the name add resolves to the identically named function "add" in the same module.
mailbox_add = importlib.import_module("keri.cli.commands.mailbox.add")


@pytest.mark.parametrize("version", [None, Vrsn_1_0, Vrsn_2_0], ids=["default", "v1", "v2"])
@pytest.mark.parametrize("delegated", [False, True], ids=["direct", "delegated"])
def test_mailbox_add_posts_multipart_fields(monkeypatch, capsys, helpers, version, delegated):
    """`kli mailbox add` keeps the existing multipart admin envelope.

    The command should only stub the outbound HTTP transport seam.  The rest of
    the test intentionally exercises the real local habitat logic so the posted
    `rpy` still reflects current KERIpy reply construction.
    """
    effective = version if version is not None else Version
    name = f"test-mailbox-add-{os.urandom(4).hex()}"
    requests = []

    # Capture the outbound multipart request without needing a live mailbox
    # server, so the test can assert the exact admin envelope the CLI builds.
    class ClientStub:
        def __init__(self):
            self.responses = decking.Deck()
            self.requester = type("Requester", (), {"path": "/"})()

        def request(self, **kwargs):
            requests.append(kwargs)
            self.responses.append(type("Rep", (), {
                "status": 200,
                "data": "",
                "body": "",
            })())

        def respond(self):
            return self.responses.popleft()

    # Satisfy the command's witness publication dependency with an in-memory
    # doer so the controller run loop can advance without network side effects.
    class WitnessPublisherStub(doing.DoDoer):
        def __init__(self, **kwargs):
            self.msgs = decking.Deck()
            self.cues = decking.Deck()
            super().__init__(doers=[doing.doify(self.publishDo)])

        def publishDo(self, tymth=None, tock=0.0, **kwa):
            self.wind(tymth)
            self.tock = tock
            _ = (yield self.tock)

            while True:
                while self.msgs:
                    self.cues.append(self.msgs.popleft())
                    yield self.tock
                yield self.tock

    def stub_http_client(hab, wit):
        return ClientStub(), doing.DoDoer(doers=[])

    monkeypatch.setattr(mailbox_add, "httpClient", stub_http_client)
    monkeypatch.setattr(mailbox_add, "WitnessPublisher", WitnessPublisherStub)

    with openHby(name=name, temp=True, version=effective) as hby:
        # Reuse the already-open temp Habery so the test does not touch the
        # persistent `~/.keri` tree.
        def setup_habery(**kwargs):
            """Keep the real fixture open while asserting the CLI carries its version."""
            assert kwargs["version"] == version
            return hby

        monkeypatch.setattr(mailbox_add, "setupHby", setup_habery)
        delegator = hby.makeHab(name="delegator", version=effective) if delegated else None
        alice = hby.makeHab(name="alice", transferable=True, version=effective,
                            delpre=delegator.pre if delegator else None)
        if delegator:
            # Seal the delegated inception before the CLI gathers its evidence.
            delegator.interact(data=[dict(i=alice.pre, s="0", d=alice.pre)], version=effective)
            for msg in delegator.db.clonePreIter(pre=delegator.pre, gvrsn=effective):
                alice.psr.parse(ims=msg)
        mailbox = hby.makeHab(name="mbx", transferable=False, version=effective)
        alice_pre = alice.pre
        mailbox_pre = mailbox.pre
        argv = [
            "--name",
            name,
            "--alias",
            "alice",
            "--mailbox",
            mailbox_pre,
        ]
        if version is not None:
            argv.extend(["--version", f"{version.major}.{version.minor}"])
        args = mailbox_add.parser.parse_args(argv)
        doers = args.handler(args)

        runController(doers=doers)

        assert len(requests) == 1
        request = requests[0]
        assert request["method"] == "POST"
        assert request["path"] == "/mailboxes"
        assert request["headers"]["Content-Type"] == "multipart/form-data"
        assert "fargs" in request
        assert request["fargs"]["kel"]
        assert request["fargs"]["rpy"]
        assert "Content-Disposition" not in request["fargs"]["kel"]
        assert request["fargs"]["rpy"].startswith('{"v":"')
        serder = SerderKERI(raw=request["fargs"]["rpy"].encode("utf-8"))
        assert serder.pvrsn == effective
        # Parse the exact multipart wire, not just its JSON prefix: the reply and
        # replay attachment counters must agree with the selected ingress genus.
        frames = Parser(version=effective).parse(
            ims=bytearray((request["fargs"]["kel"] + request["fargs"]["rpy"]).encode()),
            framed=True, processive=False,
        )
        # Habitat replay includes delegator events before a delegated controller.
        expected = [delegator.pre, delegator.pre, alice_pre] if delegator else [alice_pre]
        assert [frame.serder.pre for frame in frames[:-1]] == expected
        assert all(frame.sigers for frame in frames[:-1])
        assert frames[-1].serder.said == serder.said
        assert frames[-1].tsgs
        if delegator:
            ancestors = Parser(version=effective).parse(
                ims=bytearray(request["fargs"]["delkel"].encode()), framed=True, processive=False,
            )
            assert [frame.serder.pre for frame in ancestors] == [delegator.pre, delegator.pre]
            assert all(frame.sigers for frame in ancestors)
        else:
            assert "delkel" not in request["fargs"]
        # The accepted role publication uses the same genus as admission.
        published = doers[0].witpub.cues[0]["msg"]
        replies = Parser(version=effective).parse(ims=bytearray(published),
                                                  framed=True, processive=False)
        assert any(frame.serder.said == serder.said for frame in replies)
        assert serder.ked["r"] == "/end/role/add"
        assert serder.ked["a"] == {
            "cid": alice_pre,
            "role": Roles.mailbox,
            "eid": mailbox_pre,
        }

        out = capsys.readouterr().out
        assert f"Mailbox {mailbox_pre} added for alice" in out

    helpers.remove_test_dirs(name)


def test_mailbox_add_posts_relative_to_stored_mailbox_url_path(monkeypatch, capsys, helpers):
    """`kli mailbox add` appends `mailboxes` relative to the stored mailbox URL path."""
    name = f"test-mailbox-add-path-{os.urandom(4).hex()}"
    requests = []

    class ClientStub:
        def __init__(self):
            self.responses = decking.Deck()
            self.requester = type("Requester", (), {"path": "/relay/admin"})()

        def request(self, **kwargs):
            requests.append(kwargs)
            self.responses.append(type("Rep", (), {
                "status": 200,
                "data": "",
                "body": "",
            })())

        def respond(self):
            return self.responses.popleft()

    class WitnessPublisherStub(doing.DoDoer):
        def __init__(self, **kwargs):
            self.msgs = decking.Deck()
            self.cues = decking.Deck()
            super().__init__(doers=[doing.doify(self.publishDo)])

        def publishDo(self, tymth=None, tock=0.0, **kwa):
            self.wind(tymth)
            self.tock = tock
            _ = (yield self.tock)

            while True:
                while self.msgs:
                    self.cues.append(self.msgs.popleft())
                    yield self.tock
                yield self.tock

    def stub_http_client(hab, wit):
        return ClientStub(), doing.DoDoer(doers=[])

    monkeypatch.setattr(mailbox_add, "httpClient", stub_http_client)
    monkeypatch.setattr(mailbox_add, "WitnessPublisher", WitnessPublisherStub)

    with openHby(name=name, temp=True) as hby:
        monkeypatch.setattr(mailbox_add, "setupHby", lambda **kwargs: hby)
        alice = hby.makeHab(name="alice", transferable=True)
        mailbox = hby.makeHab(name="mbx", transferable=False)
        args = mailbox_add.parser.parse_args([
            "--name",
            name,
            "--alias",
            "alice",
            "--mailbox",
            mailbox.pre,
        ])

        runController(doers=args.handler(args))

        assert len(requests) == 1
        assert requests[0]["path"] == "/relay/admin/mailboxes"

        out = capsys.readouterr().out
        assert f"Mailbox {mailbox.pre} added for alice" in out

    helpers.remove_test_dirs(name)
