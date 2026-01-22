import os

import pytest

from hio.base import doing

from keri.app import habbing, directing
from keri.app.cli.commands.exn import send as send_cmd


def patch_poster(monkeypatch):
    calls = []
    cues = []

    class PosterStub(doing.DoDoer):
        def __init__(self, **kwargs):
            self.cues = cues
            super().__init__(doers=[])

        def send(self, *, src, dest, topic, serder, attachment):
            calls.append(
                {
                    "src": src,
                    "dest": dest,
                    "topic": topic,
                    "serder": serder,
                    "attachment": bytes(attachment),
                }
            )
            cues.append({"dest": dest, "topic": topic, "said": serder.said})

    monkeypatch.setattr(send_cmd.forwarding, "Poster", PosterStub)
    return calls, cues


def test_exn_send_with_json_obj(monkeypatch, capsys, helpers):
    calls, cues = patch_poster(monkeypatch)

    name = f"test-exn-send-{os.urandom(4).hex()}"

    with habbing.openHby(name=name, temp=False) as hby:
        alice = hby.makeHab(name="alice")
        bob = hby.makeHab(name="bob")
        alice_pre = alice.pre
        bob_pre = bob.pre

    args = send_cmd.parser.parse_args(
        [
            "--name",
            name,
            "--sender",
            "alice",
            "--recipient",
            bob_pre,
            "--route",
            "/challenge/response",
            "--data",
            '{"words":["red","blue"]}',
        ]
    )
    assert args.handler is not None

    doers = args.handler(args)
    assert len(doers) == 1

    try:
        directing.runController(doers=doers)

        assert len(calls) == 1
        call = calls[0]
        assert call["src"] == alice_pre
        assert call["dest"] == bob_pre
        assert call["topic"] == "challenge"
        assert call["serder"].ked["r"] == "/challenge/response"
        assert call["serder"].ked["a"] == {"words": ["red", "blue"]}

        assert len(cues) == 1
        assert cues[0]["said"] == call["serder"].said

        out = capsys.readouterr().out
        assert "Sent EXN message" in out
    finally:
        helpers.remove_test_dirs(name)


def test_exn_send_with_data_items(monkeypatch, capsys, helpers):
    calls, cues = patch_poster(monkeypatch)

    name = f"test-exn-send-{os.urandom(4).hex()}"

    with habbing.openHby(name=name, temp=False) as hby:
        alice = hby.makeHab(name="alice")
        bob = hby.makeHab(name="bob")
        alice_pre = alice.pre
        bob_pre = bob.pre

    args = send_cmd.parser.parse_args(
        [
            "--name",
            name,
            "--sender",
            "alice",
            "--recipient",
            bob_pre,
            "--route",
            "/challenge/response",
            "--data",
            'words=["red","blue"]',
            "--data",
            "number=42",
        ]
    )
    assert args.handler is not None

    doers = args.handler(args)
    assert len(doers) == 1

    try:
        directing.runController(doers=doers)

        assert len(calls) == 1
        call = calls[0]
        assert call["src"] == alice_pre
        assert call["dest"] == bob_pre
        assert call["topic"] == "challenge"
        assert call["serder"].ked["r"] == "/challenge/response"
        assert call["serder"].ked["a"] == {"words": ["red", "blue"], "number": 42}

        assert len(cues) == 1
        assert cues[0]["said"] == call["serder"].said

        out = capsys.readouterr().out
        assert "Sent EXN message" in out
    finally:
        helpers.remove_test_dirs(name)


def test_exn_send_invalid_sender(monkeypatch, helpers):
    patch_poster(monkeypatch)

    name = f"test-exn-send-{os.urandom(4).hex()}"

    with habbing.openHby(name=name, temp=False) as hby:
        bob = hby.makeHab(name="bob")
        bob_pre = bob.pre

    args = send_cmd.parser.parse_args(
        [
            "--name",
            name,
            "--sender",
            "alice",  # Alice does not exist
            "--recipient",
            bob_pre,
            "--route",
            "/challenge/response",
            "--data",
            'words=["red","blue"]',
        ]
    )
    assert args.handler is not None

    doers = args.handler(args)
    assert len(doers) == 1

    try:
        with pytest.raises(ValueError, match="invalid sender alias"):
            directing.runController(doers=doers)
    finally:
        helpers.remove_test_dirs(name)


def test_exn_send_invalid_recipient(monkeypatch, capsys, helpers):
    patch_poster(monkeypatch)

    name = f"test-exn-send-{os.urandom(4).hex()}"

    with habbing.openHby(name=name, temp=False) as hby:
        hby.makeHab(name="alice")

    args = send_cmd.parser.parse_args(
        [
            "--name",
            name,
            "--sender",
            "alice",
            "--recipient",
            "invalid_recipient",  # Invalid recipient
            "--route",
            "/challenge/response",
            "--data",
            'words=["red","blue"]',
        ]
    )
    assert args.handler is not None

    doers = args.handler(args)
    assert len(doers) == 1

    try:
        with pytest.raises(ValueError, match="invalid recipient"):
            directing.runController(doers=doers)
    finally:
        helpers.remove_test_dirs(name)
