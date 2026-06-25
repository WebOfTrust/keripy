# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.multisig.test_join module
"""
from contextlib import contextmanager

import multicommand

from keri import core
from keri.app import habbing
from keri.app.cli import commands
from keri.app.cli.commands.multisig import join as multisig_join_cmd


TMP_BASE_PATH = "base-multisig-join"


def isolatedBase(tmp_path):
    """Return a relative KERI base namespace unique to each pytest test."""
    return f"{TMP_BASE_PATH}-{tmp_path.parent.name}-{tmp_path.name}"


def closeHby(hby, clear=True):
    """Close Habery and its Configer."""
    if hby is not None:
        cf = getattr(hby, "cf", None)
        hby.close(clear=clear)
        if clear and cf is not None:
            cf.close(clear=True)


def closeJoinDoer(doer, clear=True):
    """Close resources opened by JoinDoer."""
    if getattr(doer, "rgy", None) is not None:
        doer.rgy.reger.close(clear=clear)
    if getattr(doer, "notifier", None) is not None:
        doer.notifier.noter.close(clear=clear)
    closeHby(getattr(doer, "hby", None), clear=clear)


@contextmanager
def openJoinDoers(args):
    """Open JoinDoer through command handler and close its resources."""
    doers = args.handler(args)
    try:
        yield doers
    finally:
        for doer in doers:
            closeJoinDoer(doer)


def test_multisig_join_registry_name_avoids_auto_prompt(tmp_path, monkeypatch):
    name = "prompt"
    base = isolatedBase(tmp_path)
    salt = core.Salter(raw=b'0123456789abcdef').qb64

    with habbing.openHby(name=name, base=base, temp=False, clear=True, salt=salt):
        pass

    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["multisig", "join",
                              "--name", name,
                              "--base", base,
                              "--group", "g",
                              "--auto",
                              "--registry-name", "r1"])

    with openJoinDoers(args) as doers:
        doer = doers[0]
        assert isinstance(doer, multisig_join_cmd.JoinDoer)
        assert doer.registryName == "r1"

        # Monkeypatching just used to prove registryName skips interactive input.
        monkeypatch.setattr("builtins.input",
                            lambda prompt: (_ for _ in ()).throw(AssertionError("unexpected prompt")))
        assert doer._registryName() == "r1"

        doer.registryName = None
        # Monkeypatching just used to provide deterministic interactive CLI input.
        monkeypatch.setattr("builtins.input", lambda prompt: "typed-r1")
        assert doer._registryName() == "typed-r1"
