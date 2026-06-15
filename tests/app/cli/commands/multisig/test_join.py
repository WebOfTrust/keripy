# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.multisig.test_join module

Focused branch coverage for the KLI multisig join command.
"""
from contextlib import contextmanager

from keri import core
from keri.app import habbing
from keri.app.cli.commands.multisig import join as multisig_join_cmd


def closeHby(hby, clear=True):
    """Helper for explicitly closing resources opened by a Habery"""
    if hby is not None:
        cf = getattr(hby, "cf", None)
        hby.close(clear=clear)
        if clear and cf is not None:
            cf.close(clear=True)


@contextmanager
def openJoinDoer(*args, **kwa):
    """Context manager for closing resources opened by JoinDoer"""
    doer = None
    try:
        doer = multisig_join_cmd.JoinDoer(*args, **kwa)
        yield doer
    finally:
        if doer is not None:
            if getattr(doer, "rgy", None) is not None:
                doer.rgy.reger.close(clear=True)
            if getattr(doer, "notifier", None) is not None:
                doer.notifier.noter.close(clear=True)
            closeHby(getattr(doer, "hby", None))


def test_multisig_join_registry_name_avoids_auto_prompt(monkeypatch):
    """Verifies --registry-name avoids the interactive registry name prompt."""
    args = multisig_join_cmd.parser.parse_args(["--name", "a",
                                                "--group", "g",
                                                "--auto",
                                                "--registry-name", "r1"])
    assert args.registry_name == "r1"

    name = "prompt"
    base = "test-multisig-join-prompt"
    # Create the keystore, close it, then reopen it through JoinDoer.
    salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name=name, base=base, temp=False, clear=True, salt=salt):
        pass

    # Run just enough of the JoinDoer to prove that --registry-name or the prompt act as expected.
    with openJoinDoer(name=name, base=base, bran=None, group="g") as doer:
        doer.registryName = "r1"
        # Monkeypatching just used to prove registryName skips interactive input.
        monkeypatch.setattr("builtins.input",
                            lambda prompt: (_ for _ in ()).throw(AssertionError("unexpected prompt")))
        assert doer._registryName() == "r1"

        doer.registryName = None
        # Monkeypatching just used to provide deterministic interactive CLI input.
        monkeypatch.setattr("builtins.input", lambda prompt: "typed-r1")
        assert doer._registryName() == "typed-r1"
