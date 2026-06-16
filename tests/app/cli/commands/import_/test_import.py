# -*- encoding: utf-8 -*-
"""
tests.app.cli.commands.import_.test_import module
"""
import multicommand
import pytest

from keri.app.cli import commands


def test_public_import_command_is_discoverable():
    # Purpose: root `kli import` uses the _index.py keyword wrapper and must stay public.
    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["import", "--name", "test", "--cesr-in", "-"])
    assert args.handler is not None
    assert args.cesr_in == "-"
    assert args.transferable is True


def test_public_import_command_rejects_removed_hints():
    # Purpose: root `kli import` should not expose group/alias hints; registry names come from imported state.
    parser = multicommand.create_parser(commands)
    with pytest.raises(SystemExit):
        parser.parse_args(["import", "--name", "test", "--group", "multisig"])
    with pytest.raises(SystemExit):
        parser.parse_args(["import", "--name", "test", "--alias", "multisig"])
