# -*- encoding: utf-8 -*-
"""
tests.app.cli.test_dnd_cli module

Tests that the Do-Not-Delegate config trait is reachable from `kli incept` and visible to a
delegator in `kli delegate confirm`.

DND is the delegator's only control over how far a delegation chain may extend, and a delegator
exercises it by refusing to anchor an inception event that lacks it (KERI spec-body.md:379). Both
halves of that were missing: the trait could not be set from `kli incept` at all, and the approval
prompt did not show the delegate's config traits, so the refusal could not be made on an informed
basis.
"""

import os

import multicommand

from keri.app import runController
from keri.cli import commands
from keri.cli.commands import incept as incept_command
from keri.cli.commands.delegate import confirm as confirm_command
from keri.cli.common import existingHab
from keri.core import Salter
from keri.kering import Ilks, TraitDex

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_incept_dnd_flag_reaches_options():
    """--dnd survives the merge of command line args with an options file."""
    parser = multicommand.create_parser(commands)

    args = parser.parse_args(["incept", "--name", "test", "--alias", "bounded", "--transferable",
                              "--icount", "1", "--ncount", "1", "--isith", "1", "--nsith", "1",
                              "--toad", "0", "--dnd"])
    assert incept_command.mergeArgsWithFile(args).DnD is True

    # Absent means absent, not None: makeHab takes it as a keyword with a False default.
    args = parser.parse_args(["incept", "--name", "test", "--alias", "unbounded", "--transferable",
                              "--icount", "1", "--ncount", "1", "--isith", "1", "--nsith", "1",
                              "--toad", "0"])
    assert incept_command.mergeArgsWithFile(args).DnD is False


def test_incept_dnd_from_options_file():
    """A DnD key in an options file reaches the same place the flag does."""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["incept", "--name", "test", "--alias", "bounded", "--transferable",
                              "--file", os.path.join(TEST_DIR, "dnd-sample.json")])
    assert incept_command.mergeArgsWithFile(args).DnD is True


def test_incept_dnd_lands_in_key_state(helpers):
    """The incepted AID refuses to act as a delegator, which is what the trait is for."""
    helpers.remove_test_dirs("test-dnd")
    parser = multicommand.create_parser(commands)
    salt = Salter(raw=b'0123456789abcdef').qb64

    args = parser.parse_args(["init", "--name", "test-dnd", "--nopasscode", "--salt", salt])
    runController(doers=args.handler(args))

    args = parser.parse_args(["incept", "--name", "test-dnd", "--alias", "bounded", "--transferable",
                              "--file", os.path.join(TEST_DIR, "dnd-sample.json")])
    runController(doers=args.handler(args))

    with existingHab(name="test-dnd", alias="bounded") as (hby, hab):
        assert hab.kever.doNotDelegate is True
        assert TraitDex.DoNotDelegate in hab.kever.serder.ked["c"]

    args = parser.parse_args(["incept", "--name", "test-dnd", "--alias", "unbounded", "--transferable",
                              "--file", os.path.join(TEST_DIR, "transferable-sample.json")])
    runController(doers=args.handler(args))

    with existingHab(name="test-dnd", alias="unbounded") as (hby, hab):
        assert hab.kever.doNotDelegate is False


def test_confirm_reports_config_traits():
    """The approval prompt names every trait in the event, recognized or not.

    Kever keeps only EO and DND out of `c` and drops the rest, so a summary built from Kever
    attributes would hide exactly the traits a delegator most needs to see before anchoring.
    This reads the event.
    """
    ked = dict(t=Ilks.dip, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk", c=[])
    lines = confirm_command.traitSummary(ked)
    assert "Establishment Only: False" in lines
    assert "Do Not Delegate: False" in lines

    ked["c"] = [TraitDex.DoNotDelegate]
    lines = confirm_command.traitSummary(ked)
    assert "Do Not Delegate: True" in lines
    assert "Establishment Only: False" in lines

    ked["c"] = [TraitDex.EstOnly, TraitDex.DoNotDelegate]
    lines = confirm_command.traitSummary(ked)
    assert "Establishment Only: True" in lines
    assert "Do Not Delegate: True" in lines


def test_confirm_reports_traits_keripy_does_not_parse():
    """An unrecognized trait is shown rather than silently dropped.

    DID is defined in TraitCodex and read nowhere in src/, so a delegator anchoring a dip that
    carries it would otherwise have no way to see it.
    """
    ked = dict(t=Ilks.dip, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk",
               c=[TraitDex.DelegateIsDelegator])
    lines = confirm_command.traitSummary(ked)
    assert TraitDex.DelegateIsDelegator in lines
    assert "Do Not Delegate: False" in lines


def test_confirm_missing_config_field_is_not_an_error():
    """A rotation event has no `c` field at all."""
    ked = dict(t=Ilks.drt, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk")
    lines = confirm_command.traitSummary(ked)
    assert "Do Not Delegate: False" in lines


def _bareConfirmDoer(requireDnD=True):
    """A ConfirmDoer with no Habery behind it.

    ConfirmDoer.__init__ builds a Habery, a mailbox director and five other doers, none of
    which the decline decision touches. Constructing it without them keeps this a test of
    the decision rather than of the wiring.
    """
    doer = confirm_command.ConfirmDoer.__new__(confirm_command.ConfirmDoer)
    doer.requireDnD = requireDnD
    doer.declined = set()
    return doer


def test_confirm_declines_delegated_inception_without_dnd(capsys):
    """--require-dnd refuses a delegate that would be free to delegate onward."""
    doer = _bareConfirmDoer()
    ked = dict(t=Ilks.dip, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk", c=[])

    assert doer.declineForDnD(ked, "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV") is True
    assert "require-dnd" in capsys.readouterr().out

    ked["c"] = [TraitDex.DoNotDelegate]
    assert doer.declineForDnD(ked, "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG") is False
    assert capsys.readouterr().out == ""


def test_confirm_announces_each_decline_once(capsys):
    """The refusal does not spin the console while the request sits in escrow.

    confirmDo polls the delegation escrow on every tock, and declining leaves the entry
    where it is, so announcing on each pass would print forever. The interactive path is
    immune because it blocks on input(), and --auto is immune because it always approves;
    --require-dnd is the only path that neither blocks nor resolves.
    """
    doer = _bareConfirmDoer()
    ked = dict(t=Ilks.dip, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk", c=[])
    said = "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV"

    assert doer.declineForDnD(ked, said) is True
    assert capsys.readouterr().out != ""

    for _ in range(5):  # stands in for repeated polls of the same escrowed request
        assert doer.declineForDnD(ked, said) is True
    assert capsys.readouterr().out == ""

    # A different request still gets announced.
    assert doer.declineForDnD(ked, "EGyJ7y3TlewCW97dgBN-4pckhCqsni-zHNZ_G8zVerPG") is True
    assert "require-dnd" in capsys.readouterr().out


def test_confirm_does_not_require_dnd_of_a_rotation(capsys):
    """Config traits are inception only, so a delegated rotation carries none to require."""
    doer = _bareConfirmDoer()
    ked = dict(t=Ilks.drt, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk")

    assert doer.declineForDnD(ked, "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV") is False
    assert capsys.readouterr().out == ""


def test_confirm_without_require_dnd_declines_nothing(capsys):
    """Absent the flag, a dip with no DND is left for the operator to judge."""
    doer = _bareConfirmDoer(requireDnD=False)
    ked = dict(t=Ilks.dip, i="EBcIURLpxmVwahksgrsGW6_dUw0zBhyEHYFk17eWrZfk", c=[])

    assert doer.declineForDnD(ked, "EEaJrM-0HPs4hATSqSpvotRBAjKuJO6ri5Uh7KBoLYbV") is False
    assert capsys.readouterr().out == ""


def test_confirm_require_dnd_flag_parses():
    """--require-dnd lets a delegator refuse an unbounded delegate without reading the prompt.

    Without it, --auto approves every request blind, which is the same rubber stamp the prompt
    was hiding.
    """
    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["delegate", "confirm", "--name", "test", "--alias", "delegator",
                              "--require-dnd"])
    assert args.require_dnd is True

    args = parser.parse_args(["delegate", "confirm", "--name", "test", "--alias", "delegator"])
    assert args.require_dnd is False
