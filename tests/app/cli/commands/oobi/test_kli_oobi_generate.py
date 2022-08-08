import os
import secrets

from keri.app import directing, habbing
from keri.app.cli import commands

import multicommand

from keri.app.cli.common import existing

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def test_standalone_kli_commands(helpers, capsys):
    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False
    base = secrets.token_hex(8)

    parser = multicommand.create_parser(commands)
    args = parser.parse_args(["init", "--name", "test", "--nopasscode", "--salt", habbing.SALT, "--base", base,
                              "--config-dir", TEST_DIR, "--config-file", "test"])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    with existing.existingHby("test", base=base) as hby:
        assert os.path.isdir(hby.db.path) is True

    args = parser.parse_args(["incept", "--name", "test", "--alias", "non-trans", "--base", base, "--file",
                              os.path.join(TEST_DIR, "non-transferable-sample.json"), "--config", TEST_DIR])
    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    # Create non-transferable identifier
    with existing.existingHab(name="test", base=base, alias="non-trans") as (hby, hab):
        assert hab.pre == "BjzVSYRS7pWuKLbo_FBqDB2RYnMmbdDo8RG1TDVz_L0o"

    capsys.readouterr()
    args = parser.parse_args(["oobi", "generate", "--name", "test", "--alias", "non-trans", "--base", base,
                              "--role", "controller"])

    assert args.handler is not None
    doers = args.handler(args)

    directing.runController(doers=doers)

    capsigs = capsys.readouterr()
    assert capsigs.out == 'http://189.64.128.90:5642/oobi/BjzVSYRS7pWuKLbo_FBqDB2RYnMmbdDo8RG1TDVz_L0o/controller\n'

    helpers.remove_test_dirs("test")
    assert os.path.isdir("/usr/local/var/keri/ks/test") is False
