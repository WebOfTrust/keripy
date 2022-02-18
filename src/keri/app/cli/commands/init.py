# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import getpass

from hio import help

from keri.app import habbing, configing, directing
from keri.app.cli.common import oobiing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Create a database and keystore')
parser.set_defaults(handler=lambda args: initialize(args),
                    transferable=True)

# Parameters for basic structure of database
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--temp', '-t', help='create a temporary keystore, used for testing', default=False)
parser.add_argument('--salt', '-s', help='qualified base64 salt for creating key pairs', required=False)
parser.add_argument("--config-dir", "-c", dest="configDir", help="directory override for configuration data")
parser.add_argument('--config-file',
                    dest="configFile",
                    action='store',
                    default=None,
                    help="configuration filename override")

# Parameters for Manager creation
# passcode => bran
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--nopasscode', help='create an unencrypted keystore', action='store_true')
parser.add_argument('--aeid', '-a', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                         'and encryption of secrets in keystore', default=None)
parser.add_argument('--seed', '-e', help='qualified base64 private-signing key (seed) for the aeid from which the '
                                         'private decryption key may be derived', default=None)


def initialize(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    if name is None or name == "":
        raise ConfigurationError("Name is required and can not be empty")

    base = args.base
    temp = args.temp
    bran = args.bran
    configFile = args.configFile
    configDir = args.configDir

    if not args.nopasscode and not bran:
        print("Creating encrypted keystore, please enter your 22 character passcode:")
        while True:
            bran = getpass.getpass("Passcode: ")
            retry = getpass.getpass("Re-enter passcode: ")

            if bran != retry:
                print("Passcodes do not match, try again.")
            else:
                break

    kwa = dict()
    kwa["salt"] = args.salt
    kwa["bran"] = bran
    kwa["aeid"] = args.aeid
    kwa["seed"] = args.seed

    cf = None
    if configFile is not None:
        cf = configing.Configer(name=configFile,
                                base=base,
                                headDirPath=configDir,
                                temp=False,
                                reopen=True,
                                clear=False)

    hby = habbing.Habery(name=name, base=base, temp=temp, cf=cf, **kwa)

    print("KERI Keystore created at:", hby.ks.path)
    if hby.mgr.aeid:
        print("\taeid:", hby.mgr.aeid)

    oc = hby.db.oobis.cntAll()
    if oc:
        print("\nLoading OOBIs...")

        obl = oobiing.OobiLoader(db=hby.db, auto=True)
        doers = [obl]
        directing.runController(doers=doers, expire=0.0)


