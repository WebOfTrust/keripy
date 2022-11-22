# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import getpass

from hio import help
from hio.base import doing

import keri.app.oobiing
from keri.app import habbing, configing, oobiing, connecting
from keri.app.keeping import Algos
from keri.kering import ConfigurationError
from keri.vdr import credentialing

logger = help.ogler.getLogger()


def handler(args):
    """
    Launch KERI database initialization

    Args:
        args(Namespace): arguments object from command line
    """
    init = InitDoer(args)
    return [init]


parser = argparse.ArgumentParser(description='Create a database and keystore')
parser.set_defaults(handler=handler,
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


class InitDoer(doing.DoDoer):

    def __init__(self, args):
        self.args = args
        super(InitDoer, self).__init__(doers=[doing.doify(self.initialize)])

    def initialize(self, tymth, tock=0.0):

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        args = self.args
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
        if args.salt is None:
            kwa["algo"] = Algos.randy

        cf = None
        if configFile is not None:
            cf = configing.Configer(name=configFile,
                                    base="",
                                    headDirPath=configDir,
                                    temp=False,
                                    reopen=True,
                                    clear=False)

        hby = habbing.Habery(name=name, base=base, temp=temp, cf=cf, **kwa)
        rgy = credentialing.Regery(hby=hby, name=name, base=base, temp=temp)

        print("KERI Keystore created at:", hby.ks.path)
        print("KERI Database created at:", hby.db.path)
        print("KERI Credential Store created at:", rgy.reger.path)
        if hby.mgr.aeid:
            print("\taeid:", hby.mgr.aeid)

        oc = hby.db.oobis.cntAll()
        if oc:
            print(f"\nLoading {oc} OOBIs...")

            obi = keri.app.oobiing.Oobiery(hby=hby)
            self.extend(obi.doers)

            while oc > hby.db.roobi.cntAll():
                yield 0.25

            for (oobi,), obr in hby.db.roobi.getItemIter():
                if obr.state in (oobiing.Result.resolved,):
                    print(oobi, "succeeded")
                if obr in (oobiing.Result.failed,):
                    print(oobi, "failed")

            self.remove(obi.doers)

        wc = [oobi for (oobi,), _ in hby.db.woobi.getItemIter()]
        if len(wc) > 0:
            print(f"\nAuthenticating Well-Knowns...")
            authn = oobiing.Authenticator(hby=hby)
            self.extend(authn.doers)

            while True:
                cap = []
                for (_,), wk in hby.db.wkas.getItemIter(keys=b''):
                    cap.append(wk.url)

                if set(wc) & set(cap) == set(wc):
                    break

                yield 0.5

            self.remove(authn.doers)

        hby.close()
