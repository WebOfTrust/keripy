# -*- encoding: utf-8 -*-
"""
keri.kli.common.passcode.set module

"""
import argparse
import getpass

from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.core import coring
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: set_passcode(args),
                    transferable=True)
parser.add_argument("--new", help="new  22 character encryption passcode for keystore", required=False, default=None)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='existing 22 character encryption passcode for keystore',
                    dest="bran", default=None)  # passcode => bran


def handler(args):
    """ Command line status handler

    """
    kwa = dict(args=args)
    return [doing.doify(set_passcode, **kwa)]


def set_passcode(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    newpasscode = args.new

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:

            if newpasscode is None:
                print("Re-encrypting keystore, please enter the new 22 character passcode:")
                while True:
                    newpasscode = getpass.getpass("New passcode: ")
                    retry = getpass.getpass("Re-enter new passcode: ")

                    if newpasscode != retry:
                        print("Passcodes do not match, try again.")
                    else:
                        break

            bran = coring.MtrDex.Salt_128 + newpasscode[:22]  # qb64 salt for seed
            signer = coring.Salter(qb64=bran).signer(transferable=False,
                                                     temp=False)
            seed = signer.qb64
            aeid = signer.verfer.qb64

            hby.mgr.updateAeid(aeid, seed)
            print("Passcode reset and keystore re-encrypted.")

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
