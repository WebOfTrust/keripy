# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from hio import help
from hio.base import doing

from keri.app.cli.common import existing
from keri.kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Export keys of specified identifier for use with SSH')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--private", help="export private key instead of public key", action="store_true")
parser.add_argument("--username", help="override file name for the key to export", default=None)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(export, **kwa)]


def export(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran
    private = args.private
    filename = args.username if args.username else alias
    home = str(Path.home())

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            if alias is None:
                alias = existing.aliasInput(hby)

            hab = hby.habByName(alias)
            if private:
                signer = hab.ks.pris.get(hab.kever.verfers[0].qb64,
                                         decrypter=hab.mgr.decrypter)
                sigkey = ed25519.Ed25519PrivateKey.from_private_bytes(signer.raw)
                pem = sigkey.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.OpenSSH,
                                           encryption_algorithm=serialization.NoEncryption())

                f = open(os.path.join(home, ".ssh", filename), "w")
                for line in pem.splitlines(keepends=True):
                    f.write(line.decode("utf-8"))
                f.close()
                os.chmod(os.path.join(home, ".ssh", filename), stat.S_IRUSR | stat.S_IWUSR)

            else:
                verkey = ed25519.Ed25519PublicKey.from_public_bytes(hab.kever.verfers[0].raw)
                pem = verkey.public_bytes(encoding=serialization.Encoding.OpenSSH,
                                          format=serialization.PublicFormat.OpenSSH)

                f = open(os.path.join(home, ".ssh", f"{filename}.pub"), "w")
                for line in pem.splitlines(keepends=True):
                    f.write(line.decode("utf-8"))


    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
