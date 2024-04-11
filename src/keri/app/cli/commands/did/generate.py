# -*- encoding: utf-8 -*-
"""
keri.kli.commands.oobi module

"""
import argparse
import random
import urllib
from urllib.parse import urlparse

import sys
from hio import help
from hio.base import doing

from keri import kering
from keri.app.cli.common import existing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Generate and print an AID\'s DID.')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)

# Parameters for basic structure of database
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for which to generate a DID', default=None)
parser.add_argument("--role", "-r", help="role of oobis to generate", required=False, default="witness")

# Parameters for Manager access
# passcode => bran
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--url', '-u', help="generate a DID URL instead of a DID", action="store_true")


def handler(args):
    """ command line method for generating oobies

    Parameters:
        args(Namespace): parse args namespace object

    """
    kwa = dict(args=args)
    return [doing.doify(generate, **kwa)]


def generate(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    alias = args.alias
    base = args.base
    bran = args.bran
    role = args.role
    didurl = args.url

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        if alias is None:
            alias = existing.aliasInput(hby)

        hab = hby.habByName(name=alias)
        if not didurl:
            print(f"did:keri:{hab.pre}")

        elif role in (kering.Roles.witness,):
            if not hab.kever.wits:
                print(f"{alias} identifier {hab.pre} does not have any witnesses.")
                sys.exit(-1)

            wit = random.choice(hab.kever.wits)
            urls = hab.fetchUrls(eid=wit, scheme=kering.Schemes.http) or hab.fetchUrls(eid=wit, scheme=kering.Schemes.https)
            if not urls:
                raise kering.ConfigurationError(f"unable to query witness {wit}, no http endpoint")

            url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
            up = urlparse(url)
            enc = urllib.parse.quote_plus(f"{up.scheme}://{up.hostname}:{up.port}/oobi/{hab.pre}/witness")
            print(f"did:keri:{hab.pre}?oobi={enc}")
        elif role in (kering.Roles.controller,):
            urls = hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.http) or hab.fetchUrls(eid=hab.pre, scheme=kering.Schemes.https)
            if not urls:
                print(f"{alias} identifier {hab.pre} does not have any controller endpoints")
                return
            url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
            up = urlparse(url)
            enc = urllib.parse.quote_plus(f"{up.scheme}://{up.hostname}:{up.port}/oobi/{hab.pre}/controller")
            print(f"did:keri:{hab.pre}?oobi={enc}")
