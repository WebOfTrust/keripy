# -*- encoding: utf-8 -*-
"""
keri.kli.commands.oobi module

"""
import argparse
import random
import urllib

import sys
from hio.base import doing
from hio.help import ogler

from ....kering import ConfigurationError, Roles, Schemes
from ...common import existingHby, aliasInput


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Generate and print an AID\'s DID.')
parser.set_defaults(handler=lambda args: handler(args))

parser.add_argument('--alias', '-a', help='human readable alias for which to generate a DID', default=None)
parser.add_argument("--role", "-r", help="role of oobis to generate", required=False, default="witness")
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

    with existingHby(name=name, base=base, bran=bran) as hby:
        if alias is None:
            alias = aliasInput(hby)

        hab = hby.habByName(name=alias)
        if not didurl:
            print(f"did:keri:{hab.pre}")

        elif role in (Roles.witness,):
            if not hab.kever.wits:
                print(f"{alias} identifier {hab.pre} does not have any witnesses.")
                sys.exit(-1)

            wit = random.choice(hab.kever.wits)
            urls = hab.fetchUrls(eid=wit, scheme=Schemes.http) \
                or hab.fetchUrls(eid=wit, scheme=Schemes.https)
            if not urls:
                raise ConfigurationError(f"unable to query witness {wit}, no http endpoint")

            url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
            enc = urllib.parse.quote_plus(f"{url.rstrip("/")}/oobi/{hab.pre}/witness")
            print(f"did:keri:{hab.pre}?oobi={enc}")
        elif role in (Roles.controller,):
            urls = hab.fetchUrls(eid=hab.pre, scheme=Schemes.http) \
                   or hab.fetchUrls(eid=hab.pre, scheme=Schemes.https)
            if not urls:
                print(f"{alias} identifier {hab.pre} does not have any controller endpoints")
                return
            url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
            enc = urllib.parse.quote_plus(f"{url.rstrip("/")}/oobi/{hab.pre}/controller")
            print(f"did:keri:{hab.pre}?oobi={enc}")
