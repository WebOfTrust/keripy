# -*- encoding: utf-8 -*-
"""
keri.kli.commands.oobi module

"""
import argparse

import sys
from hio.base import doing
from hio.help import ogler

from ...common import Parsery, existingHby, aliasInput

from ....kering import ConfigurationError, Roles, Schemes


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Generate and print role OOBIs for the AID of the provide alias.',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', default=None)
parser.add_argument("--role", "-r", help="role of oobis to generate", required=True)



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

    with existingHby(name=name, base=base, bran=bran) as hby:
        if alias is None:
            alias = aliasInput(hby)

        hab = hby.habByName(name=alias)
        if role in (Roles.witness,):
            if not hab.kever.wits:
                print(f"{alias} identifier {hab.pre} does not have any witnesses.")
                sys.exit(-1)

            for wit in hab.kever.wits:
                urls = hab.fetchUrls(eid=wit, scheme=Schemes.http) \
                       or hab.fetchUrls(eid=wit, scheme=Schemes.https)
                if not urls:
                    raise ConfigurationError(f"unable to query witness {wit}, no http endpoint")

                url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
                print(f"{url.rstrip("/")}/oobi/{hab.pre}/witness")
        elif role in (Roles.controller,):
            urls = hab.fetchUrls(eid=hab.pre, scheme=Schemes.http) \
                   or hab.fetchUrls(eid=hab.pre, scheme=Schemes.https)
            if not urls:
                print(f"{alias} identifier {hab.pre} does not have any controller endpoints")
                return
            url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
            print(f"{url.rstrip("/")}/oobi/{hab.pre}/controller")
        elif role in (Roles.mailbox,):
            for (_, _, eid), end in hab.db.ends.getTopItemIter(keys=(hab.pre, Roles.mailbox, )):
                if not (end.allowed and end.enabled is not False):
                    continue

                urls = hab.fetchUrls(eid=eid, scheme=Schemes.http) or hab.fetchUrls(eid=eid,
                                                                                           scheme=Schemes.https)
                if not urls:
                    print(f"{alias} identifier {hab.pre} does not have any mailbox endpoints")
                    return
                url = urls[Schemes.https] if Schemes.https in urls else urls[Schemes.http]
                print(f"{url.rstrip("/")}/oobi/{hab.pre}/mailbox/{eid}")
