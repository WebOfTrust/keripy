# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.rename module

"""
import argparse

from hio.base import doing

from ..... import help
from .... import organizing as connecting
from ...common import existing
from .....kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Rename a contact alias')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aid', '-a', help='contact AID prefix', required=False, default=None)
parser.add_argument('--old-alias', dest='old_alias', help='current alias to lookup', required=False, default=None)
parser.add_argument('--alias', help='new alias to set', required=True)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(rename, **kwa)]


def rename(tymth, tock=0.0, **opts):
    """ Command line handler for renaming a contact alias

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    aid = args.aid
    old_alias = args.old_alias
    new_alias = args.alias

    if aid is None and old_alias is None:
        print("Either --aid or --old-alias is required")
        return -1

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)

            contact = None
            pre = None

            if aid:
                pre = aid
                contact = org.get(aid)
            elif old_alias:
                contacts = org.find('alias', f"^{old_alias}$")  # Exact match
                if len(contacts) == 0:
                    print(f"Contact with alias '{old_alias}' not found")
                    return -1
                if len(contacts) > 1:
                    print(f"Multiple contacts match alias '{old_alias}'")
                    return -1
                contact = contacts[0]
                pre = contact['id']

            if contact is None:
                print("Contact not found")
                return -1

            old_alias_display = contact.get('alias', '<none>')
            org.set(pre, 'alias', new_alias)
            print(f"Renamed contact {pre} from '{old_alias_display}' to '{new_alias}'")

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        return -1
