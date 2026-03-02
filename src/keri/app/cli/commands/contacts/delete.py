# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.delete module

"""
import argparse

from ..... import help
from hio.base import doing

from .... import organizing as connecting
from ...common import existing
from .....kering import ConfigurationError

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Delete a contact')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--aid', '-a', help='contact AID prefix', required=False, default=None)
parser.add_argument('--alias', help='contact alias to lookup', required=False, default=None)
parser.add_argument('--yes', '-y', help='skip confirmation', action='store_true', default=False)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(delete, **kwa)]


def delete(tymth, tock=0.0, **opts):
    """ Command line handler for deleting a contact

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    aid = args.aid
    alias = args.alias
    yes = args.yes

    if aid is None and alias is None:
        print("Either --aid or --alias is required")
        return -1

    try:
        with existing.existingHby(name=name, base=base, bran=bran) as hby:
            org = connecting.Organizer(hby=hby)

            contact = None
            pre = None

            if aid:
                pre = aid
                contact = org.get(aid)
            elif alias:
                contacts = org.find('alias', f"^{alias}$")  # Exact match
                if len(contacts) == 0:
                    print(f"Contact with alias '{alias}' not found")
                    return -1
                if len(contacts) > 1:
                    print(f"Multiple contacts match alias '{alias}'")
                    return -1
                contact = contacts[0]
                pre = contact['id']

            if contact is None:
                print("Contact not found")
                return -1

            alias_display = contact.get('alias', pre)

            if not yes:
                confirm = input(f"Delete contact '{alias_display}' ({pre})? [y/N]: ")
                if confirm.lower() != 'y':
                    print("Aborted")
                    return 0

            org.rem(pre)
            print(f"Deleted contact '{alias_display}' ({pre})")

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first")
        return -1
