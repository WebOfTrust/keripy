# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.query module

"""
import argparse
import datetime
import json

from ..... import help
from hio.base import doing

from .... import organizing as connecting, habbing, indirecting, querying
from ...common import existing, displaying
from .....help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Query witnesses for latest key state of a contact')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--alias', '-a', help='alias of your local identifier for querying', required=True)
parser.add_argument('--contact-aid', dest='contact_aid', help='contact AID prefix to query',
                    required=False, default=None)
parser.add_argument('--contact-alias', dest='contact_alias', help='contact alias to lookup',
                    required=False, default=None)


def handler(args):
    """ command line method for querying contact key state from witnesses

    Parameters:
        args(Namespace): parse args namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    contact_aid = args.contact_aid
    contact_alias = args.contact_alias

    if contact_aid is None and contact_alias is None:
        print("Either --contact-aid or --contact-alias is required")
        return []

    queryDoer = ContactQueryDoer(name=name, base=base, bran=bran, alias=alias,
                                 contact_aid=contact_aid, contact_alias=contact_alias)
    return [queryDoer]


class ContactQueryDoer(doing.DoDoer):
    """ DoDoer for querying contact key state from witnesses """

    def __init__(self, name, base, bran, alias, contact_aid, contact_alias):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)
        self.alias = alias
        self.contact_aid = contact_aid
        self.contact_alias = contact_alias

        self.mbd = indirecting.MailboxDirector(hby=self.hby, topics=["/replay", "/receipt", "/reply"])

        doers = [self.hbyDoer, self.mbd, doing.doify(self.queryDo)]
        super(ContactQueryDoer, self).__init__(doers=doers)

    def queryDo(self, tymth, tock=0.0):
        """ Query witnesses for contact key state

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(self.alias)
        if hab is None:
            print(f"Local identifier '{self.alias}' not found")
            self.remove([self.hbyDoer, self.mbd])
            return

        org = connecting.Organizer(hby=self.hby)

        pre = None
        if self.contact_aid:
            pre = self.contact_aid
            contact = org.get(pre)
        elif self.contact_alias:
            contacts = org.find('alias', f"^{self.contact_alias}$")
            if len(contacts) == 0:
                print(f"Contact with alias '{self.contact_alias}' not found")
                self.remove([self.hbyDoer, self.mbd])
                return
            if len(contacts) > 1:
                print(f"Multiple contacts match alias '{self.contact_alias}'")
                self.remove([self.hbyDoer, self.mbd])
                return
            contact = contacts[0]
            pre = contact['id']

        if pre is None:
            print("Contact not found")
            self.remove([self.hbyDoer, self.mbd])
            return

        doer = querying.QueryDoer(hby=self.hby, hab=hab, pre=pre, kvy=self.mbd.kvy)
        self.extend([doer])

        end = helping.nowUTC() + datetime.timedelta(seconds=10)
        while helping.nowUTC() < end:
            if doer.done:
                break
            yield 1.0

        self.remove([doer])

        displaying.printExternal(self.hby, pre)

        contact = org.get(pre)
        if contact:
            print(json.dumps(contact, indent=2))

        self.remove([self.hbyDoer, self.mbd])
