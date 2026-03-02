# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands.contacts.add module

"""
import argparse
import json

from ..... import help
from hio.base import doing

from .... import oobiing
from .... import organizing as connecting, habbing, oobiing
from ...common import existing
from .....db import basing
from .....help import helping

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Add a contact via OOBI resolution')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--oobi', '-o', help='OOBI URL to resolve for contact', required=True)
parser.add_argument('--alias', help='alias to set for contact', required=False, default=None)
parser.add_argument('--field', '-f', help='field in key=value format', action='append', dest='fields', default=None)


def handler(args):
    """ command line method for adding a contact via OOBI resolution

    Parameters:
        args(Namespace): parse args namespace object

    """
    name = args.name
    base = args.base
    bran = args.bran
    oobi = args.oobi
    alias = args.alias
    fields = args.fields

    addDoer = ContactAddDoer(name=name, base=base, bran=bran,
                             oobi=oobi, alias=alias, fields=fields)
    return [addDoer]


class ContactAddDoer(doing.DoDoer):
    """ DoDoer for adding a contact via OOBI resolution """

    def __init__(self, name, base, bran, oobi, alias, fields):
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)
        self.oobi = oobi
        self.alias = alias
        self.fields = fields

        doers = [self.hbyDoer, doing.doify(self.add)]
        super(ContactAddDoer, self).__init__(doers=doers)

    def add(self, tymth, tock=0.0):
        """ Resolves OOBI and creates contact

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        obr = basing.OobiRecord(date=helping.nowIso8601())
        if self.alias:
            obr.oobialias = self.alias

        self.hby.db.oobis.put(keys=(self.oobi,), val=obr)

        obi = oobiing.Oobiery(hby=self.hby)
        authn = oobiing.Authenticator(hby=self.hby)
        self.extend(obi.doers)
        self.extend(authn.doers)

        # Wait for resolution
        while not self.hby.db.roobi.get(keys=(self.oobi,)):
            yield 0.25

        resolved = self.hby.db.roobi.get(keys=(self.oobi,))
        cid = resolved.cid

        org = connecting.Organizer(hby=self.hby)

        data = {}
        if self.alias:
            data['alias'] = self.alias

        if self.fields:
            for field in self.fields:
                if '=' not in field:
                    print(f"Invalid field format: {field}. Use key=value")
                    self.remove([self.hbyDoer, *obi.doers, *authn.doers])
                    return
                key, val = field.split('=', 1)
                data[key] = val

        org.update(cid, data)

        contact = org.get(cid)
        print(json.dumps(contact, indent=2))

        self.remove([self.hbyDoer, *obi.doers, *authn.doers])
