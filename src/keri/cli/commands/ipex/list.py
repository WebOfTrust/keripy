# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""

import argparse
import datetime
import os
import json
import sys

from hio.base import doing
from hio.help import ogler

from ...common import (Parsery, Colors, Symbols,
                       setupHby, aliasInput)

from ....kering import ConfigurationError
from ....app import MailboxDirector, Notifier, Organizer
from ....core import Schemer
from ....help import helping
from ....peer import Exchanger, cloneMessage
from ....vc import loadHandlers, Ipex
from ....vdr import Regery, Verifier


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='List notifications related to IPEX protocol messages',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: listNotes(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    default=None)

parser.add_argument("--verbose", "-V", help="print full JSON of all credentials", action="store_true")
parser.add_argument("--said", "-s", help="display only the SAID of found exn message, one per line.",
                    action="store_true")
parser.add_argument("--type", "-t", help="message type to list, options are (apply, offer, agree, grant, submit)")
parser.add_argument("--poll", "-P", help="Poll mailboxes for any IPEX messages", action="store_true")
parser.add_argument("--sent", help="Show messages sent by a local identifier, default is messages received.",
                    action="store_true")


def listNotes(args):
    """ Command line list credential registries handler

    """
    ld = ListDoer(name=args.name,
                  alias=args.alias,
                  base=args.base,
                  bran=args.bran,
                  poll=args.poll,
                  verbose=args.verbose,
                  said=args.said,
                  typ=args.type,
                  sent=args.sent)
    return [ld]


class ListDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, poll=False, verbose=False, said=False, typ=None, sent=False):
        self.poll = poll
        self.type = typ
        self.verbose = verbose
        self.said = said
        self.sent = sent
        self.notes = []

        self.hby = setupHby(name=name, base=base, bran=bran)
        if alias is None:
            alias = aliasInput(self.hby)

        self.hab = self.hby.habByName(alias)
        self.notifier = Notifier(hby=self.hby)
        self.org = Organizer(hby=self.hby)
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.vry = Verifier(hby=self.hby, reger=self.rgy.reger)
        self.exc = Exchanger(hby=self.hby, handlers=[])
        loadHandlers(self.hby, self.exc, self.notifier)
        self.mbx = MailboxDirector(hby=self.hby, topics=['/replay', '/reply', '/credential'],
                                               exc=self.exc, verifier=self.vry)

        self.doers = [self.mbx]

        super(ListDoer, self).__init__(doers=self.doers + [doing.doify(self.listDo)])

    def listDo(self, tymth, tock=0.0, **kwa):
        """ Check for any credential messages in mailboxes and list all held credentials

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.poll:
            end = helping.nowUTC() + datetime.timedelta(seconds=5)
            if not self.said:
                sys.stdout.write(f"Checking mailboxes for any ipex messages")
            sys.stdout.flush()
            while helping.nowUTC() < end:
                if not self.said:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                if "/credential" in self.mbx.times:
                    end = self.mbx.times['/credential'] + datetime.timedelta(seconds=5)
                yield 1.0
            if not self.said:
                print()

        if not self.said:
            direction = "Sent" if self.sent else "Received"
            print(f"\n{direction} IPEX Messages:")

        self.notes = []

        q = "/exn/ipex"
        if self.type is not None:
            q = f"/exn/ipex/{self.type}"

        for keys, notice in self.notifier.noter.notes.getTopItemIter():
            if notice.pad['a']['r'].startswith(q):
                self.notes.append(notice)

        for note in self.notes:
            attrs = note.attrs
            said = attrs['d']
            exn, pathed = cloneMessage(self.hby, said)
            if exn is None:
                continue

            sender = exn.ked['i']
            if (sender in self.hby.habs and not self.sent) or (sender not in self.hby.habs and self.sent):
                continue

            if self.said:
                print(exn.said)
            else:
                print()
                match exn.ked['r']:
                    case "/ipex/agree":
                        self.agree(note, exn, attrs)
                    case "/ipex/apply":
                        self.apply(note, exn, attrs)
                    case "/ipex/offer":
                        self.offer(note, exn, attrs)
                    case "/ipex/grant":
                        self.grant(exn)
                    case "/ipex/admit":
                        self.admit(note, exn, attrs)
                    case "/ipex/spurn":
                        self.spurn(note, exn, attrs)
                    case _:
                        print("Unknown Type")
                print()

        self.remove(self.doers)

    def grant(self, exn):
        print(f"GRANT - SAID: {exn.said}")
        sad = exn.ked['e']["acdc"]
        iss = exn.ked['e']['iss']

        schema = sad['s']
        scraw = self.mbx.verifier.resolver.resolve(schema)
        if not scraw:
            raise ConfigurationError("Credential schema {} not found".format(schema))

        schemer = Schemer(raw=scraw)
        response = self.hby.db.erpy.get(keys=(exn.said,))

        if response is None:
            accepted = f"No {Colors.FAIL}{Symbols.FAILED}{Colors.ENDC}"
            responseType = None
        else:
            accepted = f"Yes {Colors.OKGREEN}{Symbols.CHECKMARK}{Colors.ENDC}"
            rexn, _ = cloneMessage(self.hby, response.qb64)
            responseType = humanResponse(rexn.ked['r'])

        print(f"Credential {sad['d']}:")
        print(f"    Type: {schemer.sed['title']}")
        print(
            f"    Status: Issued {Colors.OKGREEN}{Symbols.CHECKMARK}{Colors.ENDC}")
        print(f"    Issued by {sad['i']}")
        print(f"    Issued on {iss['dt']}")
        print(f"    Already responded? {accepted}")
        if response is not None:
            print(f"    Response: {responseType} ({response.qb64})")

        if self.verbose:
            bsad = json.dumps(sad, indent=2)
            print("    Full Credential:")
            for line in bsad.splitlines():
                print(f"\t{line}")

    def apply(self, note, exn, pathed):
        pass

    def offer(self, note, exn, pathed):
        pass

    def agree(self, note, exn, pathed):
        pass

    def spurn(self, note, exn, pathed):
        print(f"SPURN - SAID: {exn.said}")
        dig = exn.ked['p']
        spurned, _ = cloneMessage(self.hby, said=dig)

        sroute = spurned.ked['r']
        sverb = os.path.basename(os.path.normpath(sroute))

        print(f"Spurned message type: {sverb.capitalize()}")
        print(f"Spurned message SAID: {spurned.said}")

        if sverb in (Ipex.grant, Ipex.offer):
            sad = spurned.ked['e']["acdc"]

            schema = sad['s']
            scraw = self.mbx.verifier.resolver.resolve(schema)
            if not scraw:
                raise ConfigurationError("Credential schema {} not found".format(schema))

            schemer = Schemer(raw=scraw)
            print(f"Spurned Credential {sad['d']}:")
            print(f"    Type: {schemer.sed['title']}")

    def admit(self, note, exn, pathed):
        print(f"ADMIT - SAID: {exn.said}")
        dig = exn.ked['p']

        admitted, _ = cloneMessage(self.hby, said=dig)
        sad = admitted.ked['e']["acdc"]

        schema = sad['s']
        scraw = self.mbx.verifier.resolver.resolve(schema)
        if not scraw:
            raise ConfigurationError("Credential schema {} not found".format(schema))

        schemer = Schemer(raw=scraw)

        print(f"Admitted message SAID: {admitted.said}")

        print(f"Credential {sad['d']}:")
        print(f"    Type: {schemer.sed['title']}")
        print(f"    Status: Accepted {Colors.OKGREEN}{Symbols.CHECKMARK}{Colors.ENDC}")

    def deleteNote(self, keys):
        yn = input(f"\n Delete the notification [Y|n]?")
        if yn in ('', 'y', 'Y'):
            self.notifier.noter.notes.rem(keys=keys)


def humanResponse(route):
    verb = os.path.basename(os.path.normpath(route))
    match verb:
        case "admit":
            return f"{Colors.OKGREEN}Admit{Colors.ENDC}"
        case "spurn":
            return f"{Colors.FAIL}Spurn{Colors.ENDC}"
    return verb.capitalize()
