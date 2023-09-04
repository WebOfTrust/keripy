# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime
import sys

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting, notifying
from keri.app.cli.common import existing, terming
from keri.core import scheming, parsing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import protocoling, proving
from keri.vdr import credentialing, verifying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Accept any newly issued credentials')
parser.set_defaults(handler=lambda args: accept(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print full JSON of all credentials", action="store_true")
parser.add_argument("--said", "-s", help="display only the SAID of found credentials, one per line.",
                    action="store_true")
parser.add_argument("--auto", "-Y", help="auto accept any issued credentials non-interactively", action="store_true")
parser.add_argument("--poll", "-P", help="Poll mailboxes for any issued credentials", action="store_true")


def accept(args):
    """ Command line list credential registries handler

    """
    ld = AcceptDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    poll=args.poll,
                    verbose=args.verbose,
                    auto=args.auto,
                    said=args.said)
    return [ld]


class AcceptDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, poll=False, verbose=False, auto=False, said=False):
        self.poll = poll
        self.verbose = verbose
        self.auto = auto
        self.said = said

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        if alias is None:
            alias = existing.aliasInput(self.hby)

        self.hab = self.hby.habByName(alias)
        self.notifier = notifying.Notifier(hby=self.hby)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        issueHandler = protocoling.IssueHandler(hby=self.hby, rgy=self.rgy, notifier=self.notifier)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[issueHandler])
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/credential'], exc=self.exc, verifier=self.vry)

        self.doers = [self.mbx, self.exc]

        super(AcceptDoer, self).__init__(doers=self.doers + [doing.doify(self.acceptDo)])

    def acceptDo(self, tymth, tock=0.0):
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
            sys.stdout.write(f"Checking mailboxes for any issued credentials")
            sys.stdout.flush()
            while helping.nowUTC() < end:
                sys.stdout.write(".")
                sys.stdout.flush()
                if "/credential" in self.mbx.times:
                    end = self.mbx.times['/credential'] + datetime.timedelta(seconds=5)
                yield 1.0
            print("\n")

        for keys, notice in self.notifier.noter.notes.getItemIter():
            attrs = notice.attrs
            route = attrs['r']

            if route == '/credential/issue':
                print("Credential issuance received:")
                said = attrs['d']
                exn, pathed = exchanging.cloneMessage(self.hby, said)
                sad = exn.ked['e']["acdc"]
                iss = exn.ked['e']['iss']

                schema = sad['s']
                scraw = self.mbx.verifier.resolver.resolve(schema)
                if not scraw:
                    raise kering.ConfigurationError("Credential schema {} not found".format(schema))

                schemer = scheming.Schemer(raw=scraw)
                creder = self.rgy.reger.creds.get(keys=(sad['d'],))
                if creder is None:
                    accepted = f"No {terming.Colors.FAIL}{terming.Symbols.FAILED}{terming.Colors.ENDC}"
                else:
                    accepted = f"Yes {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}"
                print(f"Credential {sad['d']}:")
                print(f"    Type: {schemer.sed['title']}")
                print(
                    f"    Status: Issued {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}")
                print(f"    Issued by {sad['i']}")
                print(f"    Issued on {iss['dt']}")
                print(f"    Already accepted? {accepted}")

                if creder is not None:
                    self.deleteNote(keys=keys)
                    continue

                creder = proving.Creder(ked=sad)

                if self.auto:
                    print("Auto accepting credential...")
                    yes = True
                else:
                    yn = input(f"\nAccept [Y|n]? ")
                    yes = yn in ('', 'y', 'Y')

                if yes:
                    ims = bytearray(creder.raw) + pathed["acdc"]
                    parsing.Parser(vry=self.vry).parse(ims=ims)

                    while not self.rgy.reger.creds.get(keys=creder.saidb):
                        yield self.tock

                    print(f"{creder.said} Accepted {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}"
                          f"{terming.Colors.ENDC}")

                self.deleteNote(keys=keys)

            yield self.tock

        self.remove(self.doers)

    def deleteNote(self, keys):
        if self.auto:
            print("\nAuto deleting notification.")
            self.notifier.noter.notes.rem(keys=keys)
        else:
            yn = input(f"\n Delete the notification [Y|n]?")
            if yn in ('', 'y', 'Y'):
                self.notifier.noter.notes.rem(keys=keys)

