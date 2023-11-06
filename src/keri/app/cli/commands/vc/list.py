# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import datetime
import json
import sys

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting
from keri.app.cli.common import existing, terming
from keri.core import scheming
from keri.help import helping
from keri.vdr import credentialing, verifying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='List credentials and check mailboxes for any newly issued credentials')
parser.set_defaults(handler=lambda args: list_credentials(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print full JSON of all credentials", action="store_true")
parser.add_argument("--poll", "-P", help="Poll mailboxes for any issued credentials", action="store_true")
parser.add_argument("--issued", "-i", help="Display credentials that this AID has issued.",
                    action="store_true")
parser.add_argument("--said", "-s", help="Display only the SAID of found credentials, one per line.",
                    action="store_true")
parser.add_argument("--schema", help="Display only credentials with the given schema SAID.",
                    action="store", default=None)


def list_credentials(args):
    """ Command line list credential registries handler

    """
    ld = ListDoer(name=args.name,
                  alias=args.alias,
                  base=args.base,
                  bran=args.bran,
                  verbose=args.verbose,
                  poll=args.poll,
                  said=args.said,
                  issued=args.issued,
                  schema=args.schema)
    return [ld]


class ListDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, verbose=False, poll=False, said=False, issued=False, schema=None):
        self.verbose = verbose
        self.poll = poll
        self.said = said
        self.issued = issued
        self.schema = schema

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        if alias is None:
            alias = existing.aliasInput(self.hby)

        self.hab = self.hby.habByName(alias)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/credential'], verifier=self.vry)

        doers = [self.mbx, doing.doify(self.listDo)]

        super(ListDoer, self).__init__(doers=doers)

    def listDo(self, tymth, tock=0.0):
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
            sys.stdout.write(f"Checking mailboxes for any {'issued' if self.issued else 'received'} credentials")
            sys.stdout.flush()
            while helping.nowUTC() < end:
                sys.stdout.write(".")
                sys.stdout.flush()
                if "/credential" in self.mbx.times:
                    end = self.mbx.times['/credential'] + datetime.timedelta(seconds=5)
                yield 1.0
            print("\n")

        if self.issued:
            saids = self.rgy.reger.issus.get(keys=self.hab.pre)
        else:
            saids = self.rgy.reger.subjs.get(keys=self.hab.pre)

        if self.schema is not None:
            scads = self.rgy.reger.schms.get(keys=self.schema)
            saids = [saider for saider in saids if saider.qb64 in [saider.qb64 for saider in scads]]

        if self.said:
            for said in saids:
                print(said.qb64)
        else:
            print(f"Current {'issued' if self.issued else 'received'}"
                  f" credentials for {self.hab.name} ({self.hab.pre}):\n")
            creds = self.rgy.reger.cloneCreds(saids, self.hab.db)
            for idx, cred in enumerate(creds):
                sad = cred['sad']
                status = cred["status"]
                schema = sad['s']
                scraw = self.mbx.verifier.resolver.resolve(schema)
                if not scraw:
                    raise kering.ConfigurationError("Credential schema {} not found".format(schema))

                schemer = scheming.Schemer(raw=scraw)
                print(f"Credential #{idx+1}: {sad['d']}")
                print(f"    Type: {schemer.sed['title']}")
                if status['et'] == 'iss' or status['et'] == 'bis':
                    print(f"    Status: Issued {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}")
                elif status['et'] == 'rev' or status['et'] == 'brv':
                    print(f"    Status: Revoked {terming.Colors.FAIL}{terming.Symbols.FAILED}{terming.Colors.ENDC}")
                else:
                    print(f"    Status: Unknown")
                print(f"    Issued by {sad['i']}")
                print(f"    Issued on {status['dt']}")

                if self.verbose:
                    bsad = json.dumps(sad, indent=2)
                    print("    Full Credential:")
                    for line in bsad.splitlines():
                        print(f"\t{line}")

        self.remove([self.mbx])
