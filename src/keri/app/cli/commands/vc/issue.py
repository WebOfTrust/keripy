import argparse
import json

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting, habbing, grouping
from keri.app.cli.common import existing
from keri.vc import proving
from keri.vdr import credentialing, verifying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: issueCredential(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--schema', '-s', help='qb64 SAID of Schema to issue',
                    default=None, required=False)
parser.add_argument('--edges', '-e', help='AC/DC Edge links',
                    default=None)
parser.add_argument('--rules', help='AC/DC Rules Section',
                    default=None)
parser.add_argument('--recipient', '-R', help='qb64 identifier prefix of the recipient of the credential',
                    default=None)
parser.add_argument('--data', '-d', help='Credential data, \'@\' allowed', default=None, action="store", required=False)
parser.add_argument('--credential', help='Full credential, \'@\' allowed', default=None, action="store",
                    required=False)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


def issueCredential(args):
    name = args.name
    data = None
    rules = None
    edges = None
    credential = None
    if args.data is not None:
        try:
            if args.data.startswith("@"):
                f = open(args.data[1:], "r")
                data = json.load(f)
            else:
                data = json.loads(args.data)
        except json.JSONDecodeError:
            raise kering.ConfigurationError("data supplied must be value JSON to issue in a credential")

        if args.edges is not None:
            try:
                if args.edges.startswith("@"):
                    f = open(args.edges[1:], "r")
                    edges = json.load(f)
                else:
                    edges = json.loads(args.edges)
            except json.JSONDecodeError:
                raise kering.ConfigurationError("edges supplied must be value JSON to issue in a credential")
        if args.rules is not None:
            try:
                if args.rules.startswith("@"):
                    f = open(args.rules[1:], "r")
                    rules = json.load(f)
                else:
                    rules = json.loads(args.rules)
            except json.JSONDecodeError:
                raise kering.ConfigurationError("rules supplied must be value JSON to issue in a credential")
    elif args.credential is not None:
        try:
            if args.credential.startswith("@"):
                f = open(args.credential[1:], "r")
                credential = json.load(f)
            else:
                credential = json.loads(args.credential)
        except json.JSONDecodeError:
            raise kering.ConfigurationError("data supplied must be value JSON to issue in a credential")
    else:
        raise kering.ConfigurationError("credential or data supplied must be value JSON to issue in a credential")

    issueDoer = CredentialIssuer(name=name,
                                 alias=args.alias,
                                 base=args.base,
                                 bran=args.bran,
                                 registryName=args.registry_name,
                                 schema=args.schema,
                                 recipient=args.recipient,
                                 data=data,
                                 edges=edges,
                                 rules=rules,
                                 credential=credential)

    doers = [issueDoer]
    return doers


class CredentialIssuer(doing.DoDoer):
    """
    Credential issuer DoDoer

    """

    def __init__(self, name, alias, base, bran, registryName=None, schema=None, edges=None, recipient=None, data=None,
                 rules=None, credential=None):
        """ Create DoDoer for issuing a credential and managing the processes needed to complete issuance

        Parameters:
             name:
             registryName:
             schema:
             source:
             recipient:
             data: (dict) credential data dict
             credential (dict) full credential to issue when joining a multisig issuance

        """
        self.name = name
        self.alias = alias
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.counselor = grouping.Counselor(hby=self.hby)
        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)

        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/credential"])
        self.credentialer = credentialing.Credentialer(hby=self.hby, rgy=self.rgy, registrar=self.registrar,
                                                       verifier=self.verifier)
        try:
            if credential is None:
                self.creder = self.credentialer.create(regname=registryName,
                                                       recp=recipient,
                                                       schema=schema,
                                                       source=edges,
                                                       rules=rules,
                                                       data=data)
                print(f"Writing credential {self.creder.said} to credential.json")
                f = open("./credential.json", mode="w")
                json.dump(self.creder.crd, f)
                f.close()
            else:
                self.creder = proving.Creder(ked=credential)
                self.credentialer.validate(creder=self.creder)

            self.credentialer.issue(creder=self.creder)

        except kering.ConfigurationError as e:
            print(f"error issuing credential {e}")
            return

        doers = [self.hbyDoer, mbx, self.counselor, self.registrar, self.credentialer]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.issueDo)])
        super(CredentialIssuer, self).__init__(doers=doers)

    def issueDo(self, tymth, tock=0.0):
        """  Issue Credential doer method


        Parameters:
             tymth (function): injected function wrapper closure returned by .tymen() of
                 Tymist instance. Calling tymth() returns associated Tymist .tyme.
             tock (float): injected initial tock value
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.credentialer.complete(said=self.creder.said):
            self.rgy.processEscrows()
            yield self.tock

        print(f"{self.creder.said} has been issued.")
        self.remove(self.toRemove)
