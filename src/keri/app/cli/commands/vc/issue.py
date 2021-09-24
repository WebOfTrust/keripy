import argparse
import json

from hio import help
from hio.base import doing

from keri import kering
from keri.app import directing, indirecting, grouping
from keri.app.cli.common import existing
from keri.peer import exchanging
from keri.vdr import issuing, verifying, viring

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: issueCredential(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--schema', '-s', help='qb64 SAID of Schema to issue',
                    default=None, required=True)
parser.add_argument('--type', '-t', help='Human readable type name of credential to issue',
                    default=None, required=True)
parser.add_argument('--source', '-c', help='AC/DC Source links',
                    default=None)
parser.add_argument('--recipient', '-R', help='qb64 identifier prefix of the recipient of the credential',
                    default=None)
parser.add_argument('--data', '-d', help='Credential data, \'@\' allowed', default=[], action="store", required=True)


def issueCredential(args):
    name = args.name
    if args.data is not None:
        try:
            if args.data.startswith("@"):
                f = open(args.data[1:], "r")
                data = json.load(f)
            else:
                data = json.loads(args.data)
        except json.JSONDecodeError:
            raise kering.ConfigurationError("data supplied must be value JSON to issue in a credential")
    else:
        raise kering.ConfigurationError("data supplied must be value JSON to issue in a credential")


    issueDoer = CredentialIssuer(name=name, registryName=args.registry_name, schema=args.schema, source=args.source,
                                 recipient=args.recipient, typ=args.type, data=data)

    doers = [issueDoer]
    directing.runController(doers=doers, expire=0.0)


class CredentialIssuer(doing.DoDoer):
    """
    Credential issuer DoDoer

    """

    def __init__(self, name, registryName, schema, source, recipient, typ, data):
        """

        Parameters:
             name:
             registryName:
             schema:
             source:
             recipient:
             typ: (str) human readable credential type name
             data: (dict) credential data dict
        """
        self.name = name
        self.hab, doers = existing.openHabitat(name=self.name)

        self.msg = dict(
            registryName=registryName,
            schema=schema,
            source=source,
            recipient=recipient,
            typ=typ,
            data=data
        )


        reger = viring.Registry(name=registryName)
        issuer = issuing.Issuer(hab=self.hab, name=registryName, reger=reger)
        self.verifier = verifying.Verifier(hab=self.hab, name=registryName, reger=reger, tevers=issuer.tevers)
        meh = grouping.MultisigEventHandler(hab=self.hab, verifier=self.verifier)

        handlers = [meh]
        exchanger = exchanging.Exchanger(hab=self.hab, handlers=handlers)

        mbx = indirecting.MailboxDirector(hab=self.hab, exc=exchanger, topics=["/receipt", "/multisig"])

        self.issr = issuing.IssuerDoer(hab=self.hab, issuer=issuer, verifier=self.verifier)
        doers.extend([self.issr, mbx, exchanger])
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.issueDo)])
        super(CredentialIssuer, self).__init__(doers=doers)

    def issueDo(self, tymth, tock=0.0):
        """
        """
        yield self.tock

        self.issr.msgs.append(self.msg)

        done = False
        while not done:
            while self.verifier.cues:
                cue = self.verifier.cues.popleft()
                if cue["kin"] == "saved":
                    done = True

                yield self.tock
            yield

        self.remove(self.toRemove)
