import argparse
import json

from hio import help
from hio.base import doing

from keri import kering
from keri.app import indirecting, habbing, grouping
from keri.app.cli.common import existing
from keri.vdr import credentialing, verifying

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: issueCredential(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None)
parser.add_argument('--schema', '-s', help='qb64 SAID of Schema to issue',
                    default=None, required=True)
parser.add_argument('--source', '-e', help='AC/DC Source links',
                    default=None)
parser.add_argument('--recipient', '-R', help='qb64 identifier prefix of the recipient of the credential',
                    default=None)
parser.add_argument('--data', '-d', help='Credential data, \'@\' allowed', default=[], action="store", required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran


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
                                 recipient=args.recipient, data=data)

    doers = [issueDoer]
    return doers


class CredentialIssuer(doing.DoDoer):
    """
    Credential issuer DoDoer

    """

    def __init__(self, name, alias, base, bran, registryName, schema, source, recipient, data):
        """ Create DoDoer for issuing a credential and managing the processes needed to complete issuance

        Parameters:
             name:
             registryName:
             schema:
             source:
             recipient:
             data: (dict) credential data dict
        """
        self.name = name
        self.alias = alias
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        counselor = grouping.Counselor(hby=self.hby)

        self.msg = dict(
            registryName=registryName,
            schema=schema,
            source=source,
            recipient=recipient,
            data=data
        )

        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig"])
        self.icpr = credentialing.RegistryIssueDoer(hby=self.hby, rgy=self.rgy, counselor=counselor)

        doers = [self.hbyDoer, mbx, counselor]
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
        yield self.tock

        self.issr.msgs.append(self.msg)

        creder = None
        published = False
        witnessed = False
        finished = False
        while not ((published and witnessed) or finished):
            while self.issr.cues:
                cue = self.issr.cues.popleft()
                if cue["kin"] == "saved":
                    creder = cue["creder"]

                if cue["kin"] == "finished":
                    finished = True

                elif cue["kin"] == "published":
                    published = True

                elif cue["kin"] == "witnessed":
                    witnessed = True

                yield self.tock
            yield


        print(f"{creder.said} has been issued.")
        self.remove(self.toRemove)
