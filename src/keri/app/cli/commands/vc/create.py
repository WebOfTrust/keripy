import argparse
import json

from hio import help
from hio.base import doing

from keri import kering
from keri import core
from keri.core import coring, eventing, serdering

from keri.app import indirecting, habbing, grouping, connecting, forwarding, signing, notifying
from keri.app.cli.common import existing
from keri.help import helping
from keri.peer import exchanging
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
parser.add_argument('--recipient', '-R', help='alias or qb64 identifier prefix of the recipient of the credential',
                    default=None)
parser.add_argument('--data', '-d', help='Credential data, \'@\' allowed', default=None, action="store", required=False)
parser.add_argument('--credential', help='Full credential, \'@\' allowed', default=None, action="store",
                    required=False)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--private", help="flag to indicate if this credential needs privacy preserving features",
                    action="store_true")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument("--time", help="timestamp for the credential creation", required=False, default=None)


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
                                 credential=credential,
                                 timestamp=args.time,
                                 private=args.private)

    doers = [issueDoer]
    return doers


class CredentialIssuer(doing.DoDoer):
    """
    Credential issuer DoDoer

    """

    def __init__(self, name, alias, base, bran, registryName=None, schema=None, edges=None, recipient=None, data=None,
                 rules=None, credential=None, timestamp=None, private=False):
        """ Create DoDoer for issuing a credential and managing the processes needed to complete issuance

        Parameters:
             name:
             registryName:
             schema:
             edges:
             recipient:
             data: (dict) credential data dict
             credential: (dict) full credential to issue when joining a multisig issuance
             out (str): Filename for credential output
             private: (bool) privacy preserving

        """
        self.name = name
        self.registryName = registryName
        self.timestamp = timestamp
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        if self.hab is None:
            raise ValueError(f"invalid alias {alias}")

        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)  # setup doer
        self.counselor = grouping.Counselor(hby=self.hby)
        self.registrar = credentialing.Registrar(hby=self.hby, rgy=self.rgy, counselor=self.counselor)
        self.org = connecting.Organizer(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)
        notifier = notifying.Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)
        exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(exc, mux)

        self.verifier = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        mbx = indirecting.MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/credential"],
                                          verifier=self.verifier, exc=exc)
        self.credentialer = credentialing.Credentialer(hby=self.hby, rgy=self.rgy, registrar=self.registrar,
                                                       verifier=self.verifier)

        try:
            if credential is None:
                if recipient is None:
                    recp = None
                elif recipient in self.hby.kevers:
                    recp = recipient
                else:
                    recp = self.org.find("alias", recipient)
                    if len(recp) != 1:
                        raise ValueError(f"invalid recipient {recipient}")
                    recp = recp[0]['id']

                if self.timestamp is not None:
                    data["dt"] = self.timestamp

                self.creder = self.credentialer.create(regname=registryName,
                                                       recp=recp,
                                                       schema=schema,
                                                       source=edges,
                                                       rules=rules,
                                                       data=data,
                                                       private=private)
            else:
                self.creder = serdering.SerderACDC(sad=credential) # proving.Creder(ked=credential)
                self.credentialer.validate(creder=self.creder)

        except kering.ConfigurationError as e:
            print(f"error issuing credential {e}")
            return

        doers = [self.hbyDoer, mbx, self.counselor, self.registrar, self.credentialer, self.postman]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.createDo)])
        super(CredentialIssuer, self).__init__(doers=doers)

    def createDo(self, tymth, tock=0.0):
        """  Issue Credential doer method


        Parameters:
             tymth (function): injected function wrapper closure returned by .tymen() of
                 Tymist instance. Calling tymth() returns associated Tymist .tyme.
             tock (float): injected initial tock value
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        registry = self.rgy.registryByName(self.registryName)
        hab = registry.hab

        dt = self.creder.attrib["dt"] if "dt" in self.creder.attrib else helping.nowIso8601()
        iserder = registry.issue(said=self.creder.said, dt=dt)

        #vcid = iserder.ked["i"]
        #rseq = coring.Seqner(snh=iserder.ked["s"])
        rseal = eventing.SealEvent(iserder.pre, iserder.snh, iserder.said)
        rseal = dict(i=rseal.i, s=rseal.s, d=rseal.d)

        if registry.estOnly:
            anc = hab.rotate(data=[rseal])

        else:
            anc = hab.interact(data=[rseal])

        aserder = serdering.SerderKERI(raw=anc)
        self.credentialer.issue(self.creder, iserder)
        self.registrar.issue(self.creder, iserder, aserder)

        acdc = signing.serialize(self.creder, coring.Prefixer(qb64=iserder.pre),
                                 core.Number(num=iserder.sn, code=core.NumDex.Huge),
                                 coring.Saider(qb64=iserder.said))

        if isinstance(self.hab, habbing.GroupHab):
            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                exn, atc = grouping.multisigIssueExn(ghab=self.hab, acdc=acdc, iss=iserder.raw, anc=anc)
                self.postman.send(src=self.hab.mhab.pre,
                                  dest=recp,
                                  topic="multisig",
                                  serder=exn,
                                  attachment=atc)

        while not self.credentialer.complete(said=self.creder.said):
            self.rgy.processEscrows()
            yield self.tock

        print(f"{self.creder.said} has been created.")
        self.remove(self.toRemove)
