# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio import help
from hio.base import doing

from keri.app import connecting, forwarding
from keri.app.cli.common import existing
from keri.core import coring
from keri.vc import protocoling
from keri.vdr import credentialing

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Send credential presentation for specified credential to recipient')
parser.set_defaults(handler=lambda args: present_credential(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--said", "-s", help="SAID of the credential to present.", required=True)
parser.add_argument("--include", "-i", help="send credential and all other cryptographic artifacts with presentation",
                    action="store_true")
parser.add_argument("--recipient", "-r", help="alias or qb64 AID ")


def present_credential(args):
    """ Command line credential presentation handler

    """

    ed = PresentDoer(name=args.name,
                     alias=args.alias,
                     base=args.base,
                     bran=args.bran,
                     said=args.said,
                     recipient=args.recipient,
                     include=args.include)
    return [ed]


class PresentDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, recipient, include):
        self.said = said
        self.recipient = recipient
        self.include = include

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.org = connecting.Organizer(hby=self.hby)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.postman = forwarding.Postman(hby=self.hby)

        doers = [self.postman, doing.doify(self.presentDo)]

        super(PresentDoer, self).__init__(doers=doers)

    def presentDo(self, tymth, tock=0.0):
        """ Present credential from store and any related material

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

        creder = self.rgy.reger.creds.get(self.said)
        if creder is None:
            raise ValueError(f"invalid credential SAID {self.said}")

        if self.recipient in self.hby.kevers:
            recp = self.recipient
        else:
            recp = self.org.find("alias", self.recipient)
            if len(recp) != 1:
                raise ValueError(f"invalid recipient {self.recipient}")
            recp = recp[0]['id']

        if self.include:
            credentialing.sendCredential(self.hby, hab=self.hab, reger=self.rgy.reger, postman=self.postman,
                                         creder=creder, recp=recp)

        if self.hab.mhab:
            senderHab = self.hab.mhab
        else:
            senderHab = self.hab

        if senderHab.pre != creder.issuer:
            for msg in senderHab.db.cloneDelegation(senderHab.kever):
                serder = coring.Serder(raw=msg)
                atc = msg[serder.size:]
                self.postman.send(src=senderHab.pre, dest=recp, topic="credential", serder=serder, attachment=atc)

            for msg in senderHab.db.clonePreIter(pre=senderHab.pre):
                serder = coring.Serder(raw=msg)
                atc = msg[serder.size:]
                self.postman.send(src=senderHab.pre, dest=recp, topic="credential", serder=serder, attachment=atc)

        exn, atc = protocoling.presentationExchangeExn(hab=senderHab, reger=self.rgy.reger, said=self.said)
        self.postman.send(src=senderHab.pre, dest=recp, topic="credential", serder=exn, attachment=atc)

        while True:
            while self.postman.cues:
                cue = self.postman.cues.popleft()
                if "said" in cue and cue["said"] == exn.said:
                    print("Presentation sent")
                    toRemove = [self.postman]
                    self.remove(toRemove)
                    return True
                yield self.tock
            yield self.tock

