# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import os

from hio.base import doing

from keri.app import forwarding, connecting, habbing, grouping, indirecting
from keri.app.cli.common import existing
from keri.app.notifying import Notifier
from keri.core import parsing, coring, eventing
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vc.protocoling import Ipex
from keri.vdr import credentialing, verifying
from keri.vdr import eventing as teventing


parser = argparse.ArgumentParser(description='Reject an IPEX apply, offer, agree or grant message')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--said", "-s", help="SAID of the exn IPEX message to spurn", required=True)
parser.add_argument("--message", "-m", help="optional human readable message to "
                                            "send to recipient", required=False, default="")


def handler(args):
    ed = SpurnDoer(name=args.name,
                   alias=args.alias,
                   base=args.base,
                   bran=args.bran,
                   said=args.said,
                   message=args.message)
    return [ed]


class SpurnDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, message):
        self.said = said
        self.message = message
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.org = connecting.Organizer(hby=self.hby)

        kvy = eventing.Kevery(db=self.hby.db)
        tvy = teventing.Tevery(db=self.hby.db, reger=self.rgy.reger)
        vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)

        self.psr = parsing.Parser(kvy=kvy, tvy=tvy, vry=vry)

        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)

        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(self.exc, mux)
        protocoling.loadHandlers(self.hby, exc=self.exc, notifier=notifier)

        mbx = indirecting.MailboxDirector(hby=self.hby,
                                          topics=["/receipt", "/multisig", "/replay", "/credential"],
                                          exc=self.exc)

        self.toRemove = [mbx]
        super(SpurnDoer, self).__init__(doers=self.toRemove + [doing.doify(self.spurnDo)])

    def spurnDo(self, tymth, tock=0.0):
        """ Sprun any IPEX message

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

        ipex, pathed = exchanging.cloneMessage(self.hby, self.said)
        if ipex is None:
            raise ValueError(f"exn message said={self.said} not found")

        route = ipex.ked['r']
        verb = os.path.basename(os.path.normpath(route))

        if verb not in (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant):
            raise ValueError(f"exn said={self.said} is not a spurnable message, route={route}")

        recp = ipex.ked['i']
        exn, atc = protocoling.ipexSpurnExn(hab=self.hab, message=self.message, spurned=ipex)
        msg = bytearray(exn.raw)
        msg.extend(atc)

        parsing.Parser().parseOne(ims=bytes(msg), exc=self.exc)

        spurn, _ = exchanging.cloneMessage(self.hby, exn.said)
        if spurn is None:
            raise ValueError(f"Invalid spurn evt={exn.ked}, not saved")

        if isinstance(self.hab, habbing.GroupHab):
            wexn, watc = grouping.multisigExn(self.hab, exn=msg)

            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                postman = forwarding.StreamPoster(hby=self.hby, hab=self.hab.mhab, recp=recp, topic="multisig")
                postman.send(serder=wexn,
                             attachment=watc)
                doer = doing.DoDoer(doers=postman.deliver())
                self.extend([doer])

            while not self.exc.complete(said=wexn.said):
                yield self.tock

        if self.exc.lead(self.hab, said=exn.said):
            print("Sending spurn message...")
            postman = forwarding.StreamPoster(hby=self.hby, hab=self.hab, recp=recp, topic="credential")
            postman.send(serder=exn,
                         attachment=atc)

            doer = doing.DoDoer(doers=postman.deliver())
            self.extend([doer])

            while not doer.done:
                yield self.tock

        self.remove(self.toRemove)
