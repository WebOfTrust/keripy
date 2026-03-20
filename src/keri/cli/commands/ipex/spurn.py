# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import os

from hio.base import doing

from ...common import Parsery, setupHby

from ....kering import Vrsn_1_0
from ....app import (Notifier, StreamPoster, Organizer,
                     GroupHab, Multiplexor, MailboxDirector,
                     multisigExn)

from ....app.grouping import loadHandlers as loadHandlersGrouping

from ....core import Kevery, Parser
from ....peer import Exchanger, cloneMessage
from ....vc import Ipex, ipexSpurnExn
from ....vc.protocoling import loadHandlers as loadHandlersProtocoling
from ....vdr import Regery, Verifier, Tevery


parser = argparse.ArgumentParser(description='Reject an IPEX apply, offer, agree or grant message', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)

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
        self.hby = setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.org = Organizer(hby=self.hby)

        kvy = Kevery(db=self.hby.db)
        tvy = Tevery(db=self.hby.db, reger=self.rgy.reger)
        vry = Verifier(hby=self.hby, reger=self.rgy.reger)

        self.psr = Parser(kvy=kvy, tvy=tvy, vry=vry, version=Vrsn_1_0)

        notifier = Notifier(self.hby)
        mux = Multiplexor(self.hby, notifier=notifier)

        self.exc = Exchanger(hby=self.hby, handlers=[])
        loadHandlersGrouping(self.exc, mux)
        loadHandlersProtocoling(self.hby, exc=self.exc, notifier=notifier)

        mbx = MailboxDirector(hby=self.hby,
                              topics=["/receipt", "/multisig", "/replay", "/credential"],
                              exc=self.exc)

        self.toRemove = [mbx]
        super(SpurnDoer, self).__init__(doers=self.toRemove + [doing.doify(self.spurnDo)])

    def spurnDo(self, tymth, tock=0.0, **kwa):
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

        ipex, pathed = cloneMessage(self.hby, self.said)
        if ipex is None:
            raise ValueError(f"exn message said={self.said} not found")

        route = ipex.ked['r']
        verb = os.path.basename(os.path.normpath(route))

        if verb not in (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant):
            raise ValueError(f"exn said={self.said} is not a spurnable message, route={route}")

        recp = ipex.ked['i']
        exn, atc = ipexSpurnExn(hab=self.hab, message=self.message, spurned=ipex)
        msg = bytearray(exn.raw)
        msg.extend(atc)

        Parser(version=Vrsn_1_0).parseOne(ims=bytes(msg), exc=self.exc)

        spurn, _ = cloneMessage(self.hby, exn.said)
        if spurn is None:
            raise ValueError(f"Invalid spurn evt={exn.ked}, not saved")

        if isinstance(self.hab, GroupHab):
            wexn, watc = multisigExn(self.hab, exn=msg)

            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for recp in smids:  # this goes to other participants only as a signaling mechanism
                postman = StreamPoster(hby=self.hby, hab=self.hab.mhab, recp=recp, topic="multisig")
                postman.send(serder=wexn,
                             attachment=watc)
                doer = doing.DoDoer(doers=postman.deliver())
                self.extend([doer])

            while not self.exc.complete(said=wexn.said):
                yield self.tock

        if self.exc.lead(self.hab, said=exn.said):
            print("Sending spurn message...")
            postman = StreamPoster(hby=self.hby, hab=self.hab, recp=recp, topic="credential")
            postman.send(serder=exn,
                         attachment=atc)

            doer = doing.DoDoer(doers=postman.deliver())
            self.extend([doer])

            while not doer.done:
                yield self.tock

        self.remove(self.toRemove)
