# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from ...common import existing, Parsery

from .... import Vrsn_1_0
from ....app import (Notifier, Organizer, GroupHab,
                     Multiplexor, MailboxDirector,
                     WitnessInquisitor, StreamPoster, multisigExn)

from ....app.grouping import loadHandlers as loadHandlersGrouping

from ....core import Parser, Sadder, Kevery
from ....peer import Exchanger, cloneMessage, serializeMessage
from ....vc import ipexAdmitExn
from ....vc.protocoling import loadHandlers as loadHandlersProtocoling
from ....vdr import Regery, Verifier, Tevery


parser = argparse.ArgumentParser(description='Accept a credential being issued or presented in response to an IPEX '
                                             'grant',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)

parser.add_argument("--said", "-s", help="SAID of the exn grant message to admit", required=True)
parser.add_argument("--message", "-m", help="optional human readable message to "
                                            "send to recipient", required=False, default="")
parser.add_argument("--time", help="timestamp", required=False, default=None)


def handler(args):
    ed = AdmitDoer(name=args.name,
                   alias=args.alias,
                   base=args.base,
                   bran=args.bran,
                   said=args.said,
                   message=args.message,
                   timestamp=args.time)
    return [ed]


class AdmitDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, message, timestamp ):
        self.said = said
        self.message = message
        self.timestamp = timestamp
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.org = Organizer(hby=self.hby)
        self.witq = WitnessInquisitor(hby=self.hby)

        self.kvy = Kevery(db=self.hby.db)
        self.tvy = Tevery(db=self.hby.db, reger=self.rgy.reger)
        self.vry = Verifier(hby=self.hby, reger=self.rgy.reger)

        self.psr = Parser(kvy=self.kvy, tvy=self.tvy, vry=self.vry, version=Vrsn_1_0)

        notifier = Notifier(self.hby)
        mux = Multiplexor(self.hby, notifier=notifier)

        self.exc = Exchanger(hby=self.hby, handlers=[])
        loadHandlersGrouping(self.exc, mux)
        loadHandlersProtocoling(self.hby, exc=self.exc, notifier=notifier)

        mbx = MailboxDirector(hby=self.hby,
                              topics=["/receipt", "/multisig", "/replay", "/credential"],
                              exc=self.exc, kvy=self.kvy, tvy=self.tvy, verifier=self.vry)

        self.toRemove = [mbx, self.witq]
        super(AdmitDoer, self).__init__(doers=self.toRemove + [doing.doify(self.admitDo)])

    def admitDo(self, tymth, tock=0.0, **kwa):
        """ Admit credential by accepting into database and sending /ipex/admit exn message

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

        grant, pathed = cloneMessage(self.hby, self.said)
        if grant is None:
            raise ValueError(f"exn message said={self.said} not found")

        route = grant.ked['r']
        if route != "/ipex/grant":
            raise ValueError(f"exn said={self.said} is not a grant message, route={route}")

        embeds = grant.ked['e']
        acdc = embeds["acdc"]
        issr = acdc['i']

        # Lets get the latest KEL and Registry if needed
        self.witq.query(src=self.hab.pre, pre=issr)
        if "ri" in acdc:
            self.witq.telquery(src=self.hab.pre, pre=issr, ri=acdc["ri"], i=acdc["d"])

        for label in ("anc", "iss", "acdc"):
            ked = embeds[label]
            sadder = Sadder(ked=ked)
            ims = bytearray(sadder.raw) + pathed[label]
            self.psr.parseOne(ims=ims)

        said = acdc["d"]
        while not self.rgy.reger.saved.get(keys=said):
            yield self.tock

        recp = grant.ked['i']
        exn, atc = ipexAdmitExn(hab=self.hab, message=self.message, grant=grant, dt=self.timestamp)
        msg = bytearray(exn.raw)
        msg.extend(atc)

        Parser(version=Vrsn_1_0).parseOne(ims=bytes(msg), exc=self.exc)

        sender = self.hab
        if isinstance(self.hab, GroupHab):
            sender = self.hab.mhab
            wexn, watc = multisigExn(self.hab, exn=msg)

            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for part in smids:  # this goes to other participants only as a signaling mechanism
                postman = StreamPoster(hby=self.hby, hab=self.hab.mhab, recp=part, topic="multisig")
                postman.send(serder=wexn,
                             attachment=watc)
                doer = doing.DoDoer(doers=postman.deliver())
                self.extend([doer])

            while not self.exc.complete(said=exn.said):
                yield self.tock

        if self.exc.lead(self.hab, said=exn.said):
            print(f"Sending admit message to {recp}")
            postman = StreamPoster(hby=self.hby, hab=sender, recp=recp, topic="credential")

            atc = serializeMessage(self.hby, exn.said)
            del atc[:exn.size]
            postman.send(serder=exn,
                         attachment=atc)

            doer = doing.DoDoer(doers=postman.deliver())
            self.extend([doer])

            while not doer.done:
                yield self.tock

            print(f"... admit message sent")
            self.remove([doer])

        self.remove(self.toRemove)
