# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from keri.app import forwarding, connecting, habbing, grouping, indirecting, signing
from keri.app.cli.common import existing
from keri.app.notifying import Notifier
from keri.core import coring, parsing
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing

parser = argparse.ArgumentParser(description='Reply to IPEX agree message or initiate an IPEX exchange with a '
                                             'credential issuance or presentation')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--recipient", "-r", help="alias or qb64 identifier prefix of the self.recp of "
                                              "the credential", required=True)
parser.add_argument("--said", "-s", help="SAID of the credential to grant", required=True)
parser.add_argument("--message", "-m", help="optional human readable message to "
                                            "send to recipient", required=False, default="")
parser.add_argument("--time", help="timestamp for the revocation", required=False, default=None)


def handler(args):
    ed = GrantDoer(name=args.name,
                   alias=args.alias,
                   base=args.base,
                   bran=args.bran,
                   said=args.said,
                   recp=args.recipient,
                   message=args.message,
                   timestamp=args.time)
    return [ed]


class GrantDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, recp, message, timestamp):
        self.said = said
        self.recp = recp
        self.message = message
        self.timestamp = timestamp
        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.org = connecting.Organizer(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)
        notifier = Notifier(self.hby)
        mux = grouping.Multiplexor(self.hby, notifier=notifier)

        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        grouping.loadHandlers(self.exc, mux)
        protocoling.loadHandlers(self.hby, rgy=self.rgy, exc=self.exc, notifier=notifier)

        mbx = indirecting.MailboxDirector(hby=self.hby,
                                          topics=["/receipt", "/multisig", "/replay", "/credential"],
                                          exc=self.exc)

        self.toRemove = [self.postman, mbx]
        super(GrantDoer, self).__init__(doers=self.toRemove + [doing.doify(self.grantDo)])

    def grantDo(self, tymth, tock=0.0):
        """ Grant credential by creating /ipex/grant exn message

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

        creder, prefixer, seqner, saider = self.rgy.reger.cloneCred(said=self.said)
        if creder is None:
            raise ValueError(f"invalid credential SAID to grant={self.said}")

        acdc = signing.serialize(creder, prefixer, seqner, saider)

        if self.recp is None:
            recp = creder.subject['i'] if 'i' in creder.subject else None
        elif self.recp in self.hby.kevers:
            recp = self.recp
        else:
            recp = self.org.find("alias", self.recp)
            if len(recp) != 1:
                raise ValueError(f"invalid recipient {self.recp}")
            recp = recp[0]['id']

        if recp is None:
            raise ValueError("unable to find recipient")

        iss = self.rgy.reger.cloneTvtAt(creder.said)

        iserder = coring.Serder(raw=bytes(iss))
        seqner = coring.Seqner(sn=iserder.sn)

        serder = self.hby.db.findAnchoringEvent(creder.ked['i'],
                                                anchor=dict(i=iserder.pre, s=seqner.snh, d=iserder.said))
        anc = self.hby.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said)

        exn, atc = protocoling.ipexGrantExn(hab=self.hab, recp=recp, message=self.message, acdc=acdc, iss=iss, anc=anc,
                                            dt=self.timestamp)
        msg = bytearray(exn.raw)
        msg.extend(atc)

        parsing.Parser().parseOne(ims=bytes(msg), exc=self.exc)

        sender = self.hab.pre
        if isinstance(self.hab, habbing.GroupHab):
            sender = self.hab.mhab.pre
            wexn, watc = grouping.multisigExn(self.hab, exn=msg)

            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for part in smids:  # this goes to other participants
                self.postman.send(src=self.hab.mhab.pre,
                                  dest=part,
                                  topic="multisig",
                                  serder=wexn,
                                  attachment=watc)

            while not self.exc.complete(said=exn.said):
                yield self.tock

        if self.exc.lead(self.hab, said=exn.said):
            print(f"Sending message {exn.said} to {recp}")
            atc = exchanging.serializeMessage(self.hby, exn.said)
            del atc[:exn.size]
            self.postman.send(src=sender,
                              dest=recp,
                              topic="credential",
                              serder=exn,
                              attachment=atc)

            while not self.postman.sent(said=exn.said):
                yield self.tock

            print("... grant message sent")

        self.remove(self.toRemove)
