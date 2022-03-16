# -*- encoding: utf-8 -*-
"""
KERI
keri.app.delegating module

module for enveloping and forwarding KERI message
"""

from hio import help
from hio.base import doing
from hio.help import decking

from . import agenting, forwarding
from ..core import coring
from ..db import dbing

logger = help.ogler.getLogger()


class Boatswain(doing.DoDoer):
    """
    Sends messages to Delegator of an identifier and wait for the anchoring evcent to
    be processed to ensure the inception or rotation event has been approved by the delegator.

    Removes all Doers and exits as Done once the event has been anchored.

    """

    def __init__(self, hby, msgs=None, cues=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab (Hab): Habitat of the identifier to populate witnesses
            msg (bytes): is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None
            scheme (str): Scheme to favor if available

        """
        self.hby = hby
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.postman = forwarding.Postman(hby=hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)

        super(Boatswain, self).__init__(doers=[self.witq, self.postman, doing.doify(self.anchorDo)], **kwa)

    def anchorDo(self, tymth=None, tock=0.0):
        """
        Returns doifiable Doist compatible generator method (doer dog)

        Usage:
            add result of doify on this method to doers list

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock is injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                pre = msg["pre"]

                if pre not in self.hby.habs:
                    continue

                # load the hab of the delegated identifier to anchor
                hab = self.hby.habs[pre]
                alias = hab.name
                delpre = hab.kever.delegator  # get the delegator identifier
                dkever = hab.kevers[delpre]  # and the delegator's kever

                sn = msg["sn"] if "sn" in msg else hab.kever.sn

                # load the event and signatures
                evt = hab.makeOwnEvent(sn=sn)
                srdr = coring.Serder(raw=evt)
                del evt[:srdr.size]

                if srdr.ked["t"] == coring.Ilks.dip:  # are we incepting a new event?
                    phab = self.proxy(alias, hab.kever)  # create a proxy identifier for comms
                    if phab.kever.wits:
                        witDoer = agenting.WitnessReceiptor(hby=self.hby)
                        self.extend([witDoer])

                        witDoer.msgs.append(dict(pre=phab.pre))
                        while not witDoer.cues:
                            _ = yield self.tock

                        self.remove([witDoer])

                else:
                    phab = self.hby.habByName(f"{alias}-proxy")

                self.postman.send(src=phab.pre, dest=delpre, topic="delegate", serder=srdr, attachment=evt)
                yield self.tock

                yield from self.waitForAnchor(phab, hab, dkever, srdr)

                self.cues.append(msg)
                yield self.tock

            yield self.tock

    def waitForAnchor(self, phab, hab, dkever, serder):
        anchor = dict(i=serder.said, s=serder.sn, d=serder.said)
        self.witq.query(src=phab.pre, pre=dkever.prefixer.qb64, anchor=anchor)

        while True:
            if serder := self.hby.db.findAnchoringEvent(dkever.prefixer.qb64, anchor=anchor):
                seqner = coring.Seqner(sn=serder.sn)
                couple = seqner.qb64b + serder.saidb
                dgkey = dbing.dgKey(hab.kever.prefixer.qb64b, hab.kever.serder.saidb)
                self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)
                break
            yield

        return True

    def proxy(self, alias, kever):
        """ Create a proxy identifier for forward and query messages

        Uses witness and witness threshold configuration from delegated identifier to create
        a proxy identifier that will be able to send forward exn messages and query messages.

        Parameters:
            alias (str): human readable name of identifier to create a proxy for
            kever (Kever): key event representation of identitifer to create proxy for

        Returns:

        """
        palias = f"{alias}-proxy"
        kwargs = dict(
            transferable=True,
            wits=kever.wits,
            icount=1,
            isith=1,
            ncount=1,
            nsith=1,
            toad=kever.toad,
        )

        hab = self.hby.makeHab(palias, **kwargs)
        return hab
