# -*- encoding: utf-8 -*-
"""
KERI
keri.app.delegating module

module for enveloping and forwarding KERI message
"""
import json

from hio import help
from hio.base import doing
from hio.help import decking

from . import agenting, forwarding
from ..core import coring
from ..db import dbing, basing
from ..help import helping
from ..peer import exchanging

logger = help.ogler.getLogger()


class Boatswain(doing.DoDoer):
    """
    Sends messages to Delegator of an identifier and wait for the anchoring event to
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

                if hab.phab:
                    phab = hab.phab
                elif srdr.ked["t"] == coring.Ilks.dip:  # are we incepting a new event?
                    phab = self.proxy(alias, hab.kever)  # create a proxy identifier for comms
                    if phab.kever.wits:
                        witDoer = agenting.WitnessReceiptor(hby=self.hby)
                        self.extend([witDoer])

                        witDoer.msgs.append(dict(pre=phab.pre))
                        while not witDoer.cues:
                            _ = yield self.tock

                        self.remove([witDoer])

                        icp = phab.db.cloneEvtMsg(pre=phab.pre, fn=0, dig=phab.kever.serder.saidb)
                        ser = coring.Serder(raw=icp)
                        del icp[:ser.size]

                        self.postman.send(src=phab.pre, dest=hab.kever.delegator, topic="delegate", serder=ser,
                                          attachment=icp)
                else:
                    phab = self.hby.habByName(f"{alias}-proxy")

                # Send exn message for notification purposes
                exn, atc = delegateRequestExn(phab, delpre=delpre, ked=srdr.ked, aids=hab.aids)
                # exn of /oobis of all multisig participants to rootgar
                # self.postman.send(src=phab.pre, dest=hab.kever.delegator, topic="oobis", serder=exn, attachment=atc)
                self.postman.send(src=phab.pre, dest=hab.kever.delegator, topic="delegate", serder=exn, attachment=atc)
                self.postman.send(src=phab.pre, dest=delpre, topic="delegate", serder=srdr, attachment=evt)

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
            isith='1',
            ncount=0,
            nsith='0',
            toad=kever.toad,
        )

        hab = self.hby.makeHab(palias, **kwargs)
        return hab


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer delegation protocols

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Outbound notifications

    """
    delreq = DelegateRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(delreq)
    oobireq = OobiRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(oobireq)


class DelegateRequestHandler(doing.DoDoer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/delegate/request"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            controller (str) qb64 identity prefix of controller
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(DelegateRequestHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages by parsing and verifying the credential and storing it in the wallet

        Parameters:
            payload is dict representing the body of a multisig/incept message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                if "pre" not in msg:
                    logger.error(f"invalid delegate request message, missing pre.  evt=: {msg}")
                    continue

                prefixer = msg["pre"]
                if "payload" not in msg:
                    logger.error(f"invalid delegate request message, missing payload.  evt=: {msg}")
                    continue

                pay = msg["payload"]
                if "ked" not in pay or "delpre" not in pay:
                    logger.error(f"invalid delegate request payload, ked and delpre are required.  payload=: {pay}")
                    continue

                src = prefixer.qb64
                delpre = pay["delpre"]
                if delpre not in self.hby.habs:
                    logger.error(f"invalid delegate request message, no local delpre for evt=: {pay}")
                    continue

                data = dict(
                    src=src,
                    r='/delegate/request',
                    delpre=delpre,
                    ked=pay["ked"]
                )
                if "aids" in pay:
                    data["aids"] = pay["aids"]

                self.notifier.add(attrs=data)
                # if I am multisig, send oobi information of participants in (delegateeeeeeee) mutlisig group to his
                # multisig group

                yield
            yield


def delegateRequestExn(hab, delpre, ked, aids=None):
    data = dict(
        delpre=delpre,
        ked=ked
    )

    if aids is not None:
        data["aids"] = aids

    # Create `exn` peer to peer message to notify other participants UI
    exn = exchanging.exchange(route=DelegateRequestHandler.resource, modifiers=dict(),
                              payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims


class OobiRequestHandler(doing.DoDoer):
    """
    Handler for oobi notification EXN messages

    """
    resource = "/oobis"

    def __init__(self, hby, notifier, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            oobiery (Oobiery) OOBI loader

        """
        self.hby = hby
        self.notifier = notifier
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(OobiRequestHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """

        Handle incoming messages processing new contacts via OOBIs

        Parameters:

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                prefixer = msg["pre"]
                pay = msg["payload"]
                if "dest" not in pay:
                    print(f"invalid oobi request message, missing dest.  evt=: {msg}")
                    continue
                pre = pay["dest"]

                if "oobialias" not in pay:
                    print(f"invalid oobi message, missing oobialias.  evt=: {msg}")
                    continue
                oobialias = pay["oobialias"]

                if "oobi" not in pay:
                    print(f"invalid oobi message, missing oobi.  evt=: {msg}")
                    continue
                oobi = pay["oobi"]

                hab = self.hby.habs[pre]

                src = prefixer.qb64
                obr = basing.OobiRecord(oobialias=oobialias, date=helping.nowIso8601())
                self.hby.db.oobis.pin(keys=(oobi,), val=obr)

                data = dict(
                    r="/oobi",
                    src=src,
                    alias=hab.name,
                    oobialias=oobialias,
                    oobi=oobi
                )

                self.notifier.add(attrs=data)

                yield
            yield


def oobiRequestExn(hab, dest, oobialias, oobi):
    data = dict(
        dest=dest,
        oobialias=oobialias,
        oobi=oobi
    )

    # Create `exn` peer to peer message to notify other participants UI
    exn = exchanging.exchange(route=OobiRequestHandler.resource, modifiers=dict(),
                              payload=data)
    ims = hab.endorse(serder=exn, last=True, pipelined=False)
    del ims[:exn.size]

    return exn, ims
