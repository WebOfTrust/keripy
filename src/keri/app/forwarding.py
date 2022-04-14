# -*- encoding: utf-8 -*-
"""
KERI
keri.app.forwarding module

module for enveloping and forwarding KERI message
"""

import random

from hio.base import doing
from hio.help import decking

from keri import kering
from keri.app import agenting
from keri.core import coring, eventing
from keri.db import dbing
from keri.peer import exchanging


class Postman(doing.DoDoer):
    """
    DoDoer that wraps any KERI event (KEL, TEL, Peer to Peer) in a /fwd `exn` envelope and
    delivers to sends them to one of the target recipient's witnesses for store and forward
    to the intended recipient

    """

    def __init__(self, hby, evts=None, cues=None, klas=None, **kwa):
        self.hby = hby
        self.evts = evts if evts is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.klas = klas if klas is not None else agenting.HttpWitnesser

        doers = [doing.doify(self.deliverDo)]
        super(Postman, self).__init__(doers=doers, **kwa)

    def deliverDo(self, tymth=None, tock=0.0):
        """
        Returns:  doifiable Doist compatible generator method that processes
                   a queue of messages and envelopes them in a `fwd` message
                   and sends them to one of the witnesses of the recipient for
                   store and forward.

        Usage:
            add result of doify on this method to doers list
        """

        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.evts:
                evt = self.evts.popleft()
                src = evt["src"]
                recp = evt["dest"]
                tpc = evt["topic"]
                srdr = evt["serder"]

                # Get the hab of the sender
                hab = self.hby.habs[src]

                # Get the kever of the recipient and choose a witness
                wit = agenting.mailbox(hab, recp)
                if not wit:
                    continue

                msg = bytearray()
                msg.extend(introduce(hab, wit))
                # Transpose the signatures to point to the new location

                # create the forward message with payload embedded at `a` field
                fwd = exchanging.exchange(route='/fwd', modifiers=dict(pre=recp, topic=tpc),
                                          payload=srdr.ked)
                ims = hab.endorse(serder=fwd, last=True, pipelined=False)

                if "attachment" in evt:
                    atc = bytearray()
                    attachment = evt["attachment"]
                    pather = coring.Pather(path=["a"])
                    atc.extend(pather.qb64b)
                    atc.extend(attachment)
                    ims.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                              count=(len(atc) // 4)).qb64b)
                    ims.extend(atc)

                witer = agenting.witnesser(hab=hab, wit=wit)

                msg.extend(ims)
                witer.msgs.append(bytearray(msg))  # make a copy
                self.extend([witer])

                while not witer.sent:
                    _ = (yield self.tock)

                self.cues.append(dict(dest=recp, topic=tpc, said=srdr.said))
                yield self.tock

            yield self.tock

    def send(self, src, dest, topic, serder, attachment=None):
        """
        Utility function to queue a msg on the Postman's buffer for
        enveloping and forwarding to a witness

        Parameters:
            src (str): qb64 identifier prefix of sender
            dest (str) is identifier prefix qb64 of the intended recipient
            topic (str): topic of message
            serder (Serder) KERI event message to envelope and forward:
            attachment (bytes): attachment bytes

        """

        evt = dict(src=src, dest=dest, topic=topic, serder=serder)
        if attachment is not None:
            evt["attachment"] = attachment

        self.evts.append(evt)

    def sendEvent(self, hab, fn=0):
        """ Returns generator for sending event and waiting until send is complete """
        # Send KEL event for processing
        icp = self.hby.db.cloneEvtMsg(pre=hab.pre, fn=fn, dig=hab.kever.serder.saidb)
        ser = coring.Serder(raw=icp)
        del icp[:ser.size]
        self.send(src=hab.pre, dest=hab.kever.delegator, topic="delegate", serder=ser, attachment=icp)
        while True:
            if self.cues:
                cue = self.cues.popleft()
                if cue["said"] == ser.said:
                    break
                else:
                    self.cues.append(cue)
            yield self.tock


class ForwardHandler(doing.Doer):
    """
    Handler for forward `exn` messages used to envelope other KERI messages intended for another recipient.
    This handler acts as a mailbox for other identifiers and stores the messages in a local database.

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/fwd",
           "q": {
              "pre": "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",
              "topic": "delegate"
            }
           "a": '{
              "v":"KERI10JSON000154_",
              "t":"dip",
              "d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI",
              "i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI",
              "s":"0",
              "kt":"1",
              "k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],
              "n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU",
              "bt":"0",
              "b":[],
              "c":[],
              "a":[],
              "di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"
           }
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/fwd"

    def __init__(self, hby, mbx, cues=None, **kwa):
        """

        Parameters:
            mbx (Mailboxer): message storage for store and forward
            formats (list) of format str names accepted for offers
            cues (Optional(decking.Deck)): outbound cue messages

        """
        self.hby = hby
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
        self.mbx = mbx

        super(ForwardHandler, self).__init__(**kwa)

    def do(self, tymth, tock=0.0, **opts):
        """ Handle incoming messages by parsing and verifiying the credential and storing it in the wallet

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Messages:
            payload is dict representing the body of a /credential/issue message
            pre is qb64 identifier prefix of sender
            sigers is list of Sigers representing the sigs on the /credential/issue message
            verfers is list of Verfers of the keys used to sign the message

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                modifiers = msg["modifiers"]
                attachments = msg["attachments"]

                recipient = modifiers["pre"]
                topic = modifiers["topic"]
                resource = f"{recipient}/{topic}"

                pevt = bytearray()
                for pather, atc in attachments:
                    ked = pather.resolve(payload)
                    sadder = coring.Sadder(ked=ked, kind=eventing.Serials.json)
                    pevt.extend(sadder.raw)
                    pevt.extend(atc)

                if not pevt:
                    print("error with message, nothing to forward", msg)
                    continue

                self.mbx.storeMsg(topic=resource, msg=pevt)
                yield self.tock

            yield self.tock


def introduce(hab, wit):
    """ Clone and return hab KEL if lastest event has not been receipted by wit

    Check to see if the target witness has already provided a receipt for the latest event
    for the identifier of hab, clone the KEL and return it as a bytearray so it can be sent to
    the target.

    Parameters:
        hab (Hab): local environment for the identifier to propagate
        wit (str): qb64 identifier prefix of the recipient of KEL if not already receipted

    Returns:
        bytearray: cloned KEL of hab

    """
    msgs = bytearray()
    if wit in hab.kever.wits:
        return msgs

    iserder = hab.kever.serder
    witPrefixer = coring.Prefixer(qb64=wit)
    dgkey = dbing.dgKey(wit, iserder.said)
    found = False
    if witPrefixer.transferable:  # find if have rct from other pre for own icp
        for quadruple in hab.db.getVrcsIter(dgkey):
            if bytes(quadruple).decode("utf-8").startswith(hab.pre):
                found = True  # yes so don't send own inception
    else:  # find if already rcts of own icp
        for couple in hab.db.getRctsIter(dgkey):
            if bytes(couple).decode("utf-8").startswith(hab.pre):
                found = True  # yes so don't send own inception

    if not found:  # no receipt from remote so send own inception
        # no vrcs or rct of own icp from remote so send own inception
        for msg in hab.db.clonePreIter(pre=hab.pre):
            msgs.extend(msg)

        msgs.extend(hab.replyEndRole(cid=hab.pre, role=kering.Roles.witness))

    return msgs

