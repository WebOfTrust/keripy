# -*- encoding: utf-8 -*-
"""
KERI
keri.app.forwarding module

module for enveloping and forwarding KERI message
"""
import random
from ordered_set import OrderedSet as oset

from hio.base import doing
from hio.help import decking, ogler

from keri import kering
from keri.app import agenting
from keri.app.habbing import GroupHab
from keri.core import coring, eventing, serdering
from keri.db import dbing
from keri.kering import Roles
from keri.peer import exchanging

logger = ogler.getLogger()


class Poster(doing.DoDoer):
    """
    DoDoer that wraps any KERI event (KEL, TEL, Peer to Peer) in a /fwd `exn` envelope and
    delivers them to one of the target recipient's witnesses for store and forward
    to the intended recipient

    """

    def __init__(self, hby, mbx=None, evts=None, cues=None, **kwa):
        self.hby = hby
        self.mbx = mbx
        self.evts = evts if evts is not None else decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()

        doers = [doing.doify(self.deliverDo)]
        super(Poster, self).__init__(doers=doers, **kwa)

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
                atc = evt["attachment"] if "attachment" in evt else None

                # Get the hab of the sender
                if "hab" in evt:
                    hab = evt["hab"]
                else:
                    hab = self.hby.habs[src]

                ends = hab.endsFor(recp)
                try:
                    # If there is a controller, agent or mailbox in ends, send to all
                    if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                        for role in (Roles.controller, Roles.agent, Roles.mailbox):
                            if role in ends:
                                if role == Roles.mailbox:
                                    yield from self.forward(hab, ends[role], recp=recp, serder=srdr, atc=atc, topic=tpc)
                                else:
                                    yield from self.sendDirect(hab, ends[role], serder=srdr, atc=atc)

                    # otherwise send to one witness
                    elif Roles.witness in ends:
                        yield from self.forwardToWitness(hab, ends[Roles.witness], recp=recp, serder=srdr, atc=atc, topic=tpc)
                    else:
                        logger.info(f"No end roles for {recp} to send evt={recp}")
                        continue
                except kering.ConfigurationError as e:
                    logger.error(f"Error sending to {recp} with ends={ends}.  Err={e}")
                    continue
                # Get the kever of the recipient and choose a witness

                self.cues.append(dict(dest=recp, topic=tpc, said=srdr.said))

                yield self.tock

            yield self.tock

    def send(self, dest, topic, serder, src=None, hab=None, attachment=None):
        """
        Utility function to queue a msg on the Poster's buffer for
        enveloping and forwarding to a witness

        Parameters:
            src (str): qb64 identifier prefix of sender
            hab (Hab): Sender identifier habitat
            dest (str) is identifier prefix qb64 of the intended recipient
            topic (str): topic of message
            serder (Serder) KERI event message to envelope and forward:
            attachment (bytes): attachment bytes

        """
        src = src if src is not None else hab.pre

        evt = dict(src=src, dest=dest, topic=topic, serder=serder)
        if attachment is not None:
            evt["attachment"] = attachment
        if hab is not None:
            evt["hab"] = hab

        self.evts.append(evt)

    def sent(self, said):
        """ Check if message with given SAID was sent

        Parameters:
            said (str): qb64 SAID of message to check for
        """

        for cue in self.cues:
            if cue["said"] == said:
                return True

        return False

    def sendEvent(self, hab, fn=0):
        """ Returns generator for sending event and waiting until send is complete """
        # Send KEL event for processing
        icp = self.hby.db.cloneEvtMsg(pre=hab.pre, fn=fn, dig=hab.kever.serder.saidb)
        ser = serdering.SerderKERI(raw=icp)
        del icp[:ser.size]

        sender = hab.mhab.pre if isinstance(hab, GroupHab) else hab.pre
        self.send(src=sender, dest=hab.kever.delegator, topic="delegate", serder=ser, attachment=icp)
        while True:
            if self.cues:
                cue = self.cues.popleft()
                if cue["said"] == ser.said:
                    break
                else:
                    self.cues.append(cue)
            yield self.tock

    def sendDirect(self, hab, ends, serder, atc):
        for ctrl, locs in ends.items():
            witer = agenting.messengerFrom(hab=hab, pre=ctrl, urls=locs)

            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)

            witer.msgs.append(bytearray(msg))  # make a copy
            self.extend([witer])

            while not witer.idle:
                _ = (yield self.tock)

            self.remove([witer])

    def forward(self, hab, ends, recp, serder, atc, topic):
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{recp}/{topic}".encode("utf-8"), msg=msg)
            return

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))
        msg = bytearray()
        msg.extend(introduce(hab, mbx))
        # create the forward message with payload embedded at `a` field

        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchanging.exchange(route='/fwd', modifiers=dict(pre=recp, topic=topic),
                                       payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)

        # Transpose the signatures to point to the new location
        witer = agenting.messengerFrom(hab=hab, pre=mbx, urls=mailbox)
        msg.extend(ims)
        msg.extend(atc)

        witer.msgs.append(bytearray(msg))  # make a copy
        self.extend([witer])

        while not witer.idle:
            _ = (yield self.tock)

    def forwardToWitness(self, hab, ends, recp, serder, atc, topic):
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{recp}/{topic}".encode("utf-8"), msg=msg)
            return

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))
        msg = bytearray()
        msg.extend(introduce(hab, mbx))
        # create the forward message with payload embedded at `a` field

        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchanging.exchange(route='/fwd', modifiers=dict(pre=recp, topic=topic),
                                       payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)

        # Transpose the signatures to point to the new location
        witer = agenting.messengerFrom(hab=hab, pre=mbx, urls=mailbox)
        msg.extend(ims)
        msg.extend(atc)

        witer.msgs.append(bytearray(msg))  # make a copy
        self.extend([witer])

        while not witer.idle:
            _ = (yield self.tock)


class StreamPoster:
    """
    DoDoer that wraps any KERI event (KEL, TEL, Peer to Peer) in a /fwd `exn` envelope and
    delivers them to one of the target recipient's witnesses for store and forward
    to the intended recipient

    """

    def __init__(self, hby, recp, src=None, hab=None, mbx=None, topic=None, headers=None, **kwa):
        if hab is not None:
            self.hab = hab
        else:
            self.hab = hby.habs[src]

        self.hby = hby
        self.hab = hab
        self.recp = recp
        self.src = src
        self.messagers = []
        self.mbx = mbx
        self.topic = topic
        self.headers = headers
        self.evts = decking.Deck()

    def deliver(self):
        """
        Returns:  doifiable Doist compatible generator method that processes
                   a queue of messages and envelopes them in a `fwd` message
                   and sends them to one of the witnesses of the recipient for
                   store and forward.

        Usage:
            add result of doify on this method to doers list
        """
        msg = bytearray()

        while self.evts:
            evt = self.evts.popleft()

            serder = evt["serder"]
            atc = evt["attachment"] if "attachment" in evt else b''

            msg.extend(serder.raw)
            msg.extend(atc)

        if len(msg) == 0:
            return []

        ends = self.hab.endsFor(self.recp)
        try:
            # If there is a controller or agent in ends, send to all
            if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                for role in (Roles.controller, Roles.agent, Roles.mailbox):
                    if role in ends:
                        if role == Roles.mailbox:
                            return self.forward(self.hab, ends[role], msg=msg, topic=self.topic)
                        else:
                            return self.sendDirect(self.hab, ends[role], msg=msg)
            # otherwise send to one witness
            elif Roles.witness in ends:
                return self.forward(self.hab, ends[Roles.witness], msg=msg, topic=self.topic)

            else:
                logger.info(f"No end roles for {self.recp} to send evt={self.recp}")
                return []

        except kering.ConfigurationError as e:
            logger.error(f"Error sending to {self.recp} with ends={ends}.  Err={e}")
            return []

    def send(self, serder, attachment=None):
        """
        Utility function to queue a msg on the Poster's buffer for
        enveloping and forwarding to a witness

        Parameters:
            serder (Serder) KERI event message to envelope and forward:
            attachment (bytes): attachment bytes

        """
        ends = self.hab.endsFor(self.recp)
        try:
            # If there is a controller, agent or mailbox in ends, send to all
            if {Roles.controller, Roles.agent, Roles.mailbox} & set(ends):
                for role in (Roles.controller, Roles.agent, Roles.mailbox):
                    if role in ends:
                        if role == Roles.mailbox:
                            serder, attachment = self.createForward(self.hab, serder=serder, ends=ends,
                                                                    atc=attachment, topic=self.topic)

            # otherwise send to one witness
            elif Roles.witness in ends:
                serder, attachment = self.createForward(self.hab, ends=ends, serder=serder,
                                                        atc=attachment, topic=self.topic)
            else:
                logger.info(f"No end roles for {self.recp} to send evt={self.recp}")
                raise kering.ValidationError(f"No end roles for {self.recp} to send evt={self.recp}")
        except kering.ConfigurationError as e:
            logger.error(f"Error sending to {self.recp} with ends={ends}.  Err={e}")
            raise kering.ValidationError(f"Error sending to {self.recp} with ends={ends}.  Err={e}")

        evt = dict(serder=serder)
        if attachment is not None:
            evt["attachment"] = attachment

        self.evts.append(evt)

    def sendDirect(self, hab, ends, msg):
        for ctrl, locs in ends.items():
            self.messagers.append(agenting.streamMessengerFrom(hab=hab, pre=ctrl, urls=locs, msg=msg,
                                                               headers=self.headers))

        return self.messagers

    def createForward(self, hab, ends, serder, atc, topic):
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            msg = bytearray(serder.raw)
            if atc is not None:
                msg.extend(atc)
            self.mbx.storeMsg(topic=f"{self.recp}/{topic}".encode("utf-8"), msg=msg)
            return None, None

        # Its not us, randomly select a mailbox and forward it on
        evt = bytearray(serder.raw)
        evt.extend(atc)
        fwd, atc = exchanging.exchange(route='/fwd', modifiers=dict(pre=self.recp, topic=topic),
                                       payload={}, embeds=dict(evt=evt), sender=hab.pre)
        ims = hab.endorse(serder=fwd, last=False, pipelined=False)
        return fwd, ims + atc

    def forward(self, hab, ends, msg, topic):
        # If we are one of the mailboxes, just store locally in mailbox
        owits = oset(ends.keys())
        if self.mbx and owits.intersection(hab.prefixes):
            self.mbx.storeMsg(topic=f"{self.recp}/{topic}".encode("utf-8"), msg=msg)
            return []

        # Its not us, randomly select a mailbox and forward it on
        mbx, mailbox = random.choice(list(ends.items()))
        ims = bytearray()
        ims.extend(introduce(hab, mbx))
        ims.extend(msg)

        self.messagers.append(agenting.streamMessengerFrom(hab=hab, pre=mbx, urls=mailbox, msg=bytes(ims)))
        return self.messagers


class ForwardHandler:
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

    def __init__(self, hby, mbx):
        """

        Parameters:
            hby (Habery): database environment
            mbx (Mailboxer): message storage for store and forward

        """
        self.hby = hby
        self.mbx = mbx

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event

        """

        embeds = serder.ked['e']
        modifiers = serder.ked['q'] if 'q' in serder.ked else {}

        recipient = modifiers["pre"]
        topic = modifiers["topic"]
        resource = f"{recipient}/{topic}"

        pevt = bytearray()
        for pather, atc in attachments:
            ked = pather.resolve(embeds)
            sadder = coring.Sadder(ked=ked, kind=eventing.Serials.json)
            pevt.extend(sadder.raw)
            pevt.extend(atc)

        if not pevt:
            print("error with message, nothing to forward", serder.ked)
            return

        self.mbx.storeMsg(topic=resource, msg=pevt)


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
        for msg in hab.db.cloneDelegation(hab.kever):
            msgs.extend(msg)
        msgs.extend(hab.replyEndRole(cid=hab.pre))
    return msgs
