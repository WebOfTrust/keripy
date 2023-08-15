# -*- encoding: utf-8 -*-
"""
KERI
keri.app.messaging module

Module for defining the KERI peer to peer instant message protocol with support
for sharing other KERI messages as part of any interaction

"""
from pprint import pprint

from hio.base import doing
from hio.help import decking

from .. import help
from ..core import coring
from ..db import dbing, subing
from ..help import helping
from ..peer import exchanging

logger = help.ogler.getLogger()


class Messager(dbing.LMDBer):
    """
    Messages stores KERI `exn` instant messaging protocol messages.  These messages may conain other KERI messages
    as attachments and are intended to be read and dismissed by the controller of the recipient AID.

    """
    TailDirPath = "keri/msg"
    AltTailDirPath = ".keri/msg"
    TempPrefix = "keri_msg_"

    def __init__(self, name="msg", headDirPath=None, reopen=True, **kwa):
        """

        Parameters:
            headDirPath:
            perm:
            reopen:
            kwa:
        """
        self.mexns = None
        self.mabls = None
        self.msnds = None
        self.mrcps = None

        super(Messager, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(Messager, self).reopen(**kwa)

        # Sub-database holding date if each message exn received keyed by SAID, value is dater received
        self.mexns = subing.CesrSuber(db=self, subkey='mexns.', klas=coring.Dater)

        # Sub-database holding SAIDs of message exns indexed by each label contained in the modifiers of the message
        self.mabls = subing.CesrIoSetSuber(db=self, subkey='mabls', klas=coring.Saider)

        # Sub-database of message exn messages keyed by qb64 AID of sender
        self.msnds = subing.CesrIoSetSuber(db=self, subkey='mabls', klas=coring.Saider)

        # Sub-database of message exn messages keyed by qb64 AID of recipient
        self.mrcps = subing.CesrIoSetSuber(db=self, subkey='mabls', klas=coring.Saider)

        return self.env


def loadHandlers(hby, exc, msgr):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        msgr (Messager): Database environment for messaging exn events

    """
    incept = MessagingHandler(hby=hby, msgr=msgr)
    exc.addHandler(incept)


class MessagingHandler(doing.Doer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/msg"
    persist = True

    def __init__(self, hby, msgr, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.hby = hby
        self.msgr = msgr
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MessagingHandler, self).__init__(**kwa)

    def recur(self, tyme):
        if self.msgs:
            msg = self.msgs.popleft()
            serder = msg["serder"]
            sender = serder.pre
            ked = serder.ked
            modifiers = ked['q']

            if "i" not in ked:
                raise ValueError("invalid message exn, missing recipient")

            recipient = ked["i"]

            labels = modifiers["labels"] if "labels" in modifiers else []

            dtr = coring.Dater(dts=helping.nowIso8601())
            self.msgr.mexns.pin(keys=(serder.said,), val=dtr)
            self.msgr.msnds.add(keys=(sender,), val=serder.saider)
            self.msgr.mrcps.add(keys=(recipient,), val=serder.saider)
            for label in labels:
                self.msgr.mabls.add(keys=(label,), val=serder.saider)

        return False


def instantMessageExn(hab, recipient, subject: str, body: str, labels: list = None, attachments: dict = None):

    labels = labels if labels is not None else list()
    attachments = attachments if attachments is not None else dict()

    end = bytearray()
    e = dict()
    for label, msg in attachments.items():
        serder = coring.Serder(raw=msg)
        e[label] = serder.ked
        atc = bytes(msg[serder.size:])

        pathed = bytearray()
        pather = coring.Pather(path=["e", label])
        pathed.extend(pather.qb64b)
        pathed.extend(atc)
        end.extend(coring.Counter(code=coring.CtrDex.PathedMaterialQuadlets,
                                  count=(len(pathed) // 4)).qb64b)
        end.extend(pathed)

    data = dict(
        s=subject,
        b=body
    )

    # Create `exn` peer to peer message to notify other participants UI
    exn = exchanging.exchange(route=MessagingHandler.resource, sender=hab.pre,
                              recipient=recipient, modifiers=dict(labels=labels),
                              payload=data, embeds=e)
    ims = hab.endorse(serder=exn, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims

