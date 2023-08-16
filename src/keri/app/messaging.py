# -*- encoding: utf-8 -*-
"""
KERI
keri.app.messaging module

Module for defining the KERI peer to peer instant message protocol with support
for sharing other KERI messages as part of any interaction

"""
from collections import namedtuple

from hio.base import doing
from hio.help import decking

from .. import help
from ..core import coring, eventing
from ..db import dbing, subing
from ..help import helping
from ..kering import MissingSignatureError
from ..peer import exchanging

logger = help.ogler.getLogger()


class MessageBaser(dbing.LMDBer):
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
        self.mdtrs = None
        self.mabls = None
        self.msnds = None
        self.mrcps = None

        super(MessageBaser, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """

        :param kwa:
        :return:
        """
        super(MessageBaser, self).reopen(**kwa)

        # Sub-database holding date if each message exn received keyed by SAID, value is dater received
        self.mexns = subing.CesrSuber(db=self, subkey='mexns.', klas=coring.Dater)

        # Sub-database indexing SAID of message exns keyed by date
        self.mdtrs = subing.CesrIoSetSuber(db=self, subkey='mdtrs.', klas=coring.Saider)

        # Sub-database holding SAIDs of message exns indexed by each label contained in the modifiers of the message
        self.mabls = subing.CesrIoSetSuber(db=self, subkey='mabls.', klas=coring.Saider)

        # Sub-database of message exn messages keyed by qb64 AID of sender
        self.msnds = subing.CesrIoSetSuber(db=self, subkey='msnds.', klas=coring.Saider)

        # Sub-database of message exn messages keyed by qb64 AID of recipient
        self.mrcps = subing.CesrIoSetSuber(db=self, subkey='mrcps.', klas=coring.Saider)

        return self.env


class Messanger:
    """

    Messanger is a class for saving, indexing and loading message exns.  Message exn peer-to-peer
    events have the route '/msg' and are intended to send basic messages between AIDs with support
    for signing and embedding other events as message "attachments"

    """

    def __init__(self, hby, msgdb=None):
        """  Create Messanger for saving, indexing and listing message exns

        Parameters:
            hby (Habery): database environment for exns
            msgdb (MessageBaser): messager database environment
        """
        self.hby = hby
        self.msgdb = msgdb if msgdb is not None else MessageBaser(name=self.hby.name, temp=self.hby.temp)

    def add(self, serder):
        """ Add message exn into message database for indexing

        Parameters:
            serder (Serder): message exn serder to index in the message database

        """
        sender = serder.pre
        ked = serder.ked
        modifiers = ked['q']

        if "i" not in ked:
            raise ValueError("invalid message exn, missing recipient")

        recipient = ked["i"]

        labels = modifiers["labels"] if "labels" in modifiers else []

        dtr = coring.Dater(dts=helping.nowIso8601())
        self.msgdb.mexns.pin(keys=(serder.said,), val=dtr)
        self.msgdb.mdtrs.add(keys=(dtr.qb64,), val=serder.saider)
        self.msgdb.msnds.add(keys=(sender,), val=serder.saider)
        self.msgdb.mrcps.add(keys=(recipient,), val=serder.saider)
        for label in labels:
            self.msgdb.mabls.add(keys=(label,), val=serder.saider)

    def list(self, sender=None, recipient=None):
        """ List received message exn events filtered by recipient QID or send AID, sorted by date received

        Parameters:
            sender (str): qb64 AID of sender of message exn to filter by
            recipient (str):  qb64 AID of recipient of message exn to filter by

        Returns:
            list: list of tuple (serder, pathed signatures) of exn messages sorted by date received

        """
        saids = set()
        if sender is not None:
            for saider in self.msgdb.msnds.getIter(keys=(sender,)):
                saids.add(saider.qb64)
        elif recipient is not None:
            for saider in self.msgdb.mrcps.getIter(keys=(recipient,)):
                saids.add(saider.qb64)
        else:
            for (said,), _ in self.msgdb.mexns.getItemIter(keys=()):
                saids.add(said)

        exns = []
        for (_,), saider in self.msgdb.mdtrs.getItemIter():
            if saider.qb64 in saids:
                exns.append(self.cloneMessage(saider.qb64))

        return exns


def loadHandlers(exc, msgr=None):
    """ Load handlers for the peer-to-peer distributed group multisig protocol

    Parameters:
        exc (Exchanger): Peer-to-peer message router
        msgr (Messanger): Database environment for messaging exn events

    """
    msgr = msgr
    incept = MessagingHandler(msgr=msgr)
    exc.addHandler(incept)


class MessagingHandler(doing.Doer):
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/msg"
    persist = True

    def __init__(self, msgr, **kwa):
        """

        Parameters:
            mbx (Mailboxer) of format str names accepted for offers
            cues (decking.Deck) of outbound cue messages from handler

        """
        self.msgr = msgr
        self.msgs = decking.Deck()
        self.cues = decking.Deck()

        super(MessagingHandler, self).__init__(**kwa)

    def recur(self, tyme):
        if self.msgs:
            msg = self.msgs.popleft()
            serder = msg["serder"]
            self.msgr.add(serder=serder)

        return False


def instantMessageExn(hab, recipient, subject: str, body: str, labels: list = None, attachments: dict = None):
    """  Generate a message exn event with signature and embedded events with transposed pathed attachments.

    Parameters:
        hab (Hab): Hab for the AID sending the message
        recipient (str): qb64 AID recipient of the message
        subject (str): human readable subject line of the message
        body (str): human readable message body
        labels (list): list of str labels to categorize the message by
        attachments (dict): labeled event message streams that are added as embeds to the message with any CESR
                             attachments being added as pathed signature attachments.

    Returns:
        tuple: (message exn serder, CESR message signature and any generated pathed attachments)

    """

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

