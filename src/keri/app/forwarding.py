# -*- encoding: utf-8 -*-
"""
KERI
keri.app.forwarding module

module for enveloping and forwarding KERI message
"""

import random

from hio.base import doing
from hio.help import decking

from keri.app import agenting
from keri.core import coring, eventing
from keri.db import basing


class Postman(doing.DoDoer):
    """
    DoDoer that wraps any KERI event (KEL, TEL, Peer to Peer) in a `fwd` envelope and
    delivers to sends them to one of the target recipient's witnesses for store and forward
    to the intended recipient

    """

    def __init__(self, hab, evts=None, klas=None, **kwa):
        self.hab = hab
        self.evts = evts if evts is not None else decking.Deck()
        self.klas = klas if klas is not None else agenting.HttpWitnesser

        doers = [doing.doify(self.deliverDo)]
        super(Postman, self).__init__(doers=doers, **kwa)

    def deliverDo(self, tymth=None, tock=0.0, **opts):
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
                recp = evt["recipient"]
                tpc = evt["topic"]
                srdr = evt["serder"]
                act = evt["attachment"]

                # TODO: sign the forward message with a SAID signature and
                #  combine it with the provided attachments on the envelope
                #  so the envelope can get verified and opened and this
                #  message can be extracted and stored.
                fwd = forward(pre=recp, topic=tpc, serder=srdr)
                ims = bytearray(fwd.raw)
                ims.extend(act)

                kever = self.hab.kevers[recp]
                wit = random.choice(kever.wits)

                witer = self.klas(hab=self.hab, wit=wit)
                witer.msgs.append(bytearray(ims))  # make a copy
                self.extend([witer])

                while not witer.sent:
                    _ = (yield self.tock)

                yield self.tock

            yield self.tock

    def send(self, recipient, topic, msg):
        """
        Utility function to queue a msg on the Postman's buffer for
        enveloping and forwarding to a witness

        Parameters:
            recipient is identifier prefix qb64 of the intended recipient
            msg is bytes of signed KERI event message to envelope and forward:

        """
        serder = coring.Serder(raw=msg)
        del msg[:serder.size]

        self.evts.append(dict(recipient=recipient, topic=topic, serder=serder, attachment=bytearray(msg)))


def forward(pre, serder, topic=None, version=coring.Version, kind=coring.Serials.json):
    """
    Returns serder of forward event message.
    Utility function to automate creation of forward events.

     Parameters:
        pre is identifier prefix qb64 of recipient of message
        serder is Serder of message to wrap in forward envelope
        version is Version instance
        kind is serialization kind

    """

    vs = coring.Versify(version=version, kind=kind, size=0)
    ilk = eventing.Ilks.fwd

    r = pre + "/" + topic if topic is not None else pre

    ked = dict(v=vs,
               t=ilk,
               r=r,
               a=serder.ked,
               )


    return eventing.Serder(ked=ked)  # return serialized ked

