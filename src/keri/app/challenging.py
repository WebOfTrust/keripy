# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""
import json

from hio.base import doing
from hio.help import decking


def loadHandlers(hby, exc, mbx, controller):
    """ Load handlers for the peer-to-peer challenge response protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        mbx (Mailboxer): Database for storing mailbox messages
        controller (str): qb64 identifier prefix of controller

    """
    chacha = ChallengeHandler(hby=hby, mbx=mbx, controller=controller)
    exc.addHandler(chacha)


class ChallengeHandler(doing.Doer):
    """  Handle challange response peer to peer `exn` message """

    resource = "/challenge/response"

    def __init__(self, hby, mbx, controller):
        """ Initialize peer to peer challange response messsage """

        self.hby = hby
        self.mbx = mbx
        self.controller = controller
        self.msgs = decking.Deck()
        self.cues = decking.Deck()
        super(ChallengeHandler, self).__init__()

    def do(self, tymth, *, tock=0.0, **opts):
        """  Do override to process incoming challenge responses

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        # start enter context
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:

            while self.msgs:
                msg = self.msgs.popleft()
                payload = msg["payload"]
                signer = msg["pre"]
                words = payload["words"]

                msg = dict(
                    r="/challenge",
                    signer=signer.qb64,
                    words=words
                )

                raw = json.dumps(msg).encode("utf-8")
                self.mbx.storeMsg(self.controller+"/challenge", raw)

                yield self.tock
            yield self.tock

