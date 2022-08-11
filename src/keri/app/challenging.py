# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""

from hio.base import doing
from hio.help import decking


def loadHandlers(signaler, exc):
    """ Load handlers for the peer-to-peer challenge response protocol

    Parameters:
        signaler (Signaler): Signaler for transient messages for the controller of the agent
        exc (Exchanger): Peer-to-peer message router

    """
    chacha = ChallengeHandler(signaler=signaler)
    exc.addHandler(chacha)


class ChallengeHandler(doing.Doer):
    """  Handle challange response peer to peer `exn` message """

    resource = "/challenge/response"

    def __init__(self, signaler):
        """ Initialize peer to peer challange response messsage """

        self.msgs = decking.Deck()
        self.cues = decking.Deck()
        self.signaler = signaler
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
                    signer=signer.qb64,
                    words=words
                )

                self.signaler.push(msg, topic="/challenge")

                yield self.tock
            yield self.tock

