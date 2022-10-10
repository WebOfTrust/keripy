# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""

from hio.base import doing
from hio.help import decking


def loadHandlers(db, signaler, exc):
    """ Load handlers for the peer-to-peer challenge response protocol

    Parameters:
        db (Baser): database environment
        signaler (Signaler): Signaler for transient messages for the controller of the agent
        exc (Exchanger): Peer-to-peer message router

    """
    chacha = ChallengeHandler(db=db, signaler=signaler)
    exc.addHandler(chacha)


class ChallengeHandler(doing.Doer):
    """  Handle challange response peer to peer `exn` message """

    resource = "/challenge/response"
    persist = True

    def __init__(self, db, signaler):
        """ Initialize peer to peer challange response messsage """

        self.db = db
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

                serder = msg["serder"]

                msg = dict(
                    signer=signer.qb64,
                    said=serder.said,
                    words=words
                )

                # Notify controller of sucessful challenge
                self.signaler.push(msg, topic="/challenge")

                # Log signer against event to track successful challenges with signed response
                self.db.reps.add(keys=(signer.qb64,), val=serder.saider)

                yield self.tock
            yield self.tock
