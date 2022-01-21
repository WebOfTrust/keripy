# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""
from hio.base import doing
from hio.help import decking


def loadHandlers(hby, exc, cues=None):
    """ Load handlers for the peer-to-peer challenge response protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        cues (decking.Deck): Outbound messages from handlers

    """
    chacha = ChallengeHandler(hby=hby, cues=cues)
    exc.addHandler(chacha)


class ChallengeHandler(doing.Doer):
    """  Handle challange response peer to peer `exn` message """

    resource = "/challenge/response"

    def __init__(self, hby, cues=None):
        """ Initialize peer to peer challange response messsage """

        self.hby = hby
        self.msgs = decking.Deck()
        self.cues = cues if cues is not None else decking.Deck()
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

                self.cues.append(dict(
                    kin="challenge",
                    signer=signer,
                    words=words
                ))

                yield self.tock
            yield self.tock

