# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""

from keri.core import coring


def loadHandlers(db, signaler, exc):
    """ Load handlers for the peer-to-peer challenge response protocol

    Parameters:
        db (Baser): database environment
        signaler (Signaler): Signaler for transient messages for the controller of the agent
        exc (Exchanger): Peer-to-peer message router

    """
    chacha = ChallengeHandler(db=db, signaler=signaler)
    exc.addHandler(chacha)


class ChallengeHandler:
    """  Handle challenge response peer to peer `exn` message """

    resource = "/challenge/response"

    def __init__(self, db, signaler):
        """ Initialize peer to peer challenge response messsage """

        self.db = db
        self.signaler = signaler
        super(ChallengeHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of Challenge response messages

        Parameters:
            serder (Serder): Serder of the exn challenge response message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        payload = serder.ked['a']
        signer = serder.pre
        words = payload["words"]

        msg = dict(
            signer=signer,
            said=serder.said,
            words=words
        )

        # Notify controller of sucessful challenge
        self.signaler.push(msg, topic="/challenge")

        # Log signer against event to track successful challenges with signed response
        self.db.reps.add(keys=(signer,), val=coring.Saider(qb64=serder.said))
