# -*- encoding: utf-8 -*-
"""
keri.vc.challenging module

"""

from ..core import Diger


def loadHandlers(db, signaler, exc):
    """Registers challenge response handlers with the peer-to-peer message router.

    Creates a ``ChallengeHandler`` instance and adds it to the provided
    ``Exchanger`` so that incoming ``/challenge/response`` ``exn`` messages
    are routed and processed correctly.

    Args:
        db (Baser): Database environment used to persist signed challenge
            responses.
        signaler (Signaler): Signaler used to push transient notifications
            to the agent controller.
        exc (Exchanger): Peer-to-peer message router to which the handler
            is registered.
    """
    chacha = ChallengeHandler(db=db, signaler=signaler)
    exc.addHandler(chacha)


class ChallengeHandler:
    """Handles incoming peer-to-peer ``/challenge/response`` ``exn`` messages.

    On receipt of a valid challenge response, this handler notifies the agent
    controller via the signaler and records the signer's SAID in the database
    to track successfully completed challenges.

    Attributes:
        resource (str): The ``exn`` route this handler is registered for.
        db (Baser): Database environment used to persist challenge records.
        signaler (Signaler): Signaler used to push notifications to the agent
            controller.
    """

    resource = "/challenge/response"

    def __init__(self, db, signaler):
        """Initializes the ChallengeHandler with a database and signaler.

        Args:
            db (Baser): Database environment used to persist signed challenge
                responses.
            signaler (Signaler): Signaler used to push transient notifications
                to the agent controller.
        """
        self.db = db
        self.signaler = signaler
        super(ChallengeHandler, self).__init__()

    def handle(self, serder, attachments=None):
        """Processes an incoming challenge response ``exn`` message.

        Extracts the signer prefix, SAID, and words from the message payload,
        notifies the agent controller of the successful challenge via the
        signaler, and logs the signer's SAID in the database.

        Args:
            serder (Serder): Serder of the incoming ``/challenge/response``
                ``exn`` message. The ``ked['a']`` payload must contain a
                ``words`` field.
            attachments (list[tuple] | None): CESR SAD path attachments as
                ``(pather, SAD)`` tuples. Currently unused. Defaults to None.
        """
        payload = serder.ked['a']
        signer = serder.pre
        words = payload["words"]

        msg = dict(
            signer=signer,
            said=serder.said,
            words=words
        )

        # Notify controller of successful challenge
        self.signaler.push(msg, topic="/challenge")

        # Log signer against event to track successful challenges with signed response
        self.db.reps.add(keys=(signer,), val=Diger(qb64=serder.said))
