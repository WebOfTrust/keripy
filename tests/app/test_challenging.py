# -*- encoding: utf-8 -*-
"""
tests.app.challenging module

"""

from keri.app import ChallengeHandler, Signaler, openHab
from keri.peer import exchange


def test_challenge_handler():
    with openHab(name="test", temp=True) as (hby, hab):

        signaler = Signaler()
        handler = ChallengeHandler(db=hab.db, signaler=signaler)

        payload = dict(i=hab.pre, words=["the", "test", "words", "that", "are", "not", "sufficient"])
        exn, _ = exchange(route="/challenge/response", payload=payload, sender=hab.pre)

        handler.handle(serder=exn)

        assert len(signaler.signals) == 1
        saids = hab.db.reps.get(keys=(hab.pre,))

        assert len(saids) == 1
        assert saids[0].qb64 == exn.said
