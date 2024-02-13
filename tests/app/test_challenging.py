# -*- encoding: utf-8 -*-
"""
tests.app.challenging module

"""

from keri.app import habbing, challenging, signaling
from keri.peer import exchanging


def test_challenge_handler():
    with habbing.openHab(name="test", temp=True) as (hby, hab):

        signaler = signaling.Signaler()
        handler = challenging.ChallengeHandler(db=hab.db, signaler=signaler)

        payload = dict(i=hab.pre, words=["the", "test", "words", "that", "are", "not", "sufficient"])
        exn, _ = exchanging.exchange(route="/challenge/response", payload=payload, sender=hab.pre)

        handler.handle(serder=exn)

        assert len(signaler.signals) == 1
        saids = hab.db.reps.get(keys=(hab.pre,))

        assert len(saids) == 1
        assert saids[0].qb64 == exn.said
