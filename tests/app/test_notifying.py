# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""
import datetime

import pytest

from keri.app import notifying, habbing
from keri.core import coring
from keri.db import dbing
from keri.help import helping


def test_notice():
    payload = dict(name="John", email="john@example.com", msg="test")

    note = notifying.notice(payload)
    assert note.attrs == payload
    assert note.datetime is not None
    assert note.rid is not None

    note = notifying.notice(payload, dt="2022-07-08T15:01:05.453632")
    assert note.rid is not None
    assert note.datetime == "2022-07-08T15:01:05.453632"
    assert note.attrs == payload

    note = notifying.Notice(raw=note.raw)
    assert note.rid is not None
    assert note.datetime == "2022-07-08T15:01:05.453632"
    assert note.attrs == payload

    note = notifying.Notice(pad=note.pad)
    assert note.rid is not None
    assert note.datetime == "2022-07-08T15:01:05.453632"
    assert note.attrs == payload

    note = notifying.Notice(note=note)
    assert note.rid is not None
    assert note.datetime == "2022-07-08T15:01:05.453632"
    assert note.attrs == payload

    note = notifying.Notice(pad=note.pad)
    assert note.rid is not None

    with pytest.raises(ValueError):
        _ = notifying.Notice(pad=dict())

    _, pad = coring.Saider.saidify(dict(d="", x=1))
    with pytest.raises(ValueError):
        _ = notifying.Notice(pad=pad)

    pad = dict(d="", a={"a": 1})
    _, pad = coring.Saider.saidify(pad)
    note = notifying.Notice(pad=pad)
    assert note.pad['dt'] is not None

    now = helping.nowUTC()
    payload = dict(name="John", email="john@example.com", msg="test")
    note = notifying.notice(payload, dt=now)
    assert note.datetime == now.isoformat()


def test_dictersuber():
    with dbing.openLMDB() as db:
        payload = dict(name="John", email="john@example.com", msg="test")

        dsub = notifying.DicterSuber(db=db, subkey='nots.', sep='/', klas=notifying.Notice)
        note = notifying.notice(payload, dt="2022-07-08T15:01:05.453632")
        dt = note.datetime
        said = note.rid
        assert dsub.put(keys=(dt, said), val=note) is True

        n1 = dsub.get(keys=(dt, said))
        assert n1.rid == note.rid  # crypto equals
        assert n1.read is False

        note.read = True
        assert dsub.put(keys=(dt, said), val=note) is False

        assert dsub.pin(keys=(dt, said), val=note) is True
        n2 = dsub.get(keys=(dt, said))
        assert n2.rid == note.rid  # crypto equals
        assert n2.read is True

        assert dsub.rem(keys=(dt, said)) is True
        n3 = dsub.get(keys=(dt, said))
        assert n3 is None

        note = notifying.notice(attrs=dict(a=1))
        assert dsub.put(keys=(note.datetime, note.rid), val=note) is True
        note = notifying.notice(attrs=dict(a=2))
        assert dsub.put(keys=(note.datetime, note.rid), val=note) is True
        note = notifying.notice(attrs=dict(a=3))
        assert dsub.put(keys=(note.datetime, note.rid), val=note) is True

        res = []
        for (_, _), note in dsub.getItemIter(keys=()):
            res.append(note)

        assert len(res) == 3
        assert res[0].attrs['a'] == 1
        assert res[1].attrs['a'] == 2
        assert res[2].attrs['a'] == 3


def test_noter():
    noter = notifying.Noter()
    assert noter.path.endswith("/not/not")
    noter.reopen()
    noter.close(clear=True)

    noter = notifying.Noter(temp=True)
    assert noter.path.startswith("/tmp")

    payload = dict(name="John", email="john@example.com", msg="test")
    dt = helping.fromIso8601("2022-07-08T15:01:05.453632")
    cig = coring.Cigar(qb64="AA8r1EJXI1sTuI51TXo4F1JjxIJzwPeCxa-Cfbboi7F4Y4GatPEvK629M7G_5c86_Ssvwg8POZWNMV-WreVqBECw")
    note = notifying.notice(payload, dt=dt)
    assert noter.add(note, cig) is True

    notes = noter.getNotes(start="")
    assert len(notes) == 1
    note1, cig1 = notes[0]
    assert note1.rid == note.rid
    assert cig1.qb64 == cig.qb64

    notes = noter.getNotes(start=dt)
    assert len(notes) == 1
    note2, cig2 = notes[0]
    assert note2.rid == note.rid
    assert cig2.qb64 == cig.qb64

    assert noter.rem("ABC") is False
    assert noter.rem(note.rid) is True
    notes = noter.getNotes(start="")
    assert len(notes) == 0

    dt = datetime.datetime.now()
    note = notifying.notice(attrs=dict(a=1))
    assert noter.add(note, cig) is True
    note = notifying.notice(attrs=dict(a=2))
    assert noter.add(note, cig) is True
    note = notifying.notice(attrs=dict(a=3))
    assert noter.add(note, cig) is True

    res = []
    for note in noter.getNoteIter(start=dt):
        res.append(note)

    assert len(res) == 3
    assert res[0][0].attrs['a'] == 1
    assert res[1][0].attrs['a'] == 2
    assert res[2][0].attrs['a'] == 3

    # test paginated iteration
    for i in range(10):
        note = notifying.notice(attrs=dict(a=i))
        assert noter.add(note, cig) is True

    res = []
    for note in noter.getNoteIter(limit=5):
        res.append(note)

    assert len(res) == 5


def test_notifier():
    with habbing.openHby(name="test") as hby:
        notifier = notifying.Notifier(hby=hby)
        assert notifier.signaler is not None
        assert notifier.noter is not None

        assert notifier.add(attrs=dict(a=1, b=2, c=3)) is True
        notes = notifier.getNotes()
        assert len(notes) == 1
        note = notes[0]
        assert note.rid is not None
        assert note.pad['a'] == {'a': 1, 'b': 2, 'c': 3}
        assert note.attrs == {'a': 1, 'b': 2, 'c': 3}
        assert note.read is False

        note1, cig1 = notifier.noter.get(note.rid)
        assert note1.rid == note.rid
        assert note1.read is False

        assert hby.signator.verify(ser=note.raw, cigar=cig1) is True

        assert notifier.mar('ABC') is False
        assert notifier.mar(note.rid) is True
        note = notifier.getNotes()[0]
        assert note.read is True
        assert notifier.mar(note.rid) is False

        assert notifier.rem('ABC') is False
        assert notifier.rem(note.rid) is True
        assert notifier.getNotes() == []

        dt = datetime.datetime.now()
        assert notifier.add(attrs=dict(a=1)) is True
        assert notifier.add(attrs=dict(a=2)) is True
        assert notifier.add(attrs=dict(a=3)) is True

        notes = notifier.getNotes()
        assert len(notes) == 3

        res = []
        for note in notifier.getNoteIter(start=dt):
            res.append(note)

        assert len(res) == 3

    payload = dict(a=1, b=2, c=3)
    dt = helping.fromIso8601("2022-07-08T15:01:05.453632")
    cig = coring.Cigar(qb64="AA8r1EJXI1sTuI51TXo4F1JjxIJzwPeCxa-Cfbboi7F4Y4GatPEvK629M7G_5c86_Ssvwg8POZWNMV-WreVqBECw")
    note = notifying.notice(payload, dt=dt)
    assert notifier.noter.add(note, cig) is True

    assert notifier.mar(note.rid) is False
    assert notifier.rem(note.rid) is True
