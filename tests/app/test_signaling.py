# -*- encoding: utf-8 -*-
"""
tests.app.test_multisig module

"""
import datetime
import time

import falcon
import pytest
from falcon import testing
from hio.base import doing, tyming

from keri.app import signaling
from keri.core import coring
from keri.db import dbing
from keri.help import helping


def test_signal():
    sig = signaling.signal(attrs=dict(a=1), topic="/multisig", ckey="/multisig")

    assert sig is not None
    assert sig.rid is not None
    assert sig.topic == "/multisig"
    assert sig.attrs == dict(a=1)
    assert sig.ckey == "/multisig"

    sig = signaling.signal(dict(b=1), topic="/delegation", dt="2022-07-08T15:01:05.453632")
    assert sig.rid is not None
    assert sig.topic == "/delegation"
    assert sig.attrs == dict(b=1)
    assert sig.ckey is None
    assert sig.dt == "2022-07-08T15:01:05.453632"

    sig = signaling.Signal(pad=dict(c=1), ckey="/notification")
    assert sig.rid is not None
    assert sig.attrs is None
    assert sig.ckey == "/notification"
    assert sig.dt is not None
    assert sig.topic is None

    now = helping.nowUTC()
    payload = dict(name="John", email="john@example.com", msg="test")
    sig = signaling.signal(payload, topic="/d", dt=now)
    assert sig.dt == now.isoformat()

    now = helping.nowUTC()
    sig.dt = now
    assert sig.dt == now.isoformat()


def test_signaler():
    signaler = signaling.Signaler()

    assert signaler.signals is not None

    signaler.push(attrs=dict(a=1, b=2), topic="/delegation")
    assert len(signaler.signals) == 1

    sig = signaler.signals.popleft()
    assert sig.attrs == dict(a=1, b=2)
    assert sig.dt is not None
    assert sig.rid is not None
    assert sig.ckey is None
    assert sig.topic == "/delegation"

    signaler.push(attrs=dict(a=1), topic="/m")
    signaler.push(attrs=dict(a=2), topic="/m", ckey="abc")
    signaler.push(attrs=dict(a=3), topic="/m")
    signaler.push(attrs=dict(a=4), topic="/m", ckey="abc")

    assert len(signaler.signals) == 3

    assert signaler.signals[0].attrs == dict(a=1)
    assert signaler.signals[1].attrs == dict(a=4)
    assert signaler.signals[2].attrs == dict(a=3)

    signaler.signals.clear()
    assert len(signaler.signals) == 0

    signaler.push(attrs=dict(a=1), topic="/m")
    signaler.push(attrs=dict(a=2), topic="/m", ckey="abc")
    signaler.push(attrs=dict(a=3), topic="/m")
    now = datetime.datetime.now() - datetime.timedelta(minutes=11)
    signaler.push(attrs=dict(a=4), topic="/m", ckey="abc", dt=now)

    assert len(signaler.signals) == 3

    limit = 0.5
    tock = 0.025
    doist = doing.Doist(tock=tock, limit=limit, doers=[signaler])
    doist.enter()

    tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

    while not tymer.expired:
        doist.recur()
        time.sleep(doist.tock)

    assert doist.limit == limit

    assert len(signaler.signals) == 2


def test_signal_ends():
    app = falcon.App()
    signaler = signaling.Signaler()

    # change the default timeout so our requests return
    signaling.SignalIterable.TimeoutMBX = 1
    signaler.push(attrs=dict(a=1), topic="/m", dt=helping.fromIso8601("2022-08-11T08:10:05.164948"))
    signaler.push(attrs=dict(a=2), topic="/m", ckey="abc", dt=helping.fromIso8601("2022-08-11T08:10:05.165089"))
    assert len(signaler.signals) == 2

    rid0 = signaler.signals[0].rid
    rid1 = signaler.signals[1].rid

    _ = signaling.loadEnds(app, signals=signaler.signals)

    client = testing.TestClient(app)
    result = client.simulate_get(path="/mbx")

    assert result.status == falcon.HTTP_200
    assert result.text == ('retry: 5000\n'
                           '\n'
                           f'id: {rid0}\n'
                           'retry: 5000\n'
                           'event: /m\n'
                           f'data: {{"i": "{rid0}", "dt": '
                           '"2022-08-11T08:10:05.164948", "r": "/m", "a": {"a": 1}}\n'
                           '\n'
                           f'id: {rid1}\n'
                           'retry: 5000\n'
                           'event: /m\n'
                           f'data: {{"i": "{rid1}", "dt": '
                           '"2022-08-11T08:10:05.165089", "r": "/m", "a": {"a": 2}}\n'
                           '\n')

    assert len(signaler.signals) == 0

    signaler.push(attrs=dict(a=1), topic="/m", dt=helping.fromIso8601("2022-08-11T08:10:05.164948"))
    signaler.push(attrs=dict(a=2), topic="/m", ckey="abc", dt=helping.fromIso8601("2022-08-11T08:10:05.165089"))
    assert len(signaler.signals) == 2

    rid0 = signaler.signals[0].rid
    rid1 = signaler.signals[1].rid

    result = client.simulate_post(path="/mbx")

    assert result.status == falcon.HTTP_200
    assert result.text == ('retry: 5000\n'
                           '\n'
                           f'id: {rid0}\n'
                           'retry: 5000\n'
                           'event: /m\n'
                           f'data: {{"i": "{rid0}", "dt": '
                           '"2022-08-11T08:10:05.164948", "r": "/m", "a": {"a": 1}}\n'
                           '\n'
                           f'id: {rid1}\n'
                           'retry: 5000\n'
                           'event: /m\n'
                           f'data: {{"i": "{rid1}", "dt": '
                           '"2022-08-11T08:10:05.165089", "r": "/m", "a": {"a": 2}}\n'
                           '\n')
    assert len(signaler.signals) == 0
