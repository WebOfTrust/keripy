# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""
import socket
import time

import pytest

from hio.base import doing, tyming
from hio.core import http
from hio.core.tcp import clienting, serving

from keri import kering, core
from keri.core import coring, serdering
from keri.core.coring import Seqner
from keri.help import nowIso8601
from keri.app import habbing, indirecting, agenting, directing
from keri.db import basing, dbing
from keri.vdr import eventing, viring
from tests.app import recurUntil


def test_receiptor_tocks_are_generator_local():
    with habbing.openHby(name="receiptor-generator-tocks", temp=True) as hby:
        receiptor = agenting.Receiptor(hby=hby)
        seen = []

        def receipt(pre, sn=None, auths=None, tock=0.0):
            seen.append(("receipt", tock))
            yield tock

        def get(pre, sn=None, tock=0.0):
            seen.append(("get", tock))
            yield tock

        receiptor.receipt = receipt
        receiptor.get = get
        receiptor.msgs.append({"pre": "witness"})
        receiptor.gets.append({"pre": "query"})

        witness = receiptor.witDo(tymth=lambda: 0.0, tock=0.011)
        query = receiptor.gitDo(tymth=lambda: 0.0, tock=0.013)

        assert next(witness) == 0.011
        assert next(query) == 0.013
        assert next(witness) == 0.011
        assert next(query) == 0.013
        assert seen == [("receipt", 0.011), ("get", 0.013)]

        witness.close()
        query.close()


def test_witness_receiptor(seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        rctDoer = ReceiptDoer(hby=palHby, wanHab=wanHab, wilHab=wilHab, wesHab=wesHab)

        limit = 5.0
        tock = 0.03125
        doers = wanDoers + wilDoers + wesDoers + [rctDoer]
        doist = doing.Doist(limit=limit, tock=tock, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (rctDoer.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

        assert rctDoer.done is True


class ReceiptDoer(doing.DoDoer):
    """ Test scenario of witness receipts. """

    def __init__(self, hby, wanHab, wilHab, wesHab):
        self.hby = hby
        self.wanHab = wanHab
        self.wilHab = wilHab
        self.wesHab = wesHab

        super(ReceiptDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        palHab = self.hby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre], transferable=True)

        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        witDoer.msgs.append(dict(pre=palHab.pre))
        self.extend([witDoer])

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            if len(wilWigs) == 2 and len(wanWigs) == 2:
                break
            yield self.tock

        # Controller should send endpoints between witnesses.  Check for Endpoints for each other:
        keys = (self.wanHab.pre, kering.Schemes.tcp)
        said = self.wilHab.db.lans.get(keys=keys)
        assert said is not None
        keys = (self.wilHab.pre, kering.Schemes.tcp)
        said = self.wanHab.db.lans.get(keys=keys)
        assert said is not None

        palHab.rotate(adds=[self.wesHab.pre])

        witDoer.msgs.append(dict(pre=palHab.pre, sn=1))

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            wesWigs = self.wesHab.db.getWigs(dgkey)
            if len(wilWigs) == 3 and len(wanWigs) == 3 and len(wesWigs) == 3:
                break
            yield self.tock

        self.remove([witDoer])
        return True


def make_hio_response(status, *, errored=False, error=None):
    """Create a valid HIO HTTP response for messenger tests."""
    return http.clienting.Response(
        version=(1, 1),
        status=status,
        reason=None,
        headers={},
        body=b"",
        data=None,
        request=None,
        errored=errored,
        error=error,
    )


TERMINAL_RESPONSES = (
    make_hio_response(status=204),
    make_hio_response(status=503),
    make_hio_response(status=None, errored=True, error="connection reset"),
)

HTTP_CLOSE_FRAMED_RESPONSE = (b"HTTP/1.1 200 OK\r\n"
                              b"Content-Type: application/json\r\n"
                              b"Connection: close\r\n"
                              b"\r\n"
                              b"{}")


def has_complete_http_request(ims):
    """Whether ims contains one complete Content-Length-framed request."""
    if b"\r\n\r\n" not in ims:
        return False

    head, _, body = bytes(ims).partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
            break
    return len(body) >= length


def close_framed_response_do(server):
    """Create a doer that returns one HTTP response delimited by TCP FIN."""
    @doing.doize(tock=0.03125)
    def respond(tymth=None, tock=0.0, **kwa):
        yield tock

        while not server.ixes:
            yield tock
        remoter = next(iter(server.ixes.values()))

        while not has_complete_http_request(remoter.rxbs):
            yield tock

        remoter.tx(HTTP_CLOSE_FRAMED_RESPONSE)
        while remoter.txbs:
            yield tock

        remoter.shutdownSend()
        return True

    return respond


@pytest.fixture()
def messenger_hab():
    """Provide a fully initialized temporary habitat for messenger tests."""
    with habbing.openHab(name="messenger",
                         salt=b"0123456789abcdef") as (_, hab):
        yield hab


@pytest.fixture()
def running_http_messenger(unused_tcp_port):
    """Run an HTTPMessenger through a managed Doist lifecycle."""
    messenger = agenting.HTTPMessenger(
        hab=None,
        wit="witness",
        url=f"http://127.0.0.1:{unused_tcp_port}",
    )
    connector = messenger.client.connector
    doist = doing.Doist(tock=0.0, doers=[messenger])
    doist.enter()
    assert connector.cs is not None

    try:
        yield messenger, doist
    finally:
        doist.exit()
        assert connector.cs is None


@pytest.fixture()
def running_http_stream_messenger(unused_tcp_port):
    """Run an HTTPStreamMessenger through a managed Doist lifecycle."""
    messenger = agenting.HTTPStreamMessenger(
        hab=None,
        wit="witness",
        url=f"http://127.0.0.1:{unused_tcp_port}",
    )
    connector = messenger.client.connector
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[messenger])
    doist.enter()
    assert connector.cs is not None

    try:
        yield messenger, doist
    finally:
        doist.exit()
        assert connector.cs is None


@pytest.mark.parametrize("klas", [agenting.TCPMessenger,
                                  agenting.TCPStreamMessenger])
def test_tcp_messenger_idle_requires_complete_local_drain(klas, messenger_hab):
    # Construct each TCP messenger type and validate idle or not idle state checks
    messenger = klas(
        hab=messenger_hab,
        wit="witness",
        url="tcp://localhost:5632",
    )

    # should be idle from the get-go
    assert messenger.idle

    # once a message is queued it should not be idle
    msg = bytearray(b"queued")
    messenger.msgs.append(msg)
    assert not messenger.idle

    # in-progress msg means not idle
    messenger.msgs.popleft()
    messenger.messageInProgress = True
    messenger.client = clienting.Client(txbs=bytearray(msg))
    assert not messenger.idle

    # message is still in progress even though txbs is clear, so still not idle
    messenger.client.txbs.clear()
    assert not messenger.idle

    # should be idle even with sent messages remaining
    messenger.sent.append(msg)
    messenger.messageInProgress = False
    assert messenger.idle

    # clearing sent messages does not affect idle status
    messenger.sent.popleft()
    assert messenger.idle

    # on error the messenger is not idle - errors must be handled by the caller
    messenger.error = kering.ClosedError("cut off")
    assert not messenger.idle
    messenger.client.close()


@pytest.mark.parametrize("klas", [agenting.TCPMessenger,
                                  agenting.TCPStreamMessenger])
def test_tcp_messenger_records_cutoff_with_unsent_bytes(
        klas, messenger_hab, unused_tcp_port):
    # run the real server and messenger through the same Doist
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    serverDoer = serving.ServerDoer(server=server)
    messenger = klas(
        hab=messenger_hab,
        wit="witness",
        url=f"tcp://127.0.0.1:{unused_tcp_port}",
    )
    doist = doing.Doist(tock=0.03125, limit=1.0,
                        doers=[serverDoer, messenger])
    doist.enter()

    try:
        # recur until both sides establish the TCP connection
        recurUntil(
            doist,
            condition=lambda: (messenger.client is not None and
                               messenger.client.connected and
                               bool(server.ixes)),
            message="TCP messenger did not connect",
        )

        # queue more bytes than the socket can drain in one recurrence
        client = messenger.client
        client.cs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        msg = bytearray(1024 * 1024)
        messenger.msgs.append(msg)

        doist.recur()
        assert messenger.messageInProgress
        assert client.txbs
        assert messenger.error is None

        # force peer EOF while the messenger still owns unsent bytes
        ca = next(iter(server.ixes))
        server.removeIx(ca)

        # recur until the real client observes cutoff
        recurUntil(
            doist,
            condition=lambda: messenger.error is not None,
            message="TCP cutoff was not detected",
        )

        # cutoff records terminal error and prevents idle
        assert isinstance(messenger.error, kering.ClosedError)
        assert not messenger.messageInProgress
        assert not messenger.idle
    finally:
        # Doist exit closes both HIO transports
        doist.exit()

    assert not server.opened
    assert not client.opened


def test_http_messenger_idle_requires_terminal_response():
    messenger = agenting.HTTPMessenger(
        hab=None,
        wit="witness",
        url="http://localhost:8080",
    )

    # new HTTP messenger starts idle
    assert messenger.idle

    # queued CESR work means not idle
    msg = bytearray(b"queued")
    messenger.msgs.append(msg)
    assert not messenger.idle

    # queued HIO request remains active after msgs is drained
    messenger.msgs.popleft()
    messenger.client.request(method="GET", path="/")
    assert not messenger.idle

    # active request and outbound bytes mean not idle
    messenger.client.requests.popleft()
    messenger.client.waited = True
    messenger.client.connector.txbs.extend(msg)
    assert not messenger.idle

    # outbound bytes alone still mean not idle
    messenger.client.waited = False
    assert not messenger.idle

    # received response remains work until handled
    messenger.client.connector.txbs.clear()
    expected = make_hio_response(status=204)
    messenger.client.responses.append(expected._asdict())
    assert not messenger.idle

    # handled response allows idle while sent retains the cue
    response = messenger.client.respond()
    messenger.sent.append(response)
    assert messenger.idle

    # consuming sent does not change idle
    messenger.sent.popleft()
    assert messenger.idle

    # terminal error prevents idle so the caller must surface it
    messenger.error = kering.ClosedError("cut off")
    assert not messenger.idle
    messenger.client.close()


def test_http_messenger_preserves_terminal_responses(
        running_http_messenger):
    messenger, doist = running_http_messenger
    # queue terminal HIO responses without changing their outcomes
    messenger.client.responses.extend(response._asdict()
                                      for response in TERMINAL_RESPONSES)

    # each recurrence preserves one raw response unchanged
    for expected in TERMINAL_RESPONSES:
        doist.recur()
        response = messenger.sent.popleft()
        assert isinstance(response, http.clienting.Response)
        assert response == expected
        assert messenger.error is None


def test_http_messenger_finalizes_close_framed_response(
        messenger_hab, unused_tcp_port):
    # serve a real response whose body boundary is the peer's TCP FIN
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    serverDoer = serving.ServerDoer(server=server)
    responder = close_framed_response_do(server)
    messenger = agenting.HTTPMessenger(
        hab=messenger_hab,
        wit=messenger_hab.pre,
        url=f"http://127.0.0.1:{unused_tcp_port}",
    )
    doist = doing.Doist(tock=0.03125, limit=1.0,
                        doers=[serverDoer, responder, messenger])
    doist.enter()

    try:
        messenger.msgs.append(bytearray(messenger_hab.makeOwnInception()))

        # cutoff must finalize the active response before error classification
        recurUntil(
            doist,
            condition=lambda: bool(messenger.sent) or messenger.error is not None,
            message="close-framed response did not reach a terminal outcome",
        )

        assert messenger.error is None
        assert messenger.sent[0].status == 200
        assert messenger.idle
    finally:
        doist.exit()


def test_http_stream_messenger_finalizes_close_framed_response(
        messenger_hab, unused_tcp_port):
    # exercise the one-shot messenger against the same real FIN boundary
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    serverDoer = serving.ServerDoer(server=server)
    responder = close_framed_response_do(server)
    messenger = agenting.HTTPStreamMessenger(
        hab=messenger_hab,
        wit=messenger_hab.pre,
        url=f"http://127.0.0.1:{unused_tcp_port}",
        msg=messenger_hab.makeOwnInception(),
    )
    doist = doing.Doist(tock=0.03125, limit=1.0,
                        doers=[serverDoer, responder, messenger])
    doist.enter()

    try:
        # an active response gets its HIO finalization pass before cutoff wins
        recurUntil(doist,
                   condition=lambda: messenger.done,
                   message="HTTP stream messenger did not complete")

        assert messenger.error is None
        assert messenger.rep is not None
        assert messenger.rep.status == 200
    finally:
        doist.exit()


@pytest.mark.parametrize(
    ("request_queued", "unsent", "expected_error"),
    [
        (False, b"", False),
        (True, b"", True),
        (False, b"pending", True),
    ],
    ids=("no-pending-work", "queued-request", "unsent-bytes"),
)
def test_http_messenger_cutoff_depends_on_pending_work(
        request_queued, unsent, expected_error,
        running_http_messenger):
    messenger, doist = running_http_messenger
    connector = messenger.client.connector

    if request_queued:
        messenger.client.request(method="GET", path="/")
    connector.txbs.extend(unsent)
    connector.cutoff = True

    doist.recur()

    if expected_error:
        assert isinstance(messenger.error, kering.ClosedError)
    else:
        assert messenger.error is None
        assert messenger.idle


@pytest.mark.parametrize(
    "response",
    TERMINAL_RESPONSES,
)
def test_http_stream_messenger_preserves_terminal_response(
        response, running_http_stream_messenger):
    messenger, doist = running_http_stream_messenger
    # queue a terminal response without leaving request work
    messenger.client.requests.clear()
    messenger.client.responses.append(response._asdict())

    # terminal response completes the one-shot doer unchanged
    recurUntil(
        doist,
        condition=lambda: messenger.done,
        message="HTTP stream messenger did not complete its response",
    )
    assert messenger.done is True
    assert isinstance(messenger.rep, http.clienting.Response)
    assert messenger.rep == response
    assert messenger.error is None


def test_http_stream_messenger_cutoff_before_response_records_error(
        running_http_stream_messenger):
    messenger, doist = running_http_stream_messenger
    connector = messenger.client.connector
    # cutoff before the one-shot response is terminal
    assert messenger.client.requests
    connector.cutoff = True

    doist.recur()

    assert messenger.done is True
    assert messenger.rep is None
    assert isinstance(messenger.error, kering.ClosedError)


def test_witness_sender(seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        # looks like bad magic value in seeder is causing this to fail
        pdoer = PublishDoer(wanHby, wilHby, wesHby, palHby, seeder)
        directing.runController(doers=[pdoer], expire=10.0)
        assert pdoer.done is True


class PublishDoer(doing.DoDoer):

    def __init__(self, wanHby, wilHby, wesHby, palHby, seeder):
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)
        # Pull the regers out of the Doers so the regers are reused and do not trigger an LMDB error on reuse
        self.regers = dict(
            wan=next(doer.baser for doer in wanDoers if isinstance(doer, basing.BaserDoer)),
            wil=next(doer.baser for doer in wilDoers if isinstance(doer, basing.BaserDoer)),
            wes=next(doer.baser for doer in wesDoers if isinstance(doer, basing.BaserDoer)),
        )

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        self.palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        self.witDoer = agenting.WitnessPublisher(hby=palHby)
        doers = wanDoers + wilDoers + wesDoers + [self.witDoer]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(PublishDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Run the test and exit and remove all child doers when done """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        regser = eventing.incept(pre=self.palHab.pre, baks=[], code=coring.MtrDex.Blake3_256)
        serder = eventing.issue(vcdig=regser.pre,
                                regk="EbA1o_bItVC9i6YB3hr2C3I_Gtqvz02vCmavJNoBA3Jg")
        msg = bytearray(serder.raw)
        msg.extend(core.Counter(core.Codens.SealSourceCouples, count=1,
                                gvrsn=kering.Vrsn_1_0).qb64b)
        msg.extend(Seqner(sn=self.palHab.kever.sn).qb64b)
        msg.extend(self.palHab.kever.serder.saidb)

        self.witDoer.msgs.append(dict(pre=self.palHab.pre, msg=msg))

        while not self.witDoer.cues:
            yield self.tock

        cue = self.witDoer.cues.popleft()
        assert cue["pre"] == self.palHab.pre
        assert cue["msg"] == msg

        for name in ["wes", "wil", "wan"]:
            reger = self.regers[name]
            while True:
                raw = reger.getTvt(dbing.dgKey(serder.preb, serder.saidb))
                if raw:
                    found = serdering.SerderKERI(raw=bytes(raw))
                    if found and serder.pre == found.pre:
                        break
                yield self.tock

        self.remove(self.toRemove)
        return True


def test_witness_inquisitor(mockHelpingNowUTC, seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="qin", salt=core.Salter(raw=b'abcdef0123456789').qb64) as qinHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        palWitDoer = agenting.WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = agenting.WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        qinWitq = agenting.WitnessInquisitor(hby=qinHby)
        # query up a few to make sure it still works
        stamp = nowIso8601()  # need same time stamp or not duplicate
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        palWitq = agenting.WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits)

        limit = 5.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist.do(doers=doers)

        for hab in [palHab, qinHab]:
            kev = hab.kever
            ser = kev.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)

            wigs = wanHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wilHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wesHab.db.getWigs(dgkey)
            assert len(wigs) == 3

        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [qinWitq, palWitq]
        doist.do(doers=doers)

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers
