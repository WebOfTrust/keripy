# -*- encoding: utf-8 -*-
"""
tests.app.indirecting module

"""
import json
import time

import falcon
from falcon import testing
import hio
import pytest

from hio.core import http
from hio.base import doing, tyming
from hio.help import decking

from keri import kering
from keri import core
from keri.app import indirecting, storing, habbing, agenting
from keri.vdr import viring


def test_mailbox_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    mbx = storing.Mailboxer(temp=True)
    mb = indirecting.MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 1, "/multisig": 0},
                                     retry=1000)

    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    val = next(mbi)
    assert val == b''

    # Store a message for the iter
    msg = dict(i=pre, t="rct")
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store messages for the iter, each next returns all available messages
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    mbx.storeMsg(topic=f"{pre}/multisig", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\nid: 0\nevent: /multisi'
                   b'g\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6d'
                   b'W_GT068", "t": "rct"}\n\n')

    # First stored challenge message will not be found because topics indicates already seen
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /challenge\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx'
                   b'68GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store a message that does not match any topics
    mbx.storeMsg(topic=f"{pre}/replay", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_mailbox_multiple_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    msg = dict(words=["abc", "def"])
    mbx = storing.Mailboxer(temp=True)
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))

    mb = indirecting.MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 0, "/multisig": 0},
                                     retry=1000)
    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    # First stored challenge message will not be found because topics indicates already seen
    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /challenge\nretry: 1000\ndata: {"words": ["abc", "def'
                   b'"]}\n\nid: 1\nevent: /challenge\nretry: 1000\ndata: {"words": ["a'
                   b'bc", "def"]}\n\n')

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_qrymailbox_iter():
    with habbing.openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef') as (hby, hab):
        assert hab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
        icp = hab.makeOwnInception()
        icpSrdr = core.serdering.SerderKERI(raw=icp)
        qry = hab.query(pre=hab.pre, src=hab.pre, route="/mbx")
        srdr = core.serdering.SerderKERI(raw=qry)

        cues = decking.Deck()
        mbx = storing.Mailboxer(temp=True)
        mb = indirecting.QryRpyMailboxIterable(mbx=mbx, cues=cues, said=srdr.said, retry=1000)

        mbi = iter(mb)
        assert mb.iter is None

        #  No cued query response, empty iter
        val = next(mbi)
        assert val == b''
        assert mb.iter is None

        # A cue with the wrong said still returns nothing and recues the cue
        cues.append(dict(kin="stream", serder=icpSrdr))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 1
        assert mb.iter is None
        cues.popleft()

        cues.append(dict(kin="stream", pre=hab.pre, serder=srdr,
                         topics={"/receipt": 0, "/challenge": 1, "/multisig": 0}))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 0
        assert mb.iter is not None

        # And now it behaves just like a standard MailboxIterable
        val = next(mbi)
        assert val == b'retry: 1000\n\n'

        # Store a message for the iter
        msg = dict(i=hab.pre, t="rct")
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        val = next(mbi)
        assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: '
                       b'{"i": "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3", '
                       b'"t": "rct"}\n\n')

        mb.iter.TimeoutMBX = 0  # Force the iter to timeout
        with pytest.raises(StopIteration):
            next(mbi)


def test_wit_query_ends(seeder):
    with habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)
        witDoer = agenting.Receiptor(hby=palHby)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http])

        app = falcon.App()
        query_endpoint = indirecting.QueryEnd(wesHab)
        app.add_route("/query", query_endpoint)
        
        wesClient = testing.TestClient(app)

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            witDoer=witDoer,
            wesClient=wesClient
        )

        doers = wesDoers + [witDoer, doing.doify(wit_querier_test_do, **opts)]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)
        # doist.do(doers=doers)

        assert doist.limit == limit

        doist.exit()


def wit_querier_test_do(tymth=None, tock=0.0, **opts):
    yield tock  # enter context

    wesHab = opts["wesHab"]
    palHby = opts["palHby"]
    witDoer = opts["witDoer"]
    wesClient = opts["wesClient"]

    palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True)

    assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

    witDoer.msgs.append(dict(pre=palHab.pre))
    while not witDoer.cues:
        yield tock

    witDoer.cues.popleft()
    msg = next(wesHab.db.clonePreIter(pre=palHab.pre))

    # Test valid KEL query with 'pre'
    res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre})
    assert res.status_code == 200
    assert res.headers['Content-Type'] == "application/json+cesr"
    assert bytearray(res.content) == bytearray(msg)

    # Test KEL query without 'pre'
    res = wesClient.simulate_get("/query", params={"typ": "kel"})
    assert res.status_code == 400
    assert res.headers['Content-Type'] == "application/json"
    assert "'pre' query param is required" in res.text

    # Test KEL query with 'sn' parameter
    res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 0})
    assert res.status_code == 200
    assert res.headers['Content-Type'] == "application/json+cesr"

    # Test KEL query with non-existant 'sn' parameter
    res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 5})
    assert res.status_code == 400
    assert res.headers['Content-Type'] == "application/json"
    assert "non-existant event at seq-num 5" in res.text

    # Test valid TEL query with 'reg'
    res = wesClient.simulate_get("/query", params={"typ": "tel", "reg": "mock_reg"})
    assert res.status_code == 200
    assert res.headers['Content-Type'] == "application/json+cesr"

    # Test valid TEL query with 'vcid'
    res = wesClient.simulate_get("/query", params={"typ": "tel", "vcid": "mock_vcid"})
    assert res.status_code == 200
    assert res.headers['Content-Type'] == "application/json+cesr"

    # Test TEL query missing both 'reg' and 'vcid'
    res = wesClient.simulate_get("/query", params={"typ": "tel"})
    assert res.status_code == 400
    assert res.headers['Content-Type'] == "application/json"
    assert "Either 'reg' or 'vcid' query param is required for TEL query" in res.text

    # Test invalid 'typ' parameter
    res = wesClient.simulate_get("/query", params={"typ": "invalid"})
    assert res.status_code == 400
    assert res.headers['Content-Type'] == "application/json"
    assert "unkown query type" in res.text

def test_wit_allowlist(seeder):
    with habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wesHab = wesHby.makeHab(name="wes", transferable=False)

        # Allowed (allowlisted) participant hab
        palAllowed = palHby.makeHab(name="palAllowed", wits=[wesHab.pre], transferable=True)
        # Denied (not allowlisted) participant hab
        palDenied = palHby.makeHab(name="palDenied", wits=[wesHab.pre], transferable=True)

        aids = [palAllowed.pre]

        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, aids=aids, tcpPort=5634, httpPort=5644)
        witDoer = agenting.Receiptor(hby=palHby)

        seeder.seedWitEnds(palHby.db, witHabs=[wesHab], protocols=[kering.Schemes.http])

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            witDoer=witDoer,
            palAllowed=palAllowed,
            palDenied=palDenied,
            aids=aids,
        )
        testDo = AllowlistTestDoer(**opts)
        doers = wesDoers + [witDoer, testDo]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        while not testDo.done:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit
        doist.exit()

class AllowlistTestDoer(doing.Doer):
    def __init__(self, **opts):
        self.options = opts
        super(AllowlistTestDoer, self).__init__(**opts)

    def recur(self, tyme=0.0, deeds=None, **kwa):
        wesHab = self.options["wesHab"]
        witDoer = self.options["witDoer"]
        palAllowed = self.options["palAllowed"]
        palDenied = self.options["palDenied"]

        # Trigger witness receipting for both allowed and denied AIDs
        if not any(msg.get('pre') == palAllowed.pre for msg in witDoer.msgs):
            witDoer.msgs.append(dict(pre=palAllowed.pre))
        if not any(msg.get('pre') == palDenied.pre for msg in witDoer.msgs):
            witDoer.msgs.append(dict(pre=palDenied.pre))

        # Wait until both have been processed (one cue each)
        while len(witDoer.cues) < 2:
            yield self.tock

        # Allowed pre should have at least one event stored on witness
        allowed_iter = wesHab.db.clonePreIter(pre=palAllowed.pre)
        allowed_msg = next(allowed_iter)  # should NOT raise
        assert isinstance(allowed_msg, (bytes, bytearray)) and len(allowed_msg) > 0

        # Denied pre should have NO events (StopIteration immediately)
        denied_iter = wesHab.db.clonePreIter(pre=palDenied.pre)
        with pytest.raises(StopIteration):
            next(denied_iter)

        return True

class MockServerTls:
    def __init__(self,  certify, keypath, certpath, cafilepath, port):
        pass


class MockHttpServer:
    def __init__(self, host, port, app, servant=None):
        self.servant = servant


def test_createHttpServer(monkeypatch):
    host = "0.0.0.0"
    port = 5632
    app = falcon.App()
    server = indirecting.createHttpServer(host, port, app)
    assert isinstance(server, http.Server)

    monkeypatch.setattr(hio.core.tcp, 'ServerTls', MockServerTls)
    monkeypatch.setattr(hio.core.http, 'Server', MockHttpServer)

    server = indirecting.createHttpServer(host, port, app, keypath='keypath', certpath='certpath', cafilepath='cafilepath')

    assert isinstance(server, MockHttpServer)
    assert isinstance(server.servant, MockServerTls)


def test_metrics_end():
    """Test MetricsEnd returns Prometheus format metrics"""
    with habbing.openHby(name="test", salt=core.Salter(raw=b'0123456789abcdef').qb64, temp=True) as hby:
        reger = viring.Reger(name=hby.name, db=hby.db, temp=True)

        app = falcon.App()
        metricsEnd = indirecting.MetricsEnd(hby=hby, reger=reger)
        app.add_route("/metrics", metricsEnd)

        client = testing.TestClient(app)

        # Test GET /metrics
        res = client.simulate_get("/metrics")
        assert res.status_code == 200
        assert "text/plain" in res.headers['Content-Type']

        # Verify Prometheus format
        body = res.text
        assert "# HELP keri_escrow_count" in body
        assert "# TYPE keri_escrow_count gauge" in body

        # Verify KEL escrow metrics present
        assert 'keri_escrow_count{type="out_of_order_events",layer="kel"}' in body
        assert 'keri_escrow_count{type="partially_witnessed_events",layer="kel"}' in body
        assert 'keri_escrow_count{type="unverified_receipts",layer="kel"}' in body

        # Verify TEL escrow metrics present
        assert 'keri_escrow_count{type="out_of_order",layer="tel"}' in body
        assert 'keri_escrow_count{type="missing_registry",layer="tel"}' in body

        # Verify registry escrow metrics present
        assert 'keri_escrow_count{type="registry_missing_anchor",layer="registry"}' in body

        # All counts should be 0 for empty db
        lines = [l for l in body.split('\n') if l and not l.startswith('#')]
        for line in lines:
            assert line.endswith(' 0'), f"Expected count 0, got: {line}"

        reger.close()


if __name__ == "__main__":
    test_mailbox_iter()
    test_qrymailbox_iter()
    test_wit_query_ends()
    test_metrics_end()
