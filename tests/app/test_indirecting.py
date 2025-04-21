# -*- encoding: utf-8 -*-
"""
tests.app.indirecting module

"""
import json
import platform
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
        testDo = QueryTestDoer(**opts)
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


class QueryTestDoer(doing.Doer):
    def __init__(self, **opts):
        self.options = opts
        super(QueryTestDoer, self).__init__(**opts)

    def recur(self, tyme=0.0, deeds=None, **kwa):
        wesHab = self.options["wesHab"]
        palHby = self.options["palHby"]
        witDoer = self.options["witDoer"]
        wesClient = self.options["wesClient"]

        palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True)

        assert palHab.pre == "EEWz3RVIvbGWw4VJC7JEZnGCLPYx4-QgWOwAzGnw-g8y"

        witDoer.msgs.append(dict(pre=palHab.pre))
        while not witDoer.cues:
            yield self.tock

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

        return True


class MockServerTls:
    def __init__(self,  certify, keypath, certpath, cafilepath, port):
        pass


class MockHttpServer:
    def __init__(self, host, port, app, servant=None):
        self.servant = servant


def test_createHttpServer(monkeypatch):
    host = "0.0.0.0"
    if platform.system() == "Windows":
        host = "127.0.0.1"
    port = 5632
    app = falcon.App()
    server = indirecting.createHttpServer(host, port, app)
    assert isinstance(server, http.Server)

    monkeypatch.setattr(hio.core.tcp, 'ServerTls', MockServerTls)
    monkeypatch.setattr(hio.core.http, 'Server', MockHttpServer)

    server = indirecting.createHttpServer(host, port, app, keypath='keypath', certpath='certpath', cafilepath='cafilepath')

    assert isinstance(server, MockHttpServer)
    assert isinstance(server.servant, MockServerTls)




if __name__ == "__main__":
    test_mailbox_iter()
    test_qrymailbox_iter()
    test_wit_query_ends()
