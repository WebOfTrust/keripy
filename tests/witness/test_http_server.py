# -*- encoding: utf-8 -*-
"""
tests.witness module

"""

import falcon
import hio
from hio.core import tcp, http

from keri.witness.setup import create


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
    server = create(host, port, app)
    assert isinstance(server, http.Server)

    monkeypatch.setattr(hio.core.tcp, 'ServerTls', MockServerTls)
    monkeypatch.setattr(hio.core.http, 'Server', MockHttpServer)

    server = create(host, port, app, keypath='keypath', certpath='certpath', cafilepath='cafilepath')

    assert isinstance(server, MockHttpServer)
    assert isinstance(server.servant, MockServerTls)




if __name__ == "__main__":
    test_createHttpServer()