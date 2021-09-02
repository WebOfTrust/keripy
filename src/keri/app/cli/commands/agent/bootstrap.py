# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import argparse

import falcon
from hio.base import doing
from hio.core import http

parser = argparse.ArgumentParser()
parser.set_defaults(handler=lambda args: launch())


class Bootstrap:
    def on_post(self, req, rep):
        return falcon.HTTP_200


def launch():
    app = falcon.App()

    app.add_route('/bootstrap', Bootstrap())

    server = http.Server(port=5678, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    doers = [httpServerDoer]
    tock = 0.03125
    doist = doing.Doist(limit=0.0, tock=tock, real=True)
    doist.do(doers=doers)


if __name__ == "__main__":
    print("launching bootstrap")
    launch()
