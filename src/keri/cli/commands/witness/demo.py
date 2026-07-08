# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""

import argparse
import logging
import os

from hio.base import doing
from hio.help import ogler

from ....app import Habery, Configer, setupWitness
from ....core import Salter
from ...common import parseVersion


parser = argparse.ArgumentParser(description="Run a demo collection of witnesses")
parser.add_argument("--loglevel", action="store", required=False, default=os.getenv("KERI_LOG_LEVEL", "CRITICAL"),
                    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is CRITICAL")
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--version', default=None, required=False, type=parseVersion,
                    help='KERI protocol version for the demo witness identifiers, such as 1.0 or 2.0')
parser.set_defaults(handler=lambda args: demo(args))

logger = ogler.getLogger()

def demo(args):
    """
    Run set of three witnesses for demo

    """
    base_formatter = logging.Formatter(
        '%(asctime)s [keri] %(module)s.%(funcName)s-%(lineno)s %(levelname)-8s %(message)s')
    base_formatter.default_msec_format = None
    ogler.baseConsoleHandler.setFormatter(base_formatter)
    ogler.level = logging.getLevelName(args.loglevel.upper())
    logger.setLevel(ogler.level)
    ogler.reopen(name="keri", temp=True, clear=True)

    wancf = Configer(name="wan", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wilcf = Configer(name="wil", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wescf = Configer(name="wes", headDirPath="scripts", temp=False, reopen=True, clear=False)
    witcf = Configer(name="wit", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wubcf = Configer(name="wub", headDirPath="scripts", temp=False, reopen=True, clear=False)
    wyzcf = Configer(name="wyz", headDirPath="scripts", temp=False, reopen=True, clear=False)

    hbykwa = {}
    if args.version is not None:
        hbykwa["version"] = args.version

    wanHby = Habery(name="wan", salt=Salter(raw=b'wann-the-witness').qb64,
                    temp=False, cf=wancf, base=args.base, **hbykwa)
    wilHby = Habery(name="wil", salt=Salter(raw=b'will-the-witness').qb64,
                    temp=False, cf=wilcf, base=args.base, **hbykwa)
    wesHby = Habery(name="wes", salt=Salter(raw=b'wess-the-witness').qb64,
                    temp=False, cf=wescf, base=args.base, **hbykwa)
    witHby = Habery(name="wit", salt=Salter(raw=b'witn-the-witness').qb64,
                    temp=False, cf=witcf, base=args.base, **hbykwa)
    wubHby = Habery(name="wub", salt=Salter(raw=b'wubl-the-witness').qb64,
                    temp=False, cf=wubcf, base=args.base, **hbykwa)
    wyzHby = Habery(name="wyz", salt=Salter(raw=b'wyzs-the-witness').qb64,
                    temp=False, cf=wyzcf, base=args.base, **hbykwa)

    return [InitDoer(wan=wanHby, wil=wilHby, wes=wesHby, wit=witHby, wub=wubHby, wyz=wyzHby,
                     version=args.version)]


class InitDoer(doing.DoDoer):

    def __init__(self, wan, wil, wes, wit, wub, wyz, version=None):
        self.wan = wan
        self.wil = wil
        self.wes = wes
        self.wit = wit
        self.wub = wub
        self.wyz = wyz
        self.version = version

        super(InitDoer, self).__init__(doers=[doing.doify(self.initialize)])

    def initialize(self, tymth, tock=0.0, **kwa):
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        kwa = {}
        if self.version is not None:
            kwa["version"] = self.version

        wanDoers = setupWitness(alias="wan", hby=self.wan, tcpPort=5632, httpPort=5642, **kwa)
        wilDoers = setupWitness(alias="wil", hby=self.wil, tcpPort=5633, httpPort=5643, **kwa)
        wesDoers = setupWitness(alias="wes", hby=self.wes, tcpPort=5634, httpPort=5644, **kwa)

        witDoers = setupWitness(alias="wit", hby=self.wit, tcpPort=5635, httpPort=5645, **kwa)
        wubDoers = setupWitness(alias="wub", hby=self.wub, tcpPort=5636, httpPort=5646, **kwa)
        wyzDoers = setupWitness(alias="wyz", hby=self.wyz, tcpPort=5637, httpPort=5647, **kwa)

        self.extend(wanDoers + wilDoers + wesDoers + witDoers + wubDoers + wyzDoers)
