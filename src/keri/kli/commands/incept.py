# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import os

from hio.base import doing
from hio.core import wiring
from hio.core.tcp import clienting

from ... import help
from ...app import keeping, directing
from ...app.habbing import Habitat
from ...db import basing
from ...db import dbing
from ..common.config import loadConfig

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: incept(args.name, args.file))  # , args.file, args.with_tel
parser.add_argument('--name', '-n', help='Humane reference')
parser.add_argument('--file', '-f', help='Filename to use to create the identifier', default="")


def incept(name, file):
    cfg = loadConfig(file=file)

    print(cfg, cfg.witnesses)

    doers = []
    client = None
    if cfg is not None and cfg.witnesses is not None:
        if len(cfg.witnesses) > 0:
            parts = cfg.witnesses[0].split(":")

            if len(parts) != 2:
                raise Exception("bad config")

            path = os.path.dirname(__file__)
            path = os.path.join(path, 'logs')
            wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='demo', reopen=True,
                                headDirPath=path)
            wireDoer = wiring.WireLogDoer(wl=wl)
            doers.append(wireDoer)

            client = clienting.Client(host=parts[0], port=int(parts[1]), wl=wl)
            clientDoer = doing.ClientDoer(client=client)
            doers.append(clientDoer)

    name = cfg.name

    with basing.openDB(name=name, temp=False) as db, keeping.openKS(name=name, temp=False) as ks:
        hab = Habitat(name=name, ks=ks, db=db, isith=1, icount=1, ncount=1, temp=False)

        doers.append(keeping.KeeperDoer(keeper=hab.ks))
        doers.append(dbing.BaserDoer(baser=hab.db))

        director = InceptDirector(name=name,
                                  pre=hab.kever.prefixer.qb64,
                                  pub=hab.kever.verfers[0].qb64,
                                  hab=hab,
                                  client=client)
        doers.append(director)

        directing.runController(doers=doers)


class InceptDirector(directing.Director):
    """
    See directing.Director for inherited attributes, parameters and methods
    """

    def __init__(self, name, pre, pub, hab, client=None, **kwa):
        super().__init__(hab, client, **kwa)
        self.name = name
        self.pre = pre
        self.pub = pub
        self.tock = 0.0
        self.client = client

    def do(self, tymth=None, tock=0.0, **opts):
        """
        Generator method to run this doer
        Calling this method returns generator
        """
        try:
            self.tock = tock
            (yield self.tock)
            print(self.client, "client")
            if self.client is not None:
                while not self.client.connected:
                    logger.info("%s:\n waiting for connection to remote %s.\n\n",
                                self.hab.pre, self.client.ha)
                    (yield self.tock)

                logger.info("%s:\n connected to %s.\n\n", self.hab.pre, self.client.ha)

            print(f'{self.name} created')
            print(f'Prefix\t\t{self.pre}')
            print(f'Public key\t{self.pub}')
            print()
            print(f'Rotate keys:')
            print(f'kli rotate -n {self.name}')
            print()
            print(f'Issue a verifiable credential:')
            print(f'kli issue -n {self.name} -dsi {self.pre} --lei 506700GE1G29325QX363')
            print()
            os._exit(os.EX_OK)

        except Exception as e:
            logger.info(e)
