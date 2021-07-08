# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import datetime
import logging
from dataclasses import dataclass

from hio.base import doing
from hio.core.tcp import serving

from keri.app import habbing
from keri.core import parsing

# logger = help.ogler.getLogger()
from keri.db import koming

logging.basicConfig(
    filename='klid.log',
    level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s',
)


@dataclass
class KLIDRecord:
    started: str
    publicKey: str


class Serving(doing.Doist):

    def __init__(self, publicKey, doers: [doing.Doer] = None, **kwa):
        self.publicKey = publicKey
        logging.debug(f'running with key %s', publicKey)
        self.hab = habbing.Habitat(name='klid', temp=False)

        klid = koming.Komer(db=self.hab.db, schema=KLIDRecord, subkey='klid.')
        klid.put((self.hab.pre,), KLIDRecord(
            publicKey=publicKey,
            started=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        doers = doers if doers is not None else []
        self.server = serving.Server(host='127.0.0.1', port=5678)
        serverDoer = serving.ServerDoer(server=self.server)
        servant = Servant(server=self.server, hab=self.hab)
        doers.extend([serverDoer, servant])

        super(Serving, self).__init__(doers=doers, **kwa)

    def getPIDPath(self):
        return self.hab.db.headDirPath + '/keri'


class Servant(doing.DoDoer):
    def __init__(self, server, hab, doers=None, **kwa):
        self.hab = hab
        self.server = server
        self.cants = dict()
        doers = doers if doers is not None else []
        doers.extend([self.serviceDo])

        super(Servant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.server.wind(self.tymth)

    def wind(self, tymth):
        super(Servant, self).wind(tymth)
        self.server.wind(tymth)

    @doing.doize()
    def serviceDo(self, tymth=None, tock=0.0, **opts):
        while True:
            for ca, ix in list(self.server.ixes.items()):
                if ix.cutoff:
                    self.closeConnection(ca)
                    continue

                if ca not in self.cants:
                    cant = Commandant(remoter=ix, hab=self.hab)
                    self.cants[ca] = cant
                    self.extend(doers=[cant])

                if ix.tymeout > 0.0 and ix.tymer.expired:
                    self.closeConnection(ca)

            yield

    def closeConnection(self, ca):
        if ca in self.server.ixes:
            self.server.ixes[ca].serviceSends()
        self.server.removeIx(ca)
        if ca in self.cants:
            self.remove([self.cants[ca]])
            del self.cants[ca]


class Commandant(doing.DoDoer):

    def __init__(self, remoter, hab, doers=None, **kwa):
        self.hab = hab
        self.remoter = remoter
        self.parser = parsing.Parser(ims=self.remoter.rxbs,
                                     framed=True)

        doers = doers if doers is not None else [self.msgDo]

        super(Commandant, self).__init__(doers=doers, **kwa)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        while True:
            if self.parser.ims:
                logging.info("Server received command:\n%s\n...\n", self.parser.ims[:1024])
            yield from self.parser.parsator()

            # verify command message
            self.hab.verify()

            # process command
