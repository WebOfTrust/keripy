# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""
import logging
from datetime import datetime

from hio.base import doing

from keri.app import habbing
from keri.app.cli.common.klid_record import KLIDRecord
from keri.core import parsing
# logger = help.ogler.getLogger()
from keri.db import koming

logging.basicConfig(
    filename='klid.log',
    level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s',
)


class Serving(doing.DoDoer):

    def __init__(self, server, doers=None, always=False, **kwa):
        self.server = server
        self.cants = dict()

        self.hab = habbing.Habitat(name='klid', temp=False)

        klid = koming.Komer(db=self.hab.db, schema=KLIDRecord, subkey='klid.')
        klid.put((self.hab.pre,), KLIDRecord(
            started=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        doers = doers if doers is not None else []
        # self.excDoDoer = exchanging.Exchanger(hab=self.hab)

        doers.extend([doing.doify(self.serviceDo)])

        logging.info('super')

        super(Serving, self).__init__(doers=doers, **kwa)

        # behave = exchanging.Behavior(lambda payload, pre, sigers, verfers: None, None)
        # exc.registerBehavior(route="/cmd", behave=behave)


    def serviceDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        while True:
            for ca, ix in list(self.server.ixes.items()):
                logging.info("connection")
                if ix.cutoff:
                    logging.info('closing cutoff')
                    self.server.closeConnection(ca)
                    continue

                if ca not in self.cants:
                    logging.info('command')
                    cant = Commandant(remoter=ix, hab=self.hab, exc=None, doers=self.doers)
                    self.cants[ca] = cant
                    self.extend(doers=[cant])

                if ix.tymeout > 0.0 and ix.tymer.expired:
                    logging.info('closing tymeout')
                    self.closeConnection(ca)

            (yield self.tock)

    def closeConnection(self, ca):
        if ca in self.server.ixes:
            self.server.ixes[ca].serviceSends()
        self.server.removeIx(ca)
        if ca in self.cants:
            self.remove([self.cants[ca]])
            del self.cants[ca]


class Commandant(doing.DoDoer):

    def __init__(self, remoter, hab, exc, doers=None, **kwa):
        self.hab = hab
        self.remoter = remoter
        self.exc = exc
        self.parser = parsing.Parser(ims=self.remoter.rxbs,
                                     framed=True,
                                     kvy=self.hab.kvy)
        # add tvy
        # exc=self.exc)

        doers = doers if doers is not None else []

        doers.extend([doing.doify(self.msgDo)])

        super(Commandant, self).__init__(doers=doers, **kwa)


    def msgDo(self, tymth=None, tock=0.0, **opts):
        """
        Returns:  doifiable Doist compatible generator method
        Usage:
            add result of doify on this method to doers list
        """
        while True:
            if self.parser.ims:
                logging.info("Server received command:\n%s\n...\n", self.parser.ims[:1024])
            yield from self.parser.parsator()
