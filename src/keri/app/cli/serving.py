# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.witness module

Witness command line interface
"""

from hio import help
from hio.base import doing
from hio.core.tcp import serving

from keri.core import parsing

logger = help.ogler.getLogger()


class Serving(doing.Doist):
    def __init__(self, doers: [doing.Doer] = None, **kwa):
        doers = doers if doers is not None else []
        self.server = serving.Server(host="", port=5678)
        serverDoer = serving.ServerDoer(server=self.server)
        servant = Servant(server=self.server)
        doers.extend([serverDoer, servant])

        super(Serving, self).__init__(doers=doers, **kwa)


class Servant(doing.DoDoer):
    def __init__(self, server, doers=None, **kwa):
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
                    cant = Commandant(remoter=ix)
                    self.cants[ca] = cant
                    self.extend(doers=[cant])

                if ix.timeout > 0.0 and ix.tymer.expired:
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

    def __init__(self, remoter, doers=None, **kwa):
        self.remoter = remoter
        self.parser = parsing.Parser(ims=self.remoter.rxbs,
                                     framed=True)

        self.extend([self.msgDo])

        super(Commandant, self).__init__(doers=doers, **kwa)
        if self.tymth:
            self.remoter.wind(self.tymth)

    @doing.doize()
    def msgDo(self, tymth=None, tock=0.0, **opts):
        if self.parser.ims:
            logger.info("Server received command:\n%s\n...\n", self.parser.ims[:1024])
        yield from self.parser.parsator()
