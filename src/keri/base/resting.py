# -*- encoding: utf-8 -*-
"""
KERI


"""


import falcon

from ioflo.aid import getConsole
from ioflo.aid import odict
from ioflo.aio.http import Valet
from ioflo.base import doify


from .. import kering
from ..end import ending

console = getConsole()

"""
Usage pattern

frame server
    do keri server open at enter
    do keri server service
    do keri server close at exit
"""


@doify('KeriServerOpen', ioinits=odict(
                                        valet="",
                                        test="",
                                        port=odict(ival=8080),
                                        ))
def keriServerOpen(self):
    """
    Setup and open a rest server

    Ioinit attributes
        valet is Valet instance (wsgi server)
        port is server port

    Context: enter

    Example:
        do leopy server open at enter
    """
    port = int(self.port.value)

    app = falcon.API(middleware=[ending.CORSMiddleware()])
    ending.loadEnds(app, store=self.store)

    self.valet.value = Valet(
                            port=port,
                            bufsize=131072,
                            wlog=None,
                            store=self.store,
                            app=app,
                            timeout=1.0,
                            )

    console.terse("IP Address {}\n".format(self.valet.value.servant.ha))

    result = self.valet.value.servant.reopen()

    if not result:
        console.terse("Error opening server '{0}' at '{1}'\n".format(
            self.valet.name,
            self.valet.value.servant.ha))
        return

    console.concise("Opened server '{0}' at '{1}'\n".format(
        self.valet.name,
        self.valet.value.servant.ha, ))


@doify('KeriServerService', ioinits=odict(valet=""))
def keriServerService(self):
    """
    Service server given by valet

    Ioinit attributes:
        valet is a Valet instance

    Context: recur

    Example:
        do leopy server service
    """
    if self.valet.value:
        self.valet.value.serviceAll()


@doify('KeriServerClose', ioinits=odict(valet="",))
def KeriServerClose(self):
    """
    Close server in valet

    Ioinit attributes:
        valet is a Valet instance

    Context: exit

    Example:
        do leopy server close at exit
    """
    if self.valet.value:
        self.valet.value.close()  #  .servant.closeAll()

        console.concise("Closed server '{0}' at '{1}'\n".format(
                            self.valet.name,
                            self.valet.value.servant.eha))


