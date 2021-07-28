# -*- encoding: utf-8 -*-
"""
keri.end.ending module

ReST API endpoints

"""
import sys
import os

import falcon

import hio
from hio.core import tcp, http, wiring

from .. import help
from  ..app import keeping, habbing, directing
from  ..db import basing

logger = help.ogler.getLogger()

# Falcon reource endpoints
class AdminEnd(hio.base.Tymee):
    """
    ReST API for admin of service endpoints
    """
    def __init__(self, hab, **kwa):
        """
        Parameters:
            hab (habbing.Habitat):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(AdminEnd, self).__init__(**kwa)
        self.hab = hab

    def on_get(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Admin\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message


class EIDEnd(hio.base.Tymee):
    """
    ReST API for Service Endpoint Identifier database for each identifier prefix
    """
    def __init__(self, hab, **kwa):
        """
        Parameters:
            hab (habbing.Habitat):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(EIDEnd, self).__init__(**kwa)
        self.hab = hab

    def on_get(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Service EIDs\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message

    def on_put(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Service EIDs\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message



class EndpointEnd(hio.base.Tymee):
    """
    ReST API for Service Endpoints database for each Service Endpoint Identifier prefix
    """
    def __init__(self, hab, **kwa):
        """
        Parameters:
            hab (habbing.Habitat):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(EndpointEnd, self).__init__(**kwa)
        self.hab = hab

    def on_get(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Service Endpoints\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message

    def on_put(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Service Endpoints\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message


WEB_DIR_PATH = os.path.dirname(
                os.path.abspath(
                    sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')


def loadEnds(app, *, tymth=None, ks=None, db=None, hab=None):
    """
    Load endpoints for app with shared resource dependencies
    This function provides the endpoint resource instances
    with references to the needed shared dependencies:
        tymth: virtual time reference injection function from Tymist subclass
        ks: keystore database
        db: KEL and app database
        hab: local habitat

    Parameters:
        tymth (callable):  reference to tymist (Doist, DoDoer) virtual time reference
    """

    sink = http.serving.StaticSink(staticDirPath=STATIC_DIR_PATH)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    # Resources are represented by long-lived class instances
    app.add_route('/admin', AdminEnd(tymth=tymth, hab=hab)) # handles all requests to '/admin' URL path
    app.add_route('/eid', EIDEnd(tymth=tymth, hab=hab)) # handles all requests to '/service' URL path
    app.add_route('/end', EndpointEnd(tymth=tymth, hab=hab)) # handles all requests to '/service' URL path


def setup(name="who", temp=False, sith=None, count=1,
                    remotePort=5621, localPort=5620, webPort=8081, tymth=None):
    """
    Setup and return doers list to run controller
    """
    # setup databases  for dependency injection
    ks = keeping.Keeper(name=name, temp=temp)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=temp)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp, isith=sith, icount=count, )
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')
    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='keri',
                        reopen=True, headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)  # setup doer

    #client = tcp.Client(host='127.0.0.1', port=remotePort, wl=wl)
    #clientDoer = tcp.ClientDoer(client=client)  # setup doer
    #director = directing.Director(hab=hab, client=client, tock=0.125)
    #reactor = directing.Reactor(hab=hab, client=client)

    # must do it here to inject into Falcon endpoint resource instances
    # tymist = tyming.Tymist(tyme=0.0)

    myapp = falcon.App() # falcon.App instances are callable WSGI apps
    loadEnds(myapp, tymth=tymth, hab=hab)

    webServer = http.Server(name="keri.wsgi.server", app=myapp, port=webPort, wl=wl)
    webServerDoer = http.ServerDoer(server=webServer)

    #server = tcp.Server(host="", port=localPort, wl=wl)
    #serverDoer = tcp.ServerDoer(server=server)  # setup doer
    #directant = directing.Directant(hab=hab, server=server)
    # Reactants created on demand by directant

    logger.info("\nWeb ReST API Controller %s:\nNamed %s on HTTP port %s.\n\n",
                    hab.pre, hab.name, webPort)

    #return [ksDoer, dbDoer, habDoer, wireDoer, clientDoer, director, reactor,
            #serverDoer, directant, webServerDoer]

    return ([ksDoer, dbDoer, habDoer, wireDoer, webServerDoer])

