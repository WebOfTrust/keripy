# -*- encoding: utf-8 -*-
"""
keri.end.ending module

ReST API endpoints

"""
import sys
import os
import json
from collections import namedtuple
from typing import Union

import falcon

import hio
from hio.core import tcp, http, wiring

from .. import help
from  ..app import keeping, habbing, directing
from  ..db import basing
from  ..core import coring

logger = help.ogler.getLogger()

Schemage = namedtuple("Schemage", 'tcp http https')
Schemes = Schemage(tcp='tcp', http='http', https='https')

Rolage = namedtuple("Rolage", 'witness watcher')
Roles = Rolage(witness='witness', watcher='watcher')

def headerize(signatures):
    """
    Creates  Signature HTTP header item from signatures list

    Returns:
       item (tuple): header (label, value)

    Parameters:
       signatures (list): instances of either coring.Siger or coring.Cigar
    """
    label = "Signature"
    values = []
    for signature in signatures:
        if hasattr(signature, "index"):  # Siger has index
            tag = str(signature.index)
        elif hasattr(signature, "verfer"):  # Cigar has verfer but not index
            tag = signature.verfer.qb64
        else:
            raise ValueError("Invalid signature instance = {}.".format(signature))
        value = signature.qb64
        values.append('{}="{}"'.format(tag, value))
    return (label, ";".join(values))

# Falcon reource endpoints

class PointEnd(hio.base.Tymee):
    """
    ReST API for SEID (Service Endpoint IDentifier) database for each identifier prefix
    """
    def __init__(self, hab, **kwa):
        """
        Parameters:
            hab (habbing.Habitat):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(PointEnd, self).__init__(**kwa)
        self.hab = hab

    def on_post(self, req, rep, aid, role):
        """
        Handles POST requests
        """
        #try:
            #data = json.load(req.bounded_stream)
        #except ValueError:
            #raise falcon.HTTPError(falcon.HTTP_400,
                                   #title='Malformed JSON',
                                   #description='Error loading the request body.')

        try:
            raw_json = req.bounded_stream.read()
        except Exception:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='Read Error',
                                   description='Malformed request body.')

        # Verify signatures here

        try:
            data = json.loads(raw_json)
        except ValueError:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='JSON Error',
                                   description='Malformed JSON.')

        if role not in Roles:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='Malformed JSON',
                                   description='Invalid role.')

        for label in ["seid", "name", "dts", "scheme", "host", "port", "path"]:
            if label not in data:
                raise falcon.HTTPError(falcon.HTTP_400,
                                       title='Malformed JSON',
                                       description='Missing label.')
        scheme = data["scheme"]
        if scheme not in Schemes:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='Malformed JSON',
                                   description='Invalid scheme.')

        body = dict(aid=aid, role=role, data=data)  # response body

        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "application/json"
        rep.text = json.dumps(body)

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



class LocationEnd(hio.base.Tymee):
    """
    ReST API for Service Endpoint database for each Service Endpoint Identifier prefix
    """
    def __init__(self, hab, **kwa):
        """
        Parameters:
            hab (habbing.Habitat):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(LocationEnd, self).__init__(**kwa)
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
    # handles all requests to '/end' URL path
    app.add_route('/end/{aid}/{role}', PointEnd(tymth=tymth, hab=hab))
    # handles all requests to '/loc' URL path
    app.add_route('/loc', LocationEnd(tymth=tymth, hab=hab))
    # handles all requests to '/admin' URL path
    app.add_route('/admin', AdminEnd(tymth=tymth, hab=hab))


def setup(name="who", temp=False, tymth=None, sith=None, count=1,
                    remotePort=5621, localPort=5620, webPort=8081 ):
    """
    Setup and return doers list to run controller
    """
    # setup databases  for dependency injection
    ks = keeping.Keeper(name=name, temp=temp)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=name, temp=temp)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes

    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, temp=temp, isith=sith, icount=count)
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

