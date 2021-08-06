# -*- encoding: utf-8 -*-
"""
keri.end.ending module

ReST API endpoints

"""
import sys
import os
import json
from collections import namedtuple
from collections.abc import Mapping
from typing import Union

import falcon

import hio
from hio.core import tcp, http, wiring

from .. import help
from  ..app import keeping, habbing, directing
from  ..db import basing
from  ..core import coring

logger = help.ogler.getLogger()

Mimage = namedtuple("Mimage", "json mgpk cbor cesr")

Mimes = Mimage(json="application/json",
               mgpk='application/msgpack',
               cbor='application/cbor',
               cesr='application/cesr')

KeriMimes = Mimage(json='application/keri+json',
                   mgpk='application/keri+msgpack',
                   cbor='application/keri+cbor',
                   cesr='application/keri+cesr')

# Usage: to get Mime from serialization kind
# getattr(Mimes, coring.Serials.json.lower())
# getattr(KeriMimes, coring.Serials.json.lower())


Schemage = namedtuple("Schemage", 'tcp http https')
Schemes = Schemage(tcp='tcp', http='http', https='https')

Rolage = namedtuple("Rolage", 'witness registrar watcher judge juror')
Roles = Rolage(witness='witness', registrar='registrar', watcher='watcher',
               judge='judge', juror='juror')

FALSY = (False, 0, "?0", "no", "false", "False", "off")
TRUTHY =  (True, 1, "?1", "yes" "true", "True", 'on')

# Signature HTTP header support
Signage = namedtuple("Signage", "markers indexed signer kind", defaults=(None, None, None))


def signature(signages):
    """
    Creates  Signature HTTP header item from signats list

    RFC8941 structured Field Values for HTTP

    Returns:
        header (dict): {'Signature': 'value'} where value is RFC8941 compliant
        (Structured Field Values for HTTP) formatted str of of Signage group.
        Each signage group is separated by a comma. Each group is parameter list
        of label=value items separated by ;
        The signer and indexed are special parameters in each group.
        This format is compatible with HTTP servers that merge multiple signature
        headers into one header by iteratively appending the comma separated
        value from each Signature header.

    Parameters:
        signages (list): items are Signage namedtuples,(markers, indexed, indexed)
            where:
                markers (Union[list, dict]): When dict each item (key, val) has
                    key as str identifier of marker and has val as instance of
                    either coring.Siger or coring.Cigar.
                    When list each item is instance of either coring.Siger or
                    coring.Cigar.
                    All markers must be of same class
                indexed (bool): True means marker values are indexed signatures
                    using coring.Siger. False means marker values are unindexed
                    signatures using coring.Cigar. None means auto detect from
                    first marker value class. All markers must be of same class.
                signer (str): optional identifier of signage. May be a
                    multi-sig group identifier. Default is None. When None or
                    empty signer is not included in header value


    """
    values = []  # list of parameter items value str for each signage
    for signage in signages:
        markers = signage.markers
        indexed = signage.indexed
        signer = signage.signer
        kind = signage.kind

        if isinstance(markers, Mapping):
            tags = list(markers.keys())
            markers = list(markers.values())
        else:
            tags = []

        if indexed is None:
            indexed = hasattr(markers[0], "index")

        items = []
        tag = 'indexed'
        val = '?1' if indexed else '?0'  #  RFC8941 HTTP structured field values
        items.append('{}="{}"'.format(tag, val))
        if signer:
            tag = "signer"
            val = signer
            items.append('{}="{}"'.format(tag, val))
        if kind:
            tag = "kind"
            val = kind
            items.append('{}="{}"'.format(tag, val))

        for i, marker in enumerate(markers):
            if tags:
                tag = tags[i]
            else:  # assign defaults names since not provided
                if hasattr(marker, "index"):  # Siger has index
                    if not indexed:
                        raise ValueError("Indexed signature marker {} when "
                                         "indexed False.".format(marker))
                    tag = str(marker.index)
                elif hasattr(marker, "verfer"):  # Cigar has verfer but not index
                    if indexed:
                        raise ValueError("Unindexed signature marker {} when "
                                         "indexed True.".format(marker))
                    tag = marker.verfer.qb64
                else:
                    raise ValueError("Invalid signature marker instance = {}."
                                     "".format(marker))

            val = marker.qb64
            items.append('{}="{}"'.format(tag, val))

        values.append(";".join(items))

    return dict(Signature=",".join(values))  # join all signage value strs


def designature(value):
    """
    Parse signature header str value where value is RFC8941 compliant
        (Structured Field Values for HTTP) formatted str of of Signage group.
        Each signage group is separated by a comma. Each group is parameter list
        of label=value items separated by ;
        The signer and indexed are special parameters in each group.
        This format is compatible with HTTP servers that merge multiple signature
        headers into one header by iteratively appending the comma separated
        value from each Signature header.

    RFC8941 structured Field Values for HTTP

    Returns:
       signages (list): items are Signage namedtuples,(markers, signer, indexed)
            where:
                markers (dict): each item (key, val) has key as str identifier
                    of marker and has val as instance of either coring.Siger or
                    coring.Cigar. All markers must be of same class
                signer (str): optional identifier of signage. May be a multi-sig
                    group identifier
                indexed (bool): True means marker values are indexed signatures
                    using coring.Siger. False means marker values are unindexed
                    signatures using coring.Cigar.


       signatures (list): Siger or Cigar instances
    """
    signages = []
    values = value.replace(" ", "").split(",")  # removes all spaces
    for value in values:
        items = {}
        for item in value.split(";"):
            key, val = item.split("=", maxsplit=1)
            items[key] = val.strip('"')

        if "indexed" not in  items:
            raise ValueError("Missing indexed field in Signature header signage.")
        indexed = items["indexed"] not in FALSY  # make bool
        del items["indexed"]

        if "signer" in items:
            signer = items["signer"]
            del items["signer"]
        else:
            signer = None

        if "kind" in items:
            kind = items["kind"]
            del items["kind"]
        else:
            kind = "CESR"  # default is empty or missing

        if kind == "CESR":  # convert to Siger or Cigar instances
            for key, val in items.items():
                if indexed:
                    items[key] = coring.Siger(qb64=val)
                else:
                    items[key] = coring.Cigar(qb64=val)

        signages.append(Signage(markers=items, indexed=indexed, signer=signer, ))

    return signages


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
        try:
            raw = req.bounded_stream.read()
        except Exception:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='Read Error',
                                   description='Malformed request body.')

        # Verify signatures here on raw
        # falcon get header call to get Signature header

        # use Serder to load from raw to support any serialization
        # verify mime type


        try:
            data = json.loads(raw)
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
    myapp = falcon.App(cors_enable=True) # falcon.App instances are callable WSGI apps
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

