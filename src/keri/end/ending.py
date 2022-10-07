# -*- encoding: utf-8 -*-
"""
keri.end.ending module

ReST API endpoints

"""
import json
import os
import re
import sys

from ordered_set import OrderedSet as oset
from collections import namedtuple
from collections.abc import Mapping

import falcon
from hio import base
from hio.core import http, wiring

from .. import help
from .. import kering
from ..app import habbing
from ..core import coring

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


# Signature HTTP header support
Signage = namedtuple("Signage", "markers indexed signer ordinal digest kind")

OOBI_URL_TEMPLATE = "/oobi/{cid}/{role}"
OOBI_RE = re.compile('\\A/oobi/(?P<cid>[^/]+)/(?P<role>[^/]+)(?:/(?P<eid>[^/]+))?\\Z', re.IGNORECASE)
DOOBI_RE = re.compile('\\A/oobi/(?P<said>[^/]+)\\Z', re.IGNORECASE)
WOOBI_RE = re.compile('\\A/.well-known/keri/oobi/(?P<cid>[^/]+)\\Z')

OOBI_AID_HEADER = "KERI-AID"


def signature(signages):
    """
    Creates Signature HTTP header item from signages list

    RFC8941 Structured Field Values for HTTP

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
        signages (list): items are Signage namedtuples,
                           (markers, indexed, signer, ordinal, kind)
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
                ordinal (str): optional ordinal hex str of int that is an ordinal
                               such as sequence number to further identify the
                               keys used for the signatures. Usually when indexed
                               with signer and digest
                digest (str): optional CESR Base64 serialization of a digest to
                              further identify the keys used for the signatures.
                              Usually when indexed with signer and ordinal
                kind (str): serialization kind of the markers and other primitives


    """
    values = []  # list of parameter items value str for each signage
    for signage in signages:
        markers = signage.markers
        indexed = signage.indexed
        signer = signage.signer
        ordinal = signage.ordinal
        digest = signage.digest
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
        val = '?1' if indexed else '?0'  # RFC8941 HTTP structured field values
        items.append(f'{tag}="{val}"')
        if signer:
            tag = "signer"
            val = signer
            items.append(f'{tag}="{val}"')
        if ordinal:
            tag = "ordinal"
            val = ordinal
            items.append(f'{tag}="{val}"')
        if digest:
            tag = "digest"
            val = digest
            items.append(f'{tag}="{val}"')
        if kind:
            tag = "kind"
            val = kind
            items.append(f'{tag}="{val}"')

        for i, marker in enumerate(markers):
            if tags:
                tag = tags[i]
            else:  # assign defaults names since not provided
                if hasattr(marker, "index"):  # Siger has index
                    if not indexed:
                        raise ValueError(f"Indexed signature marker {marker} when "
                                         f"indexed False.")
                    tag = str(marker.index)
                elif hasattr(marker, "verfer"):  # Cigar has verfer but not index
                    if indexed:
                        raise ValueError(f"Unindexed signature marker {marker}"
                                         f"  when indexed True.")
                    tag = marker.verfer.qb64
                else:
                    raise ValueError(f"Invalid signature marker instance = "
                                     f"{marker}.")

            val = marker.qb64
            items.append(f'{tag}="{val}"')

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
       signages (list): items are Signage namedtuples,
                           (markers, indexed, signer, ordinal, kind)
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
                ordinal (str): optional ordinal hex str of int that is an ordinal
                               such as sequence number to further identify the
                               keys used for the signatures. Usually when indexed
                               with signer and digest
                digest (str): optional CESR Base64 serialization of a digest to
                              further identify the keys used for the signatures.
                              Usually when indexed with signer and ordinal
                kind (str): serialization kind of the markers and other primitives

       signatures (list): Siger or Cigar instances
    """
    signages = []
    values = value.replace(" ", "").split(",")  # removes all spaces
    for value in values:
        items = {}
        for item in value.split(";"):
            key, val = item.split("=", maxsplit=1)
            items[key] = val.strip('"')

        if "indexed" not in items:
            raise ValueError("Missing indexed field in Signature header signage.")
        indexed = items["indexed"] not in kering.FALSY  # make bool
        del items["indexed"]

        if "signer" in items:
            signer = items["signer"]
            del items["signer"]
        else:
            signer = None

        if "ordinal" in items:
            ordinal = items["ordinal"]
            del items["ordinal"]
        else:
            ordinal = None

        if "digest" in items:
            digest = items["digest"]
            del items["digest"]
        else:
            digest = None

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

        signages.append(Signage(markers=items, indexed=indexed, signer=signer,
                                ordinal=ordinal, digest=digest, kind=kind))

    return signages


# Falcon reource endpoints

class PointEnd(base.Tymee):
    """
    ReST API for SEID (Service Endpoint IDentifier) database for each identifier prefix
    """

    def __init__(self, hby, **kwa):
        """
        Parameters:
            hab (habbing.Hab):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(PointEnd, self).__init__(**kwa)
        self.hby = hby

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

        if role not in kering.Roles:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   title='Malformed JSON',
                                   description='Invalid role.')

        for label in ["seid", "name", "dts", "scheme", "host", "port", "path"]:
            if label not in data:
                raise falcon.HTTPError(falcon.HTTP_400,
                                       title='Malformed JSON',
                                       description='Missing label.')
        scheme = data["scheme"]
        if scheme not in kering.Schemes:
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


class LocationEnd(base.Tymee):
    """
    ReST API for Service Endpoint database for each Service Endpoint Identifier prefix
    """

    def __init__(self, hby, **kwa):
        """
        Parameters:
            hab (habbing.Hab):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(LocationEnd, self).__init__(**kwa)
        self.hby = hby

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


class AdminEnd(base.Tymee):
    """
    ReST API for admin of service endpoints
    """

    def __init__(self, hby, **kwa):
        """
        Parameters:
            hab (habbing.Hab):  instance of local habitat
            tymth (function): tymth for superclass (inherited)
        """
        super(AdminEnd, self).__init__(**kwa)
        self.hby = hby

    def on_get(self, req, rep):
        """
        Handles GET requests
        """
        message = "\nKERI Admin\n\n"
        rep.status = falcon.HTTP_200  # This is the default status
        rep.content_type = "text/html"
        rep.text = message


class OOBIEnd:
    """ REST API for OOBI endpoints

    Attributes:
        .hby (Habery): database access

    """

    def __init__(self, hby: habbing.Habery, default=None):
        """  End point for responding to OOBIs

        Parameters:
            hby (Habery): database environment
            default (str) qb64 AID of the 'self' of the node for

        """
        self.hby = hby
        self.default = default

    def on_get(self, req, rep, aid=None, role=None, eid=None):
        """  GET endoint for OOBI resource

        Parameters:
            req: Falcon request object
            rep: Falcon response object
            aid: qb64 identifier prefix of OOBI
            role: requested role for OOBI rpy message
            eid: qb64 identifier prefix of participant in role

        """

        if aid is None:
            if self.default is None:
                rep.status = falcon.HTTP_NOT_FOUND
                rep.text = "no blind oobi for this node"
                return

            aid = self.default

        if aid not in self.hby.kevers:
            rep.status = falcon.HTTP_NOT_FOUND
            return

        kever = self.hby.kevers[aid]
        owits = oset(kever.wits)
        if kever.prefixer.qb64 in self.hby.prefixes:  # One of our identifiers
            hab = self.hby.habs[kever.prefixer.qb64]
        elif match := owits.intersection(self.hby.prefixes):  # We are a witness for identifier
            pre = match.pop()
            hab = self.hby.habs[pre]
        else:  # Not allowed to respond
            rep.status = falcon.HTTP_NOT_ACCEPTABLE
            return

        eids = []
        if eid:
            eids.append(eid)

        msgs = hab.replyToOobi(aid=aid, role=role, eids=eids)
        if not msgs and role is None:
            msgs = hab.replyToOobi(aid=aid, role=kering.Roles.witness, eids=eids)
            msgs.extend(hab.replay(aid))

        if msgs:
            rep.status = falcon.HTTP_200  # This is the default status
            rep.set_header(OOBI_AID_HEADER, aid)
            rep.content_type = "application/json+cesr"
            rep.data = bytes(msgs)

        else:
            rep.status = falcon.HTTP_NOT_FOUND


WEB_DIR_PATH = os.path.dirname(
    os.path.abspath(
        sys.modules.get(__name__).__file__))
STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')


def loadEnds(app, hby, *, tymth=None, default=None):
    """
    Load endpoints for app with shared resource dependencies
    This function provides the endpoint resource instances
    with references to the needed shared dependencies:
        tymth: virtual time reference injection function from Tymist subclass
        hab: local habitat

    Parameters:
        app(falcon.App): Falcon Rest app for endpoint route registration
        hby(Habery): glocal database environment
        tymth (callable):  reference to tymist (Doist, DoDoer) virtual time reference
        default (str) qb64 AID of the 'self' of the node for

    """
    sink = http.serving.StaticSink(staticDirPath=STATIC_DIR_PATH)
    app.add_sink(sink, prefix=sink.DefaultStaticSinkBasePath)

    # Resources are represented by long-lived class instances
    # handles all requests to '/end' URL path
    app.add_route('/end/{aid}/{role}', PointEnd(tymth=tymth, hby=hby))
    # handles all requests to '/loc' URL path
    app.add_route('/loc', LocationEnd(tymth=tymth, hby=hby))
    # handles all requests to '/admin' URL path
    app.add_route('/admin', AdminEnd(tymth=tymth, hby=hby))

    end = OOBIEnd(hby=hby, default=default)
    app.add_route("/oobi", end)
    app.add_route("/oobi/{aid}", end)
    app.add_route("/oobi/{aid}/{role}", end)
    app.add_route("/oobi/{aid}/{role}/{eid}", end)


def setup(name="who", temp=False, tymth=None, isith=None, count=1,
          remotePort=5621, localPort=5620, webPort=8081):
    """
    Setup and return doers list to run controller
    """
    # setup habery with resources
    hby = habbing.Habery(name=name, base="endo", temp=True, free=True)
    hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer

    # make hab
    hab = hby.makeHab(name=name, isith=isith, icount=count)

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')
    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='keri',
                        reopen=True, headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)  # setup doer

    # client = tcp.Client(host='127.0.0.1', port=remotePort, wl=wl)
    # clientDoer = tcp.ClientDoer(client=client)  # setup doer
    # director = directing.Director(hab=hab, client=client, tock=0.125)
    # reactor = directing.Reactor(hab=hab, client=client)

    # must do it here to inject into Falcon endpoint resource instances
    myapp = falcon.App(cors_enable=True)  # falcon.App instances are callable WSGI apps
    loadEnds(myapp, tymth=tymth, hby=hby)

    webServer = http.Server(name="keri.wsgi.server", app=myapp, port=webPort, wl=wl)
    webServerDoer = http.ServerDoer(server=webServer)

    # server = tcp.Server(host="", port=localPort, wl=wl)
    # serverDoer = tcp.ServerDoer(server=server)  # setup doer
    # directant = directing.Directant(hab=hab, server=server)
    # Reactants created on demand by directant

    logger.info("\nWeb ReST API Controller %s:\nNamed %s on HTTP port %s.\n\n",
                hab.pre, hab.name, webPort)

    # return [ksDoer, dbDoer, habDoer, wireDoer, clientDoer, director, reactor,
    # serverDoer, directant, webServerDoer]

    return [hbyDoer, wireDoer, webServerDoer]


