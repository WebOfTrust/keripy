# -*- encoding: utf-8 -*-
"""
keri.vc.handling module

"""
import os
from collections import namedtuple
from hio.help import ogler

from ..kering import Vrsn_1_0, Vrsn_2_0, Version

from ..peer import cloneMessage, exchange, specialExchange

logger = ogler.getLogger()

Ipexage = namedtuple("Ipexage", 'apply offer agree grant admit spurn')
Ipex = Ipexage(apply="apply", offer="offer", agree="agree", grant="grant", admit="admit", spurn="spurn")
PreviousRoutes = {
    Ipex.offer: (Ipex.apply,),
    Ipex.agree: (Ipex.offer,),
    Ipex.grant: (Ipex.agree,),
    Ipex.admit: (Ipex.grant,),
    Ipex.spurn: (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant),
}


class IpexHandler:
    """ Processor of `exn` IPEX messages.

    """

    def __init__(self, resource, hby, notifier):
        """ Initialize instance

        Parameters:
            resource (str): route of messages for this handler
            hby (Habery): local identifier environment
            notifier (Notifier): outbound notifications

        """
        self.resource = resource
        self.hby = hby
        self.notifier = notifier

    def verify(self, serder, attachments=None):
        """  Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        Returns:
            bool: True means the exn passed behaviour specific verification for IPEX protocol messages

        """

        route = serder.ked['r']
        dig = serder.ked['p']

        match route.split("/"):
            case["", "ipex", Ipex.apply]:
                if not dig:  # Apply messages can only start an IPEX exchange
                    return True
            case["", "ipex", verb] if verb in (Ipex.offer, Ipex.grant):
                if not dig:  # This is an offer, agree or grant opening an IPEX exchange, no prior
                    return True

                pserder, _ = cloneMessage(self.hby, said=dig)
                if pserder is None:  # previous reference message does not exist
                    return False

                proute = pserder.ked['r']
                pverb = os.path.basename(os.path.normpath(proute))

                # Use established PreviousRoutes to determine if this response is valid
                if pverb not in PreviousRoutes[verb]:
                    return False

                return self.response(pserder) is None  # Make sure we don't have a response already

            case["", "ipex", verb] if verb in (Ipex.admit, Ipex.agree, Ipex.spurn):
                if not dig:  # Admit and Spurn messages can NOT start an IPEX exchange
                    return False

                pserder, _ = cloneMessage(self.hby, said=dig)
                if pserder is None:  # previous reference message does not exist
                    return False

                proute = pserder.ked['r']
                pverb = os.path.basename(os.path.normpath(proute))

                # Use established PreviousRoutes to determine if this response is valid
                if pverb not in PreviousRoutes[verb]:
                    return False

                return self.response(pserder) is None  # Make sure we don't have a response already

        return False

    def response(self, serder):
        """ Return the IPEX exn message sent as a response to the provided serder, if any

        Parameters:
            serder (Serder): IPEX exn message to check for a response

        Returns:

        """
        saider = self.hby.db.erpy.get(keys=(serder.said,))
        if saider:
            rserder, _ = cloneMessage(self.hby, saider.qb64)  # Clone previous so we reverify the sigs
            return rserder

        return None

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """
        attrs = serder.ked["a"]

        data = dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"]
        )

        self.notifier.add(attrs=data)


def ipexApplyExn(hab, recp, message, schema, attrs, version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Apply for an ACDC

    Parameters::
        hab(Hab): identifier environment for issuer of credential
        recp (str): qb64 AID of recipient
        message(str): Human readable message regarding the credential application
        schema (any): schema or its SAID
        attrs (any): attribute field label list
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns::
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
        s=schema,
        a=attrs,
        i=recp
    )

    exn = exchange(sender=hab.pre,
                   route="/ipex/apply",
                   attributes=data,
                   version=Version,
                   pvrsn=pvrsn,
                   gvrsn=gvrsn)
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    #ims.extend(end)

    return exn, ims


def ipexOfferExn(hab, message, acdc, apply=None,  version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Offer a metadata ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the credential offer
        acdc (any): metadata ACDC or its SAID
        apply (Serder): optional IPEX exn apply message that this offer is response to.
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message
    )

    embeds = dict(
        acdc=acdc
    )

    kwa = dict()
    if apply is not None:
        kwa['prior'] = apply.said

    exn, end = specialExchange(sender=hab.pre,
                               route="/ipex/offer",
                               attributes=data,
                               embeds=embeds,
                               version=version,
                               pvrsn=pvrsn,
                               gvrsn=gvrsn, **kwa)
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexAgreeExn(hab, message, offer, version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Agree an offer

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the credential agreement
        offer (Serder): IPEX exn offer message that this offer is response to.
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message
    )

    exn = exchange(sender=hab.pre,
                               prior=offer.said,
                               route="/ipex/agree",
                               attributes=data,
                               version=version,
                               pvrsn=pvrsn,
                               gvrsn=gvrsn)
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    #ims.extend(end)

    return exn, ims


def ipexGrantExn(hab, recp, message, acdc, iss=None, anc=None, agree=None,
                      dt=None, version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Disclose an ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        recp (str) qb64 AID of recipient of GRANT message
        message(str): Human readable message regarding the credential disclosure
        acdc (bytes): CESR stream of serialized ACDC with attachments
        iss (bytes): serialized TEL issuance event
        anc (bytes): serialized anchoring event in the KEL, either ixn or rot
        agree (Serder): optional IPEX exn agree message that this grant is response to.
        dt (str): Iso8601 formatted date string to use for this request
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
        i=recp,
    )

    embeds = dict(
        acdc=acdc,
    )

    if iss is not None:
        embeds['iss'] = iss

    if anc is not None:
        embeds['anc'] = anc

    kwa = dict()
    if agree is not None:
        kwa['prior'] = agree.said

    exn, end = specialExchange(sender=hab.pre,
                               route="/ipex/grant",
                               stamp=dt,
                               attributes=data,
                               embeds=embeds,
                               version=version,
                               pvrsn=pvrsn,
                               gvrsn=gvrsn,
                               **kwa)
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexAdmitExn(hab, message, grant, dt=None, version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Admit a disclosure

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        grant (Serder): IPEX grant exn message serder
        dt (str): timestamp
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
    )

    exn = exchange(sender=hab.pre,
                               prior=grant.said,
                               route="/ipex/admit",
                               stamp=dt,
                               attributes=data,
                               version=version,
                               pvrsn=pvrsn,
                               gvrsn=gvrsn,                                )
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    #ims.extend(end)

    return exn, ims


def ipexSpurnExn(hab, message, spurned, version=Version, pvrsn=None,
                      gvrsn=Version, framed=True, nested=False, genusify=False):
    """ Reject an application, offer or agreement

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        spurned (Serder): apply, offer, agree or grant received
        version (Versionage): KERI protocol default version if psvrsn is None
        pvrsn (Versionage): KERI protocol version
        gvrsn (Versionage): CESR Genus version for attachment group codes or
                        nesting group code (useful when serder.gvrsn < 2)
                        gvrsn = max(svrsn, gvrsn) where svrsn = serder.gvrsn
                            if serder.gvrsn else serder.pvrsn
        framed (bool): True means may assume each message plus its attachments
                                is isolated as frame when parsing so do not need
                                attachment group when messagizing
                           False means may not assume eash message plus its attachments
                                is isolated as frame when parsing so do need
                                attachment group when messagizing
        nested (bool): True means messagize for non-top level
                            This forces non-native serializion to be embedded
                            in non-native group code
                       False means messagize for top level of stream.
                            This allows bare non-native serialization of message
        genusify (bool): True means prepend genus version code from gvrsn before
                        serder to override default stream genus version
                     False means do nothing

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message
    )

    exn = exchange(sender=hab.pre,
                               prior=spurned.said,
                               route="/ipex/spurn",
                               attributes=data,
                               version=version,
                               pvrsn=pvrsn,
                               gvrsn=gvrsn,                                )
    ims = hab.endorse(serder=exn, last=False, gvrsn=gvrsn, framed=framed,
                      nested=nested, genusify=genusify)
    del ims[:exn.size]
    #ims.extend(end)

    return exn, ims


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the IPEX protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): outbound notifications

    """
    exc.addHandler(IpexHandler(resource="/ipex/apply", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/offer", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/agree", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/grant", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/admit", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/spurn", hby=hby, notifier=notifier))
