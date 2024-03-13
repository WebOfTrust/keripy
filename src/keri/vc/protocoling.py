# -*- encoding: utf-8 -*-
"""
keri.vc.handling module

"""
import os
from collections import namedtuple

from .. import help
from ..peer import exchanging

logger = help.ogler.getLogger()

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

                pserder, _ = exchanging.cloneMessage(self.hby, said=dig)
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

                pserder, _ = exchanging.cloneMessage(self.hby, said=dig)
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
            rserder, _ = exchanging.cloneMessage(self.hby, saider.qb64)  # Clone previous so we reverify the sigs
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


def ipexApplyExn(hab, recp, message, schema, attrs):
    """ Apply for an ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        recp (str): qb64 AID of recipient
        message(str): Human readable message regarding the credential application
        schema (any): schema or its SAID
        attrs (any): attribute field label list

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
        s=schema,
        a=attrs,
        i=recp
    )

    exn, end = exchanging.exchange(route="/ipex/apply", payload=data, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexOfferExn(hab, message, acdc, apply=None):
    """ Offer a metadata ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the credential offer
        acdc (any): metadata ACDC or its SAID
        apply (Serder): optional IPEX exn apply message that this offer is response to.

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
        kwa["dig"] = apply.said

    exn, end = exchanging.exchange(route="/ipex/offer", payload=data, sender=hab.pre, embeds=embeds, **kwa)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexAgreeExn(hab, message, offer):
    """ Agree an offer

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the credential agreement
        offer (Serder): IPEX exn offer message that this offer is response to.

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message
    )

    exn, end = exchanging.exchange(route="/ipex/agree", payload=data, sender=hab.pre, dig=offer.said)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexGrantExn(hab, recp, message, acdc, iss=None, anc=None, agree=None, dt=None):
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
        kwa['dig'] = agree.said

    exn, end = exchanging.exchange(route="/ipex/grant", payload=data, sender=hab.pre, embeds=embeds, date=dt, **kwa)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexAdmitExn(hab, message, grant, dt=None):
    """ Admit a disclosure

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        grant (Serder): IPEX grant exn message serder
        dt (str): timestamp

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
    )

    exn, end = exchanging.exchange(route="/ipex/admit", payload=data, sender=hab.pre, dig=grant.said, date=dt)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexSpurnExn(hab, message, spurned):
    """ Reject an application, offer or agreement

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        spurned (Serder): apply, offer, agree or grant received

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message
    )

    exn, end = exchanging.exchange(route="/ipex/spurn", payload=data, sender=hab.pre, dig=spurned.said)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

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
