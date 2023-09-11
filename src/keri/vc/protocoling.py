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

    def __init__(self, resource, hby, rgy, notifier):
        """ Initialize instance

        Parameters:
            resource (str): route of messages for this handler
            hby (Habery): local identifier environment
            rgy (Regery): Credential database environment
            notifier (Notifier): outbound notifications

        """
        self.resource = resource
        self.hby = hby
        self.rgy = rgy
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
            case["", "ipex", verb] if verb in (Ipex.offer, Ipex.agree, Ipex.grant):
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

            case["", "ipex", verb] if verb in (Ipex.admit, Ipex.spurn):
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
        saider = self.hby.db.erpys.get(key=(serder.said,))
        if saider:
            rserder, _ = exchanging.cloneMessage(self.hby, saider.qb64)  # Clone previous so we reverify the sigs
            return rserder

        return None

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            pathed (list): list of CESR SAD path attachments to the exn event

        """
        attrs = serder.ked["a"]

        data = dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"]
        )

        self.notifier.add(attrs=data)


def ipexApplyExn(hab, message, schema, attrs):
    """ Apply for an ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
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
        a=attrs
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
        offer (any): offer received or its SAID

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
        o=offer
    )

    exn, end = exchanging.exchange(route="/ipex/agree", payload=data, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexGrantExn(hab, message, acdc, iss, anc):
    """ Disclose an ACDC

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the credential disclosure
        acdc (bytes): CESR stream of serialized ACDC with attachments
        iss (bytes): serialized TEL issuance event
        anc (bytes): serialized anchoring event in the KEL, either ixn or rot

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
    )

    embeds = dict(
        acdc=acdc,
        iss=iss,
        anc=anc
    )

    exn, end = exchanging.exchange(route="/ipex/grant", payload=data, sender=hab.pre, embeds=embeds)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexAdmitExn(hab, message, grant):
    """ Admit a disclosure

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        grant (str): qb64 SAID of IPEX grant exn message

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
    )

    exn, end = exchanging.exchange(route="/ipex/admit", payload=data, sender=hab.pre, dig=grant)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def ipexSpurnExn(hab, message, spurn):
    """ Reject an application, offer or agreement

    Parameters:
        hab(Hab): identifier environment for issuer of credential
        message(str): Human readable message regarding the admission
        spurn (any): apply, offer or agree received, or its SAID that is rejected

    Returns:
        Serder: credential issuance exn peer to peer message
        bytes: attachments for exn message

    """
    data = dict(
        m=message,
        s=spurn
    )

    exn, end = exchanging.exchange(route="/ipex/spurn", payload=data, sender=hab.pre)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims


def loadHandlers(hby, exc, rgy, notifier):
    """ Load handlers for the IPEX protocol

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        rgy (Regery): Credential database environment
        notifier (Notifier): outbound notifications

    """
    exc.addHandler(IpexHandler(resource="/ipex/apply", hby=hby, rgy=rgy, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/offer", hby=hby, rgy=rgy, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/agree", hby=hby, rgy=rgy, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/grant", hby=hby, rgy=rgy, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/admit", hby=hby, rgy=rgy, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/spurn", hby=hby, rgy=rgy, notifier=notifier))
