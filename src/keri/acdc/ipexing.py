# -*- encoding: utf-8 -*-
"""
keri.acdc.ipexing module

IPEx protocol service support (Issuance and Presentation Exchange)

"""

from collections import namedtuple

from hio.help import ogler

from .. import Kinds
from ..kering import Colds, Vrsn_2_0, sniff
from ..core import (Counter, Codens, Diger, GenDex, Number, Serdery, Texter,
                    exchange, messagize)
from ..peer import cloneMessage

logger = ogler.getLogger()

Ipexage = namedtuple("Ipexage", "apply offer agree grant admit spurn")
Ipex = Ipexage(apply="apply", offer="offer", agree="agree",
               grant="grant", admit="admit", spurn="spurn")

PreviousRoutes = {
    Ipex.offer: (Ipex.apply,),
    Ipex.agree: (Ipex.offer,),
    Ipex.grant: (Ipex.agree,),
    Ipex.admit: (Ipex.grant,),
    Ipex.spurn: (Ipex.apply, Ipex.offer, Ipex.agree),
}

def _streamSerder(stream):
    """Extract the message serder from a bare or nested artifact stream.

    Parameters:
        stream (Serder | bytes | bytearray): Artifact body, artifact stream, or
            already-parsed serder-like object.

    Returns:
        Serder: Deserialized message serder for the provided artifact.
    """

    # if the input already looks like a serder with .said and .raw, just return it
    if hasattr(stream, "said") and hasattr(stream, "raw"):
        return stream

    # If the input has .raw, use that; otherwise treat the input itself as bytes
    ims = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)

    # If the input is a nested stream, unwrap it to get the inner message for parsing
    if _isNestedStream(ims):
        ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
        if ctr.name in (
            Codens.NonNativeBodyGroup,
            Codens.BigNonNativeBodyGroup,
        ):
            return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                  genus=GenDex.KERI,
                                                  svrsn=Vrsn_2_0)
        if ims and sniff(ims) != Colds.msg:
            ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
            if ctr.name in (
                Codens.NonNativeBodyGroup,
                Codens.BigNonNativeBodyGroup,
            ):
                return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                      genus=GenDex.KERI,
                                                      svrsn=Vrsn_2_0)

    return Serdery(version=Vrsn_2_0).reap(ims=ims,
                                          genus=GenDex.KERI,
                                          svrsn=Vrsn_2_0)


def _isNestedStream(stream):
    """Determine whether a stream already uses a supported nested wrapper.

    Parameters:
        stream (Serder | bytes | bytearray): Candidate artifact stream to inspect.

    Returns:
        bool: True when the stream starts with a nested body wrapper supported
            by the V2 parser, False when it is a bare message body.

    Raises:
        ValueError: If the stream starts with an unsupported leading CESR frame
            that this implementation refuses to reinterpret as a bare artifact.
    """
    ims = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)
    if not ims or sniff(ims) == Colds.msg:
        return False

    try:
        ctr = Counter(qb64b=ims, version=Vrsn_2_0)
    except Exception as ex:
        raise ValueError("unsupported leading frame for nested artifact stream") from ex

    if ctr.name in (
        Codens.BodyWithAttachmentGroup,
        Codens.BigBodyWithAttachmentGroup,
        Codens.NonNativeBodyGroup,
        Codens.BigNonNativeBodyGroup,
    ):
        return True

    raise ValueError(f"unsupported leading frame code for nested artifact stream: {ctr.name}")


def _normalizeNestedStream(stream):
    """Convert a carried artifact into a parser-friendly V2 nested substream.

    Parameters:
        stream (Serder | bytes | bytearray): Artifact body or artifact stream to
            carry inside an outer IPEX exchange.

    Returns:
        bytearray: V2 nested substream framed as a body-with-attachments group.
    """

    # Check if already a nested CESR substream, if so return as is
    if _isNestedStream(stream):
        return bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)

    # If not make the input into raw bytes
    raw = bytes(stream.raw) if hasattr(stream, "raw") else bytes(stream)

    # Parse the raw bytes into a Serder to get the body and attachments
    serder = _streamSerder(raw)

    body = raw[:serder.size]
    atc = raw[serder.size:]

    # Check if body is NOT CESR, if so wrap it in a NonNativeBodyGroup counter
    if serder.kind != Kinds.cesr:
        body = Counter.enclose(qb64=Texter(raw=body).qb64b,
                               code=Codens.NonNativeBodyGroup,
                               version=Vrsn_2_0)

    # Check if attachments are empty, if so create an empty AttachmentGroup counter
    nested = bytearray(body)
    if atc:
        nested.extend(atc)
    else:
        empty = Counter.enclose(qb64=b'',
                                code=Codens.ControllerIdxSigs,
                                version=Vrsn_2_0)
        nested.extend(Counter.enclose(qb64=empty,
                                      code=Codens.AttachmentGroup,
                                      version=Vrsn_2_0))

    # Return the body and attachments
    return Counter.enclose(qb64=nested,
                           code=Codens.BodyWithAttachmentGroup,
                           version=Vrsn_2_0)


def _sign(hab, serder, *, nests=None, gvrsn=None):
    """Sign and messagize an outer IPEX exchange with optional nested streams.

    Parameters:
        hab (Hab): Habitat used to sign the outer exchange.
        serder (Serder): Outer exchange serder to sign.
        nests (list[bytes | bytearray] | None): Optional nested substreams to
            append in the outer attachment section.
        gvrsn (Versionage | None): Optional CESR genus version override for the
            attachment and nesting groups.

    Returns:
        bytearray: Full signed exchange stream including the outer message body,
            attachments, and any nested substreams.
    """
    gvrsn = gvrsn if gvrsn is not None else Vrsn_2_0
    nests = nests if nests else None

    if hab.kever.prefixer.transferable:
        sigers = hab.sign(ser=serder.raw, indexed=True)
        tsgs = [(hab.kever.prefixer,
                 Number(sn=hab.kever.lastEst.s),
                 Diger(qb64=hab.kever.lastEst.d),
                 sigers)]
        return messagize(serder=serder,
                         tsgs=tsgs,
                         nests=nests,
                         framed=False,
                         gvrsn=gvrsn)

    cigars = hab.sign(ser=serder.raw, indexed=False)
    return messagize(serder=serder,
                     cigars=cigars,
                     nests=nests,
                     framed=False,
                     gvrsn=gvrsn)


class IpexHandler:
    """Verify and handle the linear V2 IPEX `exn` workflow."""

    def __init__(self, resource, hby, notifier):
        """Create a handler for one IPEX route.

        Parameters:
            resource (str): Route string handled by this instance.
            hby (Habery): Habitat environment and backing database.
            notifier: Notifier-like object with an ``add`` method.

        Returns:
            None
        """
        self.resource = resource
        self.hby = hby
        self.notifier = notifier

    def verify(self, serder, attachments=None):
        """Validate the verb, prior link, and single-response rule.

        Parameters:
            serder (Serder): Incoming IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused in the
                current linear workflow validation.

        Returns:
            bool: True when the message is valid for the linear IPEX workflow,
                False otherwise.
        """
        
        # Get route
        route = serder.ked["r"]
        
        # Get digest of prior
        dig = serder.ked["p"]
        
        parts = route.split("/")
        if len(parts) != 3 or parts[:2] != ["", "ipex"]:
            return False
        verb = parts[2]

        # Apply starts the flow so there must be no prior
        if verb == Ipex.apply:
            return not dig
        
        # Offer and Grant can start a flow so empty prior is okay
        if verb in (Ipex.offer, Ipex.grant):
            if not dig:
                return True

        # Admit, Agree and Spurn are not allowed to start a flow so empty prior rejected
        elif verb in (Ipex.admit, Ipex.agree, Ipex.spurn):
            if not dig:
                return False
        else:
            return False

        # Load the prior, reject if missing
        pserder, _ = cloneMessage(self.hby, said=dig)
        if pserder is None:
            return False
        
        # Retrieve the verb and check if previous route validates
        proute = pserder.ked["r"]
        pparts = proute.split("/")
        if len(pparts) != 3 or pparts[:2] != ["", "ipex"]:
            return False
        pverb = pparts[2]
        if pverb not in PreviousRoutes[verb]:
            return False

        return self.response(pserder) is None

    def response(self, serder):
        """Look up the recorded response to a prior IPEX exchange.

        Parameters:
            serder (Serder): Prior IPEX exchange to check for an existing reply.

        Returns:
            Serder | None: The previously recorded response serder, or None when
                no response has been recorded.
        """
        saider = self.hby.db.erpy.get(keys=(serder.said,))
        if saider:
            rserder, _ = cloneMessage(self.hby, saider.qb64)
            return rserder

        return None

    def handle(self, serder, attachments=None):
        """Emit a notifier record for an accepted IPEX message.

        Parameters:
            serder (Serder): Accepted IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused by the
                current notifier path.

        Returns:
            None
        """
        attrs = serder.ked["a"]
        self.notifier.add(attrs=dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"],
        ))


def apply(hab, recp, message, schema, attrs, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``apply`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the application.
        message (str): Human-readable application message.
        schema (str | Serder): Schema SAID or schema-like object for the request.
        attrs (dict): Requested credential attribute payload.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        route="/ipex/apply",
        stamp=dt,
        attributes=dict(
            m=message,
            s=schema.said if hasattr(schema, "said") else schema,
            a=attrs,
            i=recp,
        ),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    
    # Sign the full stream
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    
    # Strip the body so we only get the attachments
    del atc[:serder.size]

    return serder, atc


def offer(hab, message, acdc, apply=None, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``offer`` exchange with a nested ACDC stream.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable offer message.
        acdc (Serder | bytes | bytearray): Offered credential artifact.
        apply (Serder | None): Optional prior ``apply`` exchange.
        recp (str | None): Optional recipient AID. Defaults to the prior
            ``apply`` sender; supply it directly for an offer-first exchange
            opened with no prior.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Get the prior event (apply) and the party to address (its sender)
    prior = apply.said if apply is not None else ""
    receiver = recp if recp is not None else (apply.ked["i"] if apply is not None else "")

    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        prior=prior,
        route="/ipex/offer",
        stamp=dt,
        attributes=dict(
            m=message,
            acdc=_streamSerder(acdc).said,
        ),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )

    # Build attachments
    nests = [_normalizeNestedStream(acdc)]
    atc = bytearray(_sign(hab=hab, serder=serder, nests=nests, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def agree(hab, message, offer, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``agree`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable agreement message.
        offer (Serder): Prior ``offer`` exchange being accepted.
        recp (str | None): Optional recipient AID. Defaults to the prior
            ``offer`` sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    receiver = recp if recp is not None else offer.ked["i"]
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        prior=offer.said,
        route="/ipex/agree",
        stamp=dt,
        attributes=dict(m=message),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def grant(hab, recp, message, acdc, iss=None, anc=None, agree=None,
          dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``grant`` exchange with nested disclosure artifacts.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the disclosure.
        message (str): Human-readable disclosure message.
        acdc (Serder | bytes | bytearray): Credential artifact to disclose.
        iss (Serder | bytes | bytearray | None): Optional issuance artifact.
        anc (Serder | bytes | bytearray | None): Optional anchoring event stream.
        agree (Serder | None): Optional prior ``agree`` exchange.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    prior = agree.said if agree is not None else ""
    data = dict(
        m=message,
        i=recp,
        acdc=_streamSerder(acdc).said,
    )
    nests = [_normalizeNestedStream(acdc)]

    if iss is not None:
        data["iss"] = _streamSerder(iss).said
        nests.append(_normalizeNestedStream(iss))

    if anc is not None:
        data["anc"] = _streamSerder(anc).said
        nests.append(_normalizeNestedStream(anc))

    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        prior=prior,
        route="/ipex/grant",
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder, nests=nests, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def admit(hab, message, grant, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``admit`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable admission message.
        grant (Serder): Prior ``grant`` exchange being acknowledged.
        recp (str | None): Optional recipient AID. Defaults to the prior
            ``grant`` sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    receiver = recp if recp is not None else grant.ked["i"]
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        prior=grant.said,
        route="/ipex/admit",
        stamp=dt,
        attributes=dict(m=message),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def spurn(hab, message, spurned, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``spurn`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable rejection message.
        spurned (Serder): Prior exchange being rejected.
        recp (str | None): Optional recipient AID. Defaults to the spurned
            message's sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    receiver = recp if recp is not None else spurned.ked["i"]
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        prior=spurned.said,
        route="/ipex/spurn",
        stamp=dt,
        attributes=dict(m=message),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def loadHandlers(hby, exc, notifier):
    """Register handlers for the six V2 IPEX verb routes.

    Parameters:
        hby (Habery): Habitat environment and backing database.
        exc (Exchanger): Exchange router to register handlers on.
        notifier: Notifier-like object passed through to each handler.

    Returns:
        None
    """
    exc.addHandler(IpexHandler(resource="/ipex/apply", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/offer", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/agree", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/grant", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/admit", hby=hby, notifier=notifier))
    exc.addHandler(IpexHandler(resource="/ipex/spurn", hby=hby, notifier=notifier))
