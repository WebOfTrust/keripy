# -*- encoding: utf-8 -*-
"""
keri.acdc.ipexing module

IPEx protocol service support (Issuance and Presentation Exchange)

"""

from collections import namedtuple

from hio.help import ogler

from .. import Kinds
from ..kering import Colds, Vrsn_2_0, sniff
from ..core import (Counter, Codens, Diger, GenDex, Noncer, Number, Saider, Serdery, Texter,
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
    Ipex.spurn: (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant),
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

    def verify(self, serder, attachments=None, nests=None):
        """Validate the verb, prior link, and single-response rule.

        Parameters:
            serder (Serder): Incoming IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused in the
                current linear workflow validation.
            nests (list | None): Parsed V2 nested artifacts carried by offer
                and grant messages.

        Returns:
            bool: True when the message is valid for the linear IPEX workflow,
                False otherwise.
        """
        nests = nests if nests is not None else []

        # Get route
        route = serder.ked["r"]
        attrs = serder.ked["a"]
        
        # Get digest of prior
        dig = serder.ked["p"]
        
        parts = route.split("/")
        if len(parts) != 3 or parts[:2] != ["", "ipex"]:
            return False
        verb = parts[2]

        q = serder.ked.get("q")
        if not isinstance(attrs, dict) or "m" not in attrs or not isinstance(q, dict):
            return False

        if verb in (Ipex.apply, Ipex.agree, Ipex.admit, Ipex.spurn):
            # These IPEX verbs do not carry nested artifacts.
            if nests:
                return False
        elif verb == Ipex.offer:
            if ("o" not in attrs or not isinstance(attrs["o"], str)
                    or "dp" not in q or not isinstance(q["dp"], list) or not nests):
                return False
            try:
                Saider(qb64=attrs["o"])
            except Exception:
                return False
            for idx, nest in enumerate(nests):
                nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
                if not nserder.verify():
                    return False
                if idx == 0 and not nserder.compare(attrs["o"]):
                    return False

        elif verb == Ipex.grant:
            if "o" not in attrs or not isinstance(attrs["o"], str) or not nests:
                return False
            try:
                Saider(qb64=attrs["o"])
            except Exception:
                return False
            for idx, nest in enumerate(nests):
                nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
                if not nserder.verify():
                    return False
                if idx == 0 and not nserder.compare(attrs["o"]):
                    return False

        # Apply starts the flow, so it must have no prior and must carry both
        # the recipient and the transaction id.
        if verb == Ipex.apply:
            if "dp" not in q or not isinstance(q["dp"], list):
                return False
            return bool(not dig and serder.ked.get("ri", "") and serder.ked.get("x", ""))
        
        # Offer and Grant can start a flow, but flow-openers must carry both
        # the recipient and the transaction id.
        if verb in (Ipex.offer, Ipex.grant):
            if not dig:
                return bool(serder.ked.get("ri", "") and serder.ked.get("x", ""))

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
        if verb == Ipex.spurn and pverb == Ipex.grant and pserder.ked.get("p", ""):
            return False

        # Replies must target the prior sender and come from the prior receiver
        if serder.ked.get("ri", "") != pserder.ked.get("i", ""):
            return False
        preceiver = pserder.ked.get("ri", "")
        if not preceiver:
            return False
        if serder.ked.get("i", "") != preceiver:
            return False
        if serder.ked.get("x", "") != pserder.ked.get("x", ""):
            return False

        return self.response(pserder) is None

    def verifyEvidence(self, serder, *, tsgs=None, cigars=None, sourceSeals=None,
                       invalid=False):
        """Select verified non-sender evidence accepted by this IPEX route.

        A grant retains cryptographically valid evidence without assigning it
        an ACDC or DAG role. Invalid grant evidence is discarded. Other verbs
        reject non-sender evidence.
        """
        tsgs = tsgs if tsgs is not None else []
        cigars = cigars if cigars is not None else []
        sourceSeals = sourceSeals if sourceSeals is not None else []

        verb = serder.ked["r"].rsplit("/", 1)[-1]
        if verb == Ipex.grant:
            return tsgs, cigars, sourceSeals

        if tsgs or cigars or sourceSeals or invalid:
            return None

        return [], [], []

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

    def handle(self, serder, attachments=None, nests=None):
        """Emit a notifier record for an accepted IPEX message.

        Parameters:
            serder (Serder): Accepted IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused by the
                current notifier path.
            nests (list | None): Parsed V2 nested artifacts, unused by the
                notifier path.

        Returns:
            None
        """
        attrs = serder.ked["a"]
        self.notifier.add(attrs=dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"],
        ))

def apply(hab, recp, message, modifiers=None, attrs=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``apply`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the application.
        message (str): Human-readable application message.
        attrs (dict | None): Optional application body payload stored in ``a``.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        modifiers (dict | None): Query-section fields for ``q``. ``apply``
            requires an explicit disclosure plan at ``modifiers["dp"]``.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    if not recp:
        raise ValueError("recp is required when apply starts a flow")
    xid = Diger(ser=Noncer().qb64b).qb64
    if attrs is not None and not isinstance(attrs, dict):
        raise TypeError("attrs must be a dict when provided")

    data = dict(attrs) if attrs is not None else {}
    data["m"] = message
    mods = dict(modifiers) if modifiers else {}
    if "dp" not in mods or not isinstance(mods["dp"], list):
        raise ValueError("modifiers['dp'] is required and must be a list")

    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        xid=xid,
        route="/ipex/apply",
        modifiers=mods,
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    
    # Sign the full stream
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    
    # Strip the body so we only get the attachments
    del atc[:serder.size]

    return serder, atc


def offer(hab, message, origin, artifacts=None, apply=None, recp=None, dt=None,
          kind=None, gvrsn=None, modifiers=None, attrs=None):
    """Create a signed V2 IPEX ``offer`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable offer message.
        origin (Serder | bytes | bytearray): Origin metadata artifact
            identified in ``a.o`` and carried as the first nested artifact.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            attached metadata artifacts carried after ``origin``.
        apply (Serder | None): Optional prior ``apply`` exchange.
        recp (str | None): Recipient AID. Defaults to the prior ``apply``
            sender; must be supplied directly for an offer-first exchange
            opened with no prior.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        modifiers (dict | None): Optional query-section fields for ``q``.
        attrs (dict | None): Optional extra payload fields.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Get the prior event (apply) and the party to address (its sender)
    prior = apply.said if apply is not None else ""

    # If offer is starting the flow, recp must be provided and xid is
    # generated locally. Otherwise infer both from the prior apply.
    if apply is None:
        if not recp:
            raise ValueError("recp is required when no prior apply is provided")
        xid = Diger(ser=Noncer().qb64b).qb64
        receiver = recp
    else:
        if not apply.ked.get("ri", ""):
            raise ValueError("prior exchange has no explicit receiver")
        if hab.pre != apply.ked["ri"]:
            raise ValueError("sender does not match prior exchange receiver")
        if recp is not None and recp != apply.ked["i"]:
            raise ValueError("recp does not match prior exchange sender")
        receiver = apply.ked["i"]
        pxid = apply.ked.get("x", "")
        if pxid:
            xid = pxid
        else:
            xid = ""
    data = dict(attrs) if attrs is not None else {}
    data["m"] = message
    data["o"] = _streamSerder(origin).said
    nests = [_normalizeNestedStream(origin)]
    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        for artifact in artifacts:
            nests.append(_normalizeNestedStream(artifact))
    mods = dict(modifiers) if modifiers else {}
    mods.setdefault("dp", [])

    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=prior,
        route="/ipex/offer",
        modifiers=mods,
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )

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
    if not offer.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if hab.pre != offer.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != offer.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = offer.ked["i"]
    pxid = offer.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
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


def grant(hab, recp, message, origin, artifacts=None, agree=None,
          dt=None, kind=None, gvrsn=None, attrs=None):
    """Create a signed V2 IPEX ``grant`` exchange with nested disclosure artifacts.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the disclosure.
        message (str): Human-readable disclosure message.
        origin (Serder | bytes | bytearray): Origin presentation or credential
            artifact identified in ``a.o`` and carried as the first nested
            artifact.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            attached proofs or supporting artifacts carried after ``origin``.
        agree (Serder | None): Optional prior ``agree`` exchange.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        attrs (dict | None): Optional extra payload fields.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    prior = agree.said if agree is not None else ""
    if agree is None:
        if not recp:
            raise ValueError("recp is required when no prior agree is provided")
        xid = Diger(ser=Noncer().qb64b).qb64
    else:
        if not agree.ked.get("ri", ""):
            raise ValueError("prior exchange has no explicit receiver")
        if hab.pre != agree.ked["ri"]:
            raise ValueError("sender does not match prior exchange receiver")
        if recp != agree.ked["i"]:
            raise ValueError("recp does not match prior exchange sender")
        pxid = agree.ked.get("x", "")
        if pxid:
            xid = pxid
        else:
            xid = ""
    data = dict(attrs) if attrs is not None else {}
    data["m"] = message
    data["o"] = _streamSerder(origin).said
    nests = [_normalizeNestedStream(origin)]

    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        for artifact in artifacts:
            nests.append(_normalizeNestedStream(artifact))

    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        xid=xid,
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
    if not grant.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if hab.pre != grant.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != grant.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = grant.ked["i"]
    pxid = grant.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
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
    if not spurned.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if spurned.ked["r"] == "/ipex/grant" and spurned.ked.get("p", ""):
        raise ValueError("only flow-starting grants may be spurned")
    if hab.pre != spurned.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != spurned.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = spurned.ked["i"]
    pxid = spurned.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
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
