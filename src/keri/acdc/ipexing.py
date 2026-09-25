# -*- encoding: utf-8 -*-
"""
keri.acdc.ipexing module

IPEx protocol service support (Issuance and Presentation Exchange)

"""

from collections import deque, namedtuple
from collections.abc import Mapping
from copy import deepcopy

from hio.help import ogler

from .. import Kinds, Protocols
from ..kering import (Colds, DuplicitousRegistryError, Ilks, MisanchorError,
                      MisbindingError, MissingAnchorError, MissingChainError,
                      MissingSenderKeyStateError, MisdigestError,
                      MisregistryError, MissequenceError, RootSealError,
                      UnverifiedBlindError, ValidationError, Vrsn_2_0, sniff)
from ..core import (BlindState, Blinder, BoundState, Counter, Codens, Diger, GenDex, Noncer,
                    Number, Prefixer, Saider, Schemer, SealEvent, SealSource, Serdery, Texter,
                    exchange, messagize)
from ..peer.exchanging import cloneMessage, verifyAttachments

logger = ogler.getLogger()

Ipexage = namedtuple("Ipexage", "apply offer agree grant admit spurn")
Ipex = Ipexage(apply="apply", offer="offer", agree="agree",
               grant="grant", admit="admit", spurn="spurn")

PreviousRoutes = {
    Ipex.offer: (Ipex.apply,),
    Ipex.agree: (Ipex.offer,),
    Ipex.grant: (Ipex.apply, Ipex.agree),
    Ipex.admit: (Ipex.grant,),
    Ipex.spurn: (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant),
}

DisclosedNodeIlks = (None, Ilks.acm, Ilks.ace, Ilks.act, Ilks.acg)
EdgeSectionLabels = ("d", "u", "o", "w")
EdgeGroupLabels = ("d", "u", "s", "o", "w")
EdgeNodeLabels = ("d", "u", "n", "s", "o", "w")
UnaryEdgeOps = ("I2I", "NI2I", "DI2I", "E1E", "NOT")
EdgeGroupOps = ("AND", "OR")

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


def _normalizeNodeStream(stream, attachment=None):
    """Normalize one disclosed ACDC node into a nested V2 substream.

    Parameters:
        stream (Serder | bytes | bytearray): ACDC body, body+attachments
            stream, or already-nested node stream.
        attachment (bytes | bytearray | None): Optional attachment section to
            pair with the ACDC body when ``stream`` is not already a stream
            carrying attachments.

    Returns:
        bytearray: Nested V2 body-with-attachments group for one ACDC node.
    """
    # Preserve a caller-supplied node substream when it is already framed the
    # way IPEX expects: one ACDC body plus that node's attachment section.
    if _isNestedStream(stream):
        serder = _streamSerder(stream)
        if serder.proto != Protocols.acdc or serder.ilk not in DisclosedNodeIlks:
            raise ValueError("IPEX node nests must carry disclosed ACDC nodes")
        if attachment:
            raise ValueError("cannot append attachment bytes to a pre-nested ACDC node")
        return bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)

    raw = bytes(stream.raw) if hasattr(stream, "raw") else bytes(stream)
    serder = _streamSerder(raw)
    if serder.proto != Protocols.acdc or serder.ilk not in DisclosedNodeIlks:
        raise ValueError("IPEX node nests must carry disclosed ACDC nodes")

    # Rebuild plain ACDC input into the same per-node framing so later proof
    # groups can live on the owning node without changing the outer layout.
    atc = raw[serder.size:] if attachment is None else bytes(attachment)
    return _normalizeNestedStream(raw[:serder.size] + atc)


def _validSingleDagList(value, itemtype):
    """Validate one of the single-item list fields used by single-DAG IPEX.

    Parameters:
        value: Candidate wire value for a single-DAG field such as ``o`` or
            ``ax``.
        itemtype (type): Required Python type for each outer-list entry.
    Returns:
        bool: True when ``value`` matches the current single-DAG wire shape,
            False otherwise.
    """

    # The single-DAG outer-wire contract for `o` and `ax` is a list that can
    # later grow for multi-DAG without changing field type.
    if not isinstance(value, list):
        return False

    # We currently only support one DAG (until Multi DAG), so exactly one entry is required.
    if len(value) != 1:
        return False

    # The inner item type differs by field:
    # - `o` carries one origin SAID string
    # - `ax` carries one boolean
    return all(isinstance(item, itemtype) for item in value)


def _validDisclosurePath(value):
    """Validate one DAG's disclose-path plan.

    Parameters:
        value: Candidate disclose-path list for one DAG.

    Returns:
        bool: True when ``value`` is a list whose entries are disclosure-path
            triples of ``[schema SAID, DAG path, ACDC paths]`` for one DAG.
            The DAG path is either ``"/"`` for the root node or a canonical
            edge-to-node prefix that starts and ends with ``/`` and terminates
            at the far-node hop ``"_/"`` such as ``"/e/holder/_/"``.
    """
    if not isinstance(value, list):
        return False

    for item in value:
        if not isinstance(item, list) or len(item) != 3:
            return False

        schema, path, fields = item
        if not isinstance(schema, str):
            return False
        if not isinstance(path, str):
            return False
        if path == "/":
            pass
        else:
            # Non-root DAG prefixes must point at a far-node hop so later
            # field paths append cleanly beneath that disclosed node.
            if not (path.startswith("/") and path.endswith("/")):
                return False

            segments = path.strip("/").split("/")
            if not segments or any(not isinstance(segment, str) or not segment for segment in segments):
                return False
            if segments[-1] != "_":
                return False

        if not isinstance(fields, list):
            return False
        if any(not isinstance(field, str) or not field for field in fields):
            return False

    return True


def _sign(hab, serder, *, nests=None, anchor=False, endorsers=None,
          anchorers=None, gvrsn=None):
    """Sign and messagize an outer IPEX exchange with optional nested streams.

    Parameters:
        hab (Hab): Habitat used to sign the outer exchange.
        serder (Serder): Outer exchange serder to sign.
        nests (list[bytes | bytearray] | None): Optional nested substreams to
            append in the outer attachment section.
        anchor (bool): True creates a permitted KEL event sealing
            ``serder.said`` and attaches its source-seal couple to the exchange.
        endorsers (list[Hab] | None): Additional local habitats that sign the
            same outer exchange as non-sender grantors (e.g proxy AIDs).
        anchorers (list[Hab] | None): Additional local transferable habitats
            whose KELs seal the same outer exchange.
        gvrsn (Versionage | None): Optional CESR genus version override for the
            attachment and nesting groups.

    Returns:
        bytearray: Full signed exchange stream including the outer message body,
            attachments, and any nested substreams.
    """
    gvrsn = gvrsn if gvrsn is not None else Vrsn_2_0
    nests = nests if nests else None

    # Copy caller lists before filtering or iterating them.
    endorsers = list(endorsers or [])
    anchorers = list(anchorers or [])

    # Collect sender and non-sender source references together.
    bonds = []

    # Validate every additional Grant authentication habitat.
    for endorser in endorsers + anchorers:

        # Local signing requires access to the same hab
        if endorser.db is not hab.db:
            raise ValueError("additional grantors must belong to the sender's Habery")

        # The sender is already authenticated separately
        if endorser.pre == hab.pre:
            raise ValueError("sender must not be repeated as an additional grantor")

    if anchor:
        # Only transferable identifiers can append the KEL event that carries the seal.
        if not hab.kever.prefixer.transferable:
            raise ValueError("anchored IPEX exchanges require a transferable sender")

        kwa = dict(data=[dict(d=serder.said)],
                   kind=hab.kever.serder.kind,
                   version=hab.kever.serder.pvrsn,
                   gvrsn=gvrsn)

        anc = None
        if hab.kever.estOnly:
            # Establishment Only KELs reject interactions, so advance key state with a rotation.
            anc = hab.rotate(**kwa)
        else:
            # Normal KELs use a cheaper interaction that leaves key state unchanged.
            anc = hab.interact(**kwa)

        aserder = _streamSerder(anc)

        # Add the seal to the exchange's source-seal list
        bonds.append(SealSource(s=aserder.snh, d=aserder.said))

    # Create one explicit source seal for each additional anchorer.
    for anchorer in anchorers:

        # Non-transferable AIDs cannot create KEL anchors.
        if not anchorer.kever.prefixer.transferable:
            raise ValueError("anchored IPEX endorsements require transferable AIDs")

        # Seal the immutable outer EXN SAID in the anchorer's KEL.
        kwa = dict(data=[dict(d=serder.said)],
                   kind=anchorer.kever.serder.kind,
                   version=anchorer.kever.serder.pvrsn,
                   gvrsn=gvrsn)

        # Respect Establishment Only KEL policy when creating the seal.
        anc = anchorer.rotate(**kwa) if anchorer.kever.estOnly else anchorer.interact(**kwa)

        # Parse the emitted KEL event for attachment coordinates.
        aserder = _streamSerder(anc)

        # Explicitly name the non-sender anchorer in a source triple.
        bonds.append(SealEvent(i=anchorer.pre, s=aserder.snh, d=aserder.said))

    # Sign after anchoring so an Establishment Only rotation's new keys and lastEst are used.
    # Collect transferable signature groups separately from cigars.
    tsgs = []
    cigars = []

    # Sign the outer EXN with the sender's current key state.
    if hab.kever.prefixer.transferable:
        # Transferable senders produce indexed signatures.
        sigers = hab.sign(ser=serder.raw, indexed=True)

        # Bind those signatures to the sender's latest establishment event.
        tsgs.append((hab.kever.prefixer,
                     Number(sn=hab.kever.lastEst.s),
                     Diger(qb64=hab.kever.lastEst.d),
                     sigers))
    else:
        # Non-transferable senders authenticate with cigars.
        cigars.extend(hab.sign(ser=serder.raw, indexed=False))

    # Add each requested non-sender signature endorsement.
    for endorser in endorsers:

        # Transferable endorsers identify their current establishment state.
        if endorser.kever.prefixer.transferable:
            tsgs.append((endorser.kever.prefixer,
                         Number(sn=endorser.kever.lastEst.s),
                         Diger(qb64=endorser.kever.lastEst.d),
                         endorser.sign(ser=serder.raw, indexed=True)))
        else:
            # Non-transferable endorsers contribute unindexed signatures.
            cigars.extend(endorser.sign(ser=serder.raw, indexed=False))

    # Serialize the EXN with all selected authentication factors and nests.
    return messagize(serder=serder,
                     tsgs=tsgs or None,
                     cigars=cigars or None,
                     bonds=bonds or None,
                     nests=nests,
                     framed=False,
                     gvrsn=gvrsn)


class IpexHandler:
    """Verify and handle the linear V2 IPEX `exn` workflow."""

    # Receive validated sender source couples from Exchanger.
    acceptsSscs = True
    # Receive route-filtered non-sender evidence from Exchanger.
    acceptsEvidence = True

    def __init__(self, resource, hby, notifier, rgy=None):
        """Create a handler for one IPEX route.

        Parameters:
            resource (str): Route string handled by this instance.
            hby (Habery): Habitat environment and backing database.
            notifier: Notifier-like object with an ``add`` method.
            rgy (Regery | None): Optional local registry manager used when a
                disclosed node's ``rd`` requires verifier-side issuer-auth checks.

        Returns:
            None
        """
        self.resource = resource
        self.hby = hby
        self.notifier = notifier
        self.rgy = rgy
        # Only Grant treats unresolved non-sender evidence as optional. Other
        # IPEX verbs continue rejecting foreign evidence before persistence.
        # Store this policy per route-specific handler instance.
        self.acceptsMissingEvidence = resource == "/ipex/grant"

    def verify(self, serder, attachments=None, nests=None, sscs=None,
               evidence=None):
        """Validate the verb, prior link, and single-response rule.

        Parameters:
            serder (Serder): Incoming IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused in the
                current linear workflow validation.
            nests (list | None): Parsed V2 nested artifacts. In the current
                single-DAG workflow ``offer`` may carry a metadata DAG subset
                and ``grant`` may carry the final disclosed DAG.
            sscs (list | None): Sender source-seal couples retained after KRAM.
            evidence (tuple | None): Post-KRAM non-sender signature groups,
                cigars, and source-seal triples accepted by ``verifyEvidence``.

        Returns:
            bool: True when the message is valid for the linear IPEX workflow,
                False otherwise.

        Raises:
            MissingChainError: When a grant's issuer-auth proof needs TEL
                evidence that is not yet available locally and the exchange
                should be retried from escrow later.
            MissingSenderKeyStateError: When a required sender anchor refers
                to KEL evidence that is not yet available locally.
        """
        nests = nests if nests is not None else []
        sscs = sscs if sscs is not None else []

        # Normalize absent supplemental evidence to an empty accepted set.
        evidence = evidence if evidence is not None else ([], [], [])
        q = serder.ked.get("q")
        attrs = serder.ked["a"]
        dig = serder.ked["p"]

        route = serder.ked["r"]
        parts = route.split("/")
        if len(parts) != 3 or parts[:2] != ["", "ipex"]:
            return False

        verb = parts[2]
        if verb not in (Ipex.apply, *PreviousRoutes.keys()):
            return False

        # Stage 1: every inbound IPEX message must at least carry an attrs map
        # with a human message and a query/modifier map. `ax` is the only shared
        # optional list field.
        if not isinstance(attrs, dict) or "m" not in attrs or not isinstance(q, dict):
            return False
        if "ax" in attrs and not _validSingleDagList(attrs["ax"], bool):
            return False

        # Stage 2: apply/offer carry disclose-paths. The wire shape is now one
        # disclose-path list per DAG, so today's single-DAG form is a one-item
        # outer list. Offer may optionally name or carry a metadata DAG in
        # `a.o[0]`, while grant must name and carry the final disclosed DAG
        # root.
        if verb in (Ipex.apply, Ipex.offer):
            if ("dp" not in q
                    or not _validSingleDagList(q["dp"], list)
                    or not _validDisclosurePath(q["dp"][0])):
                return False
            if verb == Ipex.offer and not dig and not q["dp"][0]:
                return False

        if verb == Ipex.offer:
            if "o" in attrs:
                if not _validSingleDagList(attrs["o"], str):
                    return False
                try:
                    Saider(qb64=attrs["o"][0])
                except Exception:
                    return False
            elif nests:
                return False
        elif verb == Ipex.grant:
            if "o" not in attrs or not _validSingleDagList(attrs["o"], str) or not nests:
                return False
            try:
                Saider(qb64=attrs["o"][0])
            except Exception:
                return False

        # The other verbs never disclose nested ACDC nodes.
        elif nests:
            return False

        # Stage 3: opener flows validate directly from the message itself,
        # while replies must first resolve and validate their prior exchange.
        pserder = None
        if not dig:
            if verb == Ipex.apply:
                # Apply is always a thread opener, so it must provide both
                # receiver and transaction id on the message body.
                if not (serder.ked.get("ri", "") and serder.ked.get("x", "")):
                    return False
            elif verb in (Ipex.offer, Ipex.grant):
                # Offer and grant may also open a thread, but must then carry
                # both the receiver and the generated exchange id themselves.
                if not (serder.ked.get("ri", "") and serder.ked.get("x", "")):
                    return False
            else:
                # Agree, admit, and spurn can only appear as replies.
                return False
        elif verb == Ipex.apply:
            return False
        else:
            # Retrieve prior serder
            pserder = self._verifyReplyChain(verb=verb, serder=serder, dig=dig)
            if pserder is None:
                return False

        # Stage 4: enforce the anchoring negotiation and verify direct sender
        # KEL anchors on the messages that make the binding commitments.
        messageAx = attrs.get("ax", [False])
        messageRequiresAnchor = messageAx[0] is True
        priorRequiresAnchor = False
        if pserder is not None:
            priorAx = pserder.ked.get("a", {}).get("ax", [False])
            priorRequiresAnchor = priorAx[0] is True

            if verb in (Ipex.agree, Ipex.grant, Ipex.admit):
                # Binding replies must exactly preserve the negotiated state.
                if messageRequiresAnchor != priorRequiresAnchor:
                    return False
            elif verb == Ipex.offer:
                # An offer may initiate anchoring, but may not drop it.
                if priorRequiresAnchor and not messageRequiresAnchor:
                    return False

        # Inherit anchoring when either the message or its prior requires it.
        requiresAnchor = messageRequiresAnchor or priorRequiresAnchor

        # Agree and Admit satisfy anchoring directly through their sender.
        if verb in (Ipex.agree, Ipex.admit) and requiresAnchor:
            # Anchored replies must carry a validated sender source couple.
            if not sscs:
                return False
            # Verify the newest supplied sender source reference.
            if not self._verifySourceAnchor(serder=serder,
                                            aid=serder.pre,
                                            number=sscs[-1][0],
                                            diger=sscs[-1][1]):
                return False

        # Stage 5: offer may disclose only a reachable metadata subgraph,
        # while grant must disclose one fully closed reachable DAG rooted at
        # the message's `a.o[0]`.
        if verb == Ipex.offer and nests:
            if self._walkGraph(origin=attrs["o"][0], nests=nests, closed=False) is None:
                return False
        elif verb == Ipex.grant:
            walked = self._walkGraph(origin=attrs["o"][0], nests=nests, closed=True)
            if walked is None:
                return False
            if not self._verifyGraphSemantics(nodes=walked[0], order=walked[1]):
                return False

            # Stage 6: after the disclosed graph shape is accepted, each walked
            # registry-backed node must vet its own node-local proof group.
            if not self._verifyIssuerAuthGraph(nodes=walked[0], order=walked[1]):
                return False

            # Require Exchanger's fixed three-part evidence result.
            try:
                _, _, extraSeals = evidence
            except (TypeError, ValueError):
                return False

            # Verify every presentation registry declared across the DAG.
            tethered = self._verifyPresentationAuthGraph(
                serder=serder,
                nodes=walked[0],
                order=walked[1],
            )

            # Reject any malformed, missing, or invalid presentation factor.
            if tethered is None:
                return False

            # A truthy ax requires one permitted Grant anchorer.
            if requiresAnchor:
                # Resolve the origin ACDC named by the Grant.
                origin = walked[0][attrs["o"][0]]
                origin = origin["serder"] if isinstance(origin, dict) else origin.serder

                # Presentation registries authenticate their controlling Issuees.
                anchorers = set(tethered)

                # Count a valid direct sender anchor when supplied.
                if sscs and self._verifySourceAnchor(serder=serder,
                                                     aid=serder.pre,
                                                     number=sscs[-1][0],
                                                     diger=sscs[-1][1]):
                    anchorers.add(serder.pre)

                # Check each accepted non-sender source seal.
                for prefixer, number, diger in extraSeals:
                    if self._verifySourceAnchor(serder=serder,
                                                aid=prefixer.qb64,
                                                number=number,
                                                diger=diger):
                        # Record the AID whose KEL actually seals this Grant.
                        anchorers.add(prefixer.qb64)

                # Default IPEX policy deliberately stops at these three AIDs;
                # credential-specific policy may impose a narrower requirement.
                # Restrict default qualification to sender, Issuee, or issuer.
                candidates = (serder.pre, origin.iseaid, origin.israid)

                # Require at least one qualifying authenticated anchorer.
                if not any(aid and aid in anchorers for aid in candidates):
                    return False

        return True

    def _verifySourceAnchor(self, serder, aid, number, diger):
        """Verify one source reference against the anchorer's current Kever."""

        # Resolve the anchorer's verified current key state.
        kever = self.hby.db.kevers.get(aid)
        # Missing key state is retryable after KEL retrieval.
        if kever is None:
            raise MissingSenderKeyStateError(f"missing current key state for {aid}")

        # Compare the source reference with the current establishment state.
        lastEst = kever.lastEst
        # Reject references older than the current key state.
        if number.sn < lastEst.s:
            return False
        # Require an exact SAID at the current establishment sequence number.
        if number.sn == lastEst.s and diger.qb64 != lastEst.d:
            return False

        # Resolve the referenced event from the anchorer's accepted KEL.
        prefix = aid.encode("utf-8")
        eventSaid = self.hby.db.kels.getLast(keys=prefix, on=number.sn)

        # A missing event can become verifiable after KEL retrieval.
        if eventSaid is None:
            raise MissingSenderKeyStateError(
                f"missing KEL event at sn={number.sn} for {aid}")
        # Reject a digest that does not match the accepted event at this SN.
        if eventSaid != diger.qb64:
            return False

        # Load the event body needed to inspect its seals.
        event = self.hby.db.evts.get(keys=(prefix, diger.qb64b))
        # Treat a missing accepted event body as retryable KEL evidence.
        if event is None:
            raise MissingSenderKeyStateError(
                f"missing KEL event body at sn={number.sn} for {aid}")
        # References after lastEst must name interaction events.
        if number.sn > lastEst.s and event.ilk != Ilks.ixn:
            return False

        # Inspect every event seal for the outer IPEX SAID.
        for seal in event.seals or []:
            # Accept only a mapping that anchors this exact message.
            if isinstance(seal, Mapping) and seal.get("d") == serder.said:
                return True

        # Reject a valid KEL event that does not anchor this message.
        return False

    def _validNodeNest(self, origin, nests):
        """Validate disclosed node nests and index them by ACDC SAID.

        Parameters:
            origin (str): SAID of the origin node named in ``a.o[0]``.
            nests (list): Parsed nested ACDC node substreams.

        Returns:
            dict | None: Mapping of disclosed node SAID to its parsed nest when
                every nest is a unique ACDC node and the first nest matches the
                origin; otherwise None.
        """
        nodes = {}
        for idx, nest in enumerate(nests):
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
            if not nserder.verify():
                return None
            # Each nest must carry a real disclosed credential node, not just
            # any ACDC-protocol message such as a registry TEL event.
            if nserder.proto != Protocols.acdc or nserder.ilk not in DisclosedNodeIlks:
                return None
            if idx == 0 and not nserder.compare(origin):
                return None
            # Each disclosed DAG node must occupy exactly one nest so the node
            # body cannot appear twice with conflicting attachment groups.
            if nserder.said in nodes:
                return None
            nodes[nserder.said] = nest

        return nodes

    def _verifyReplyChain(self, verb, serder, dig):
        """Validate the prior-link rules for a reply inside an IPEX thread.

        Parameters:
            verb (str): IPEX route suffix for the reply being checked.
            serder (Serder): Incoming reply exchange message.
            dig (str): SAID of the prior message named by ``serder.ked["p"]``.

        Returns:
            Serder | None: The accepted prior when the reply points to an
                allowed message, keeps sender/receiver roles consistent, and
                does not duplicate an existing response; otherwise None.
        """
        pserder, _ = cloneMessage(self.hby, said=dig)
        if pserder is None:
            return None

        # Replies must point at the allowed prior verb in the linear IPEX chain.
        proute = pserder.ked["r"]
        pparts = proute.split("/")
        if len(pparts) != 3 or pparts[:2] != ["", "ipex"]:
            return None
        pverb = pparts[2]
        if pverb not in PreviousRoutes[verb]:
            return None
        if verb == Ipex.spurn and pverb == Ipex.grant and pserder.ked.get("p", ""):
            return None

        # Replies must target the prior sender and come from the prior receiver
        if serder.ked.get("ri", "") != pserder.ked.get("i", ""):
            return None
        preceiver = pserder.ked.get("ri", "")
        if not preceiver:
            return None
        if serder.ked.get("i", "") != preceiver:
            return None
        if serder.ked.get("x", "") != pserder.ked.get("x", ""):
            return None

        if self.response(pserder) is not None:
            return None

        return pserder

    def _walkGraph(self, origin, nests, *, closed):
        """Walk the disclosed origin DAG and return the visited node order.

        Parameters:
            origin (str): SAID of the origin node named by ``a.o[0]``.
            nests (list): Parsed nested ACDC node substreams carried by the
                offer or grant message.
            closed (bool): True requires every referenced edge target to be
                carried in ``nests``. False allows undisclosed far nodes, but
                every carried nest must still be reachable from ``origin``.

        Returns:
            tuple | None: ``(nodes, order)`` when the disclosed nests form one
                reachable disclosed graph rooted at ``origin`` under the
                selected closure rule; otherwise ``None``.
        """
        # Reuse the disclosed-node validation so graph walking starts from a
        # well-formed set of unique ACDC nests.
        nodes = self._validNodeNest(origin=origin, nests=nests)
        if nodes is None:
            return None

        # Reject if origin is not carried in the nests
        if origin not in nodes:
            return None

        # Use deque for BFS traversal so we start at the disclosed origin and
        # then fan out across every referenced child node in graph order.
        seen = set()
        order = []
        queue = deque([origin])

        # Walk the graph BFS. Grant fails closed on dangling references, while
        # offer may omit farther undisclosed nodes as long as carried nodes
        # still form one root-reachable subgraph.
        while queue:
            said = queue.popleft()
            if said in seen:
                continue
            seen.add(said)
            order.append(said)

            nest = nodes[said]
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Retrieve the edges from the node
            edges = nserder.sad.get("e")
            if edges:
                if isinstance(edges, Mapping):
                    blocks = [edges]
                elif isinstance(edges, list) and all(isinstance(edge, Mapping) for edge in edges):
                    blocks = edges
                else:
                    return None

                # Expanded edge sections may contain nested edge groups
                for edge in blocks:
                    groups = [(edge, False)]
                    while groups:
                        group, nested = groups.pop()
                        labels = EdgeGroupLabels if nested else EdgeSectionLabels   # Leaf vs group labels
                        if "n" in group:
                            for label in group:
                                if label not in EdgeNodeLabels:
                                    return None
                            edgeSaid = group.get("n")
                            if not isinstance(edgeSaid, str):
                                return None
                            try:
                                Saider(qb64=edgeSaid)
                            except Exception:
                                return None
                            if edgeSaid not in nodes:
                                if closed:
                                    return None
                                continue
                            if edgeSaid not in seen:
                                queue.append(edgeSaid)
                            continue

                        for label, node in group.items():
                            if label in labels:
                                continue
                            if not isinstance(node, Mapping):
                                return None
                            groups.append((node, True))

        # Even when offer omits farther nodes, every carried nest must still be
        # part of the root-reachable disclosed graph.
        if len(seen) != len(nodes):
            return None

        return nodes, order

    def _evaluateLeafEdge(self, group, *, nodes, nserder, inheritedSchema):
        """Evaluate one disclosed leaf edge against its referenced far node.

        Parameters:
            group (Mapping): Leaf edge mapping that must carry an ``n`` field
                naming the far-node SAID, and may carry a string or non-empty
                list of strings in ``o`` plus a schema pin in ``s``.
            nodes (dict): Mapping of disclosed node SAIDs to parsed nests built
                during the origin-graph walk.
            nserder (Serder): Serder for the current near node whose edge block
                is being evaluated.
            inheritedSchema (str | Mapping | None): Optional schema pin passed
                down from a parent edge group.

        Returns:
            bool | None: ``True`` when the leaf edge semantics are satisfied,
                ``False`` when the leaf is well-formed but its relation or
                schema constraints do not match, including recognized operators
                that this verifier cannot yet evaluate, or ``None`` when the
                leaf shape itself is malformed and verification must fail
                closed.
        """
        # Reject unknown leaf labels before we inspect the reference.
        for label in group:
            if label not in EdgeNodeLabels:
                return None

        # Resolve the far node that this edge claims to reference.
        edgeSaid = group.get("n")
        if edgeSaid not in nodes:
            return None
        far = nodes[edgeSaid]
        fserder = far["serder"] if isinstance(far, dict) else far.serder

        # Normalize one operator or a list of operators.
        op = group.get("o")
        if op is None:
            recognizedOps = ()
        elif isinstance(op, str):
            recognizedOps = (op,)
        elif (isinstance(op, list) and op
              and all(isinstance(operator, str) for operator in op)):
            recognizedOps = tuple(op)
        else:
            return None

        # Every declared unary operator must be recognized.
        if any(operator not in UnaryEdgeOps for operator in recognizedOps):
            return None

        # Recognized but unevaluated leaf operators fail as unsatisfied
        # relations instead of malformed input.
        if "NOT" in recognizedOps or "DI2I" in recognizedOps:
            return False

        # Start from a passing state, then knock the edge down to False if
        # any required relation check fails.
        matched = True
        if "E1E" in recognizedOps:
            if (not nserder.iseaid
                    or not fserder.iseaid
                    or nserder.iseaid != fserder.iseaid):
                matched = False

        # I2I compares the near issuer to the far Issuee. NI2I is explicitly
        # non-delegative and therefore adds no issuer-to-Issuee equality.
        if matched and "I2I" in recognizedOps:
            if not fserder.iseaid:
                matched = False
            elif nserder.israid != fserder.iseaid:
                matched = False

        # A leaf may pin the far node's schema directly, otherwise it
        # inherits the schema pin from its parent group.
        edgeSchema = group["s"] if "s" in group else inheritedSchema
        if matched and edgeSchema is not None:
            edgeSchemer = None
            if isinstance(edgeSchema, str):
                edgeSchemaId = edgeSchema
            elif isinstance(edgeSchema, Mapping):
                declared = edgeSchema.get("$id")
                if not isinstance(declared, str):
                    return None
                try:
                    edgeSchemer = Schemer(sed=deepcopy(edgeSchema))
                except (ValidationError, ValueError):
                    return None
                if edgeSchemer.said != declared:
                    return None
                edgeSchemaId = edgeSchemer.said
            else:
                return None

            farSchema = fserder.schema
            if isinstance(farSchema, Mapping):
                farSchemaId = farSchema.get("$id")
            elif isinstance(farSchema, str):
                farSchemaId = farSchema
            else:
                return None
            if not isinstance(farSchemaId, str):
                return None

            # A direct schema SAID match is enough. Otherwise load or build
            # the schema and verify the far node against it.
            if edgeSchemaId != farSchemaId:
                if edgeSchemer is None:
                    edgeSchemer = self.hby.db.schema.get(edgeSchemaId)
                    if edgeSchemer is None:
                        return None
                try:
                    edgeSchemer.verify(fserder.raw)
                except ValidationError:
                    matched = False

        return matched

    def _evaluateGroupEdge(self, group, *, nodes, nserder, nested, inheritedSchema):
        """Evaluate one disclosed edge group and reduce its child results.

        Parameters:
            group (Mapping): Edge-section or nested edge-group mapping whose
                child entries are either more groups or leaf edges.
            nodes (dict): Mapping of disclosed node SAIDs to parsed nests built
                during the origin-graph walk.
            nserder (Serder): Serder for the current near node whose edge block
                is being evaluated.
            nested (bool): ``True`` when ``group`` is a nested edge group and
                therefore allows group-only labels like ``s``; ``False`` for a
                top-level edge section.
            inheritedSchema (str | Mapping | None): Optional schema pin passed
                down from the parent edge group.

        Returns:
            bool | None: ``True`` when the group is well-formed and its child
                results satisfy the group's ``AND`` or ``OR`` semantics,
                ``False`` when the group is well-formed but the reduced child
                result fails, or ``None`` when the group shape is malformed and
                verification must fail closed.
        """
        # Top-level edge sections and nested edge groups allow slightly
        # different reserved labels, so choose the right set up front.
        labels = EdgeGroupLabels if nested else EdgeSectionLabels

        # Nested groups may contribute an m-ary operator and a shared schema
        # pin for every child below them.
        groupOp = group.get("o", "AND")
        if not isinstance(groupOp, str) or groupOp not in EdgeGroupOps:
            return None

        # Nested groups can pin one schema for every child below them.
        nextSchema = group.get("s", inheritedSchema) if nested else inheritedSchema
        results = []
        for label, node in group.items():
            if label in labels:
                continue
            if not isinstance(node, Mapping):
                return None

            # Recurse into each child and fail closed if any child is malformed.
            if "n" in node:
                matched = self._evaluateLeafEdge(node,
                                                 nodes=nodes,
                                                 nserder=nserder,
                                                 inheritedSchema=nextSchema)
            else:
                matched = self._evaluateGroupEdge(node,
                                                  nodes=nodes,
                                                  nserder=nserder,
                                                  nested=True,
                                                  inheritedSchema=nextSchema)
            if matched is None:
                return None
            results.append(matched)

        if not results:
            return None

        # Reduce the child booleans according to the group's operator.
        return any(results) if groupOp == "OR" else all(results)

    def _verifyGraphSemantics(self, nodes, order):
        """Verify grant edge operators and edge-schema pins across walked nodes.

        Parameters:
            nodes (dict): Mapping of disclosed node SAID to parsed nest.
            order (list): Breadth-first walk order returned by ``_walkGraph``.

        Returns:
            bool: True when every walked edge block is well-formed and its
                leaf-level and group-level operator/schema constraints are
                satisfied; False on any malformed or violated edge semantics.
        """
        for said in order:
            # Current near node from the walked grant DAG
            near = nodes[said]

            # Retrieve node serder
            nserder = near["serder"] if isinstance(near, dict) else near.serder

            # No edges means nothing more to validate for this node
            edges = nserder.sad.get("e")
            if not edges:
                continue

            # Normalize a single edge block or a list of edge blocks
            if isinstance(edges, Mapping):
                blocks = [edges]
            elif isinstance(edges, list) and all(isinstance(edge, Mapping) for edge in edges):
                blocks = edges
            else:
                return False

            for edge in blocks:
                # Evaluate the whole edge tree from the root down. Each leaf
                # returns one boolean and each group reduces its child booleans
                # with AND/OR using any inherited schema pin.
                if "n" in edge:
                    matched = self._evaluateLeafEdge(edge,
                                                     nodes=nodes,
                                                     nserder=nserder,
                                                     inheritedSchema=None)
                else:
                    matched = self._evaluateGroupEdge(edge,
                                                      nodes=nodes,
                                                      nserder=nserder,
                                                      nested=False,
                                                      inheritedSchema=None)
                if matched is not True:
                    return False

        return True

    def _verifyIssuerAuthGraph(self, nodes, order):
        """Verify issuer-auth proof groups for each walked disclosed DAG node.

        Parameters:
            nodes (dict): Mapping of disclosed node SAID to parsed nest.
            order (list): Breadth-first walk order returned by ``_walkGraph``.

        Returns:
            bool: True when every walked node has a valid issuer registry,
                direct KEL anchor, or current issuer signature factor.

        Raises:
            MissingChainError: When an issuer factor names KEL or TEL evidence
                that the verifier has not loaded locally yet.
        """
        # Run proof verification in graph order so each registry-backed node is
        # checked against the exact nested substream that carried its body.
        for said in order:

            # Resolve the node-local body and attachments.
            nest = nodes[said]

            # Read the ACDC body from either parsed representation.
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Require one valid issuer authentication factor per node.
            if not self._verifyIssuerAuthNode(serder=nserder, nest=nest):
                return False

        # Every disclosed node passed issuer authentication.
        return True

    def _verifyIssuerAuthNode(self, serder, nest):
        """Verify one ACDC using its declared issuer authentication factor."""

        # Authentication Factor 1: Registry
        # First check if a registry was declared, if so verify it
        regk = serder.sad.get("rd")
        if regk:
            record = self._vetRegistry(regk=regk,
                                       proofs=self._blindProofs(nest),
                                       target=serder.said,
                                       acdc=serder)
            if record is None:
                return False
            return True

        # An inner rd without a top-level rd selects the unsupported hidden
        # issuer-registry form; it must not fall through to another factor.
        if self._presentationRegistries(serder) is None:
            return False

        # Authentication Factor 2: Seal Anchor
        # Registry-less ACDCs must identify a direct issuer AID.
        issuer = serder.israid

        # Reject a credential with no issuer authentication identity.
        if not issuer:
            return False

        # Parse the issuer identifier before processing attachments.
        try:
            prefixer = Prefixer(qb64=issuer)
        except Exception:
            return False

        # Normalize object and dictionary nest representations.
        parsed = nest if isinstance(nest, dict) else nest.__dict__

        # Check for any Seal anchor attachments that may be supplied by the issuer.
        # Convert issuer-implied source couples into explicit triples.
        sourceSeals = [(prefixer, number, diger)
                       for number, diger in parsed.get("sscs", [])]

        # Keep only explicit source triples from the issuer.
        sourceSeals.extend((sealer, number, diger)
                           for sealer, number, diger in parsed.get("ssts", [])
                           if sealer.qb64 == issuer)

        # A supplied issuer seal selects anchor authentication.
        if sourceSeals:
            # Verify every candidate seal against local issuer KEL evidence.
            _, _, validSeals, _, missing = verifyAttachments(
                hby=self.hby,
                serder=serder,
                sourceSeals=sourceSeals,
            )
            # Missing KEL evidence makes this node retryable.
            if missing:
                raise MissingChainError(
                    f"missing issuer KEL evidence for ACDC {serder.said}")

            # A supplied issuer anchor is the selected factor. An invalid anchor
            # must not silently downgrade the ACDC to signature authentication.
            return bool(validSeals)

        # Authentication Factor 3: Signatures
        # Fall back to signature verification when no registry or anchor is supplied
        tsgs = []

        # Resolve the issuer's current key state.
        kever = self.hby.db.kevers.get(issuer)

        # Read bare indexed signatures from the node stream.
        sigers = parsed.get("sigers", [])

        # Keep explicit signature groups belonging to the issuer.
        issuerTsgs = [tsg for tsg in parsed.get("tsgs", [])
                      if tsg[0].qb64 == issuer]

        # Keep last-establishment groups belonging to the issuer.
        issuerLsgs = [lsg for lsg in parsed.get("lsgs", [])
                      if lsg[0].qb64 == issuer]

        # Transferable evidence must resolve against current issuer keys.
        if prefixer.transferable and (sigers or issuerTsgs or issuerLsgs):

            # Missing current state makes signature verification retryable.
            if kever is None:
                raise MissingChainError(
                    f"missing current issuer key state for ACDC {serder.said}")

            # Build the current establishment coordinates once.
            number = Number(sn=kever.lastEst.s)
            diger = Diger(qb64=kever.lastEst.d)

            # Bind bare signatures to the current issuer state.
            if sigers:
                tsgs.append((prefixer, number, diger, sigers))

            # Keep explicit groups that already name the current state.
            tsgs.extend(tsg for tsg in issuerTsgs
                        if tsg[1].sn == kever.lastEst.s
                        and tsg[2].qb64 == kever.lastEst.d)

            # Resolve last-establishment groups to the current state.
            tsgs.extend((sealer, number, diger, lsigers)
                        for sealer, lsigers in issuerLsgs)

        # Keep only non-transferable signatures made by the issuer.
        cigars = [cigar for cigar in parsed.get("cigars", [])
                  if cigar.verfer.qb64 == issuer]

        # Cryptographically verify all selected issuer signatures.
        validTsgs, validCigars, _, _, missing = verifyAttachments(
            hby=self.hby,
            serder=serder,
            tsgs=tsgs,
            cigars=cigars,
        )
        # Missing establishment events make verification retryable.
        if missing:
            raise MissingChainError(
                f"missing current issuer KEL evidence for ACDC {serder.said}")

        # Require at least one valid current issuer signature.
        return bool(validTsgs or validCigars)

    @staticmethod
    def _blindProofs(nest):
        """Rebuild all parsed node-local blind disclosures as Blinders."""
        # Read sequenced blind disclosures from the parsed node.
        bsqs = nest.get("bsqs", []) if isinstance(nest, dict) else nest.bsqs

        # Read bound blind disclosures from the parsed node.
        bsss = nest.get("bsss", []) if isinstance(nest, dict) else nest.bsss

        # Rebuild each sequenced disclosure as a BlindState proof.
        proofs = []
        for proof in bsqs:
            stream = b''.join(item.qb64b for item in proof)
            proofs.append(Blinder(clan=BlindState, qb64=stream))

        # Rebuild each bound disclosure as a BoundState proof.
        for proof in bsss:
            stream = b''.join(item.qb64b for item in proof)
            proofs.append(Blinder(clan=BoundState, qb64=stream))

        # Return every proof attached to this one ACDC node.
        return proofs

    def _registryEvidence(self, regk):
        """Load one complete accepted TEL chain from the injected store."""
        # Registry verification requires an injected local Regery.
        if self.rgy is None:
            return None

        # Load the registry inception and current accepted head.
        rip = self.rgy.store.seqEvent(regk, 0)
        head = self.rgy.store.headEvent(regk)

        # Missing either of them mean the local TEL chain is incomplete.
        if rip is None or head is None:
            raise MissingChainError(f"missing local TEL evidence for registry {regk}")

        # Rebuild the contiguous accepted update chain in sequence order.
        updates = []
        for sn in range(1, Number(numh=head.sad["n"]).num + 1):

            # Load the accepted event at this sequence number.
            update = self.rgy.store.seqEvent(regk, sn)

            # A sequence gap must be retrieved before retrying.
            if update is None:
                raise MissingChainError(f"missing local TEL update {sn} for registry {regk}")

            # Preserve this contiguous update for TEL verification.
            updates.append(update)

        # Return the complete local chain.
        return rip, updates

    def _vetRegistry(self, regk, proofs, target, controller=None, acdc=None,
                     cutoff=None, sourceSeals=None, requireSource=False):
        """Vet one issuer or presentation registry using matching BLIDs."""

        # Require disclosed proofs and a locally available TEL chain.
        if not proofs or (evidence := self._registryEvidence(regk)) is None:
            return None

        # Import lazily to avoid the ACDC module cycle.
        from . import regeventing
        try:
            # Resolve node-local source triples into exact TEL anchor claims.
            sources = {}
            unresolved = False
            if requireSource:
                for prefixer, number, diger in sourceSeals or []:
                    if prefixer.qb64 != controller:
                        continue

                    # Resolve the claimed source event from the Issuee's KEL.
                    eventSaid = self.hby.db.kels.getLast(
                        keys=prefixer.qb64b, on=number.sn)
                    if eventSaid is None:
                        unresolved = True
                        continue

                    # A known different event makes this source claim invalid.
                    if eventSaid != diger.qb64:
                        continue

                    # The event body may arrive after its KEL coordinate is known.
                    event = self.hby.db.evts.get(
                        keys=(prefixer.qb64b, diger.qb64b))
                    if event is None:
                        unresolved = True
                        continue

                    # Match the source only to TEL events it actually seals.
                    for update in evidence[1]:
                        if regeventing._verifyAnchorCouple(
                                update,
                                db=self.hby.db,
                                issuer=controller,
                                number=number,
                                diger=diger):
                            sources[update.said] = diger.qb64

                # An unavailable attached source is retryable after KEL retrieval.
                if not sources and unresolved:
                    raise MissingChainError(
                        f"missing presentation anchor source for registry {regk}")

            # Verify the TEL and its latest disclosed target binding.
            record = regeventing.vetBinds(rip=evidence[0],
                                          updates=evidence[1],
                                          db=self.hby.db,
                                          blinders=proofs,
                                          target=target,
                                          controller=controller,
                                          acdc=acdc,
                                          cutoff=cutoff,
                                          sources=sources,
                                          requireSource=requireSource)

            # Require the vetted chain to be the registry named by the ACDC.
            if record.regid != regk:
                raise MisregistryError(
                    f"verified registry {record.regid} does not match "
                    f"declared registry {regk}")

            return record

        # Missing KEL anchors can be resolved by later evidence retrieval.
        except MissingAnchorError as ex:
            raise MissingChainError(f"registry {regk} is missing anchored TEL evidence") from ex

        # An unresolved attached source may later prove the selected binding.
        except MisanchorError as ex:
            if requireSource and unresolved:
                raise MissingChainError(
                    f"missing presentation anchor source for registry {regk}") from ex
            return None

        # Structurally invalid or misbound TEL evidence fails permanently.
        except (MisdigestError, MissequenceError, MisregistryError,
                RootSealError, MisbindingError, DuplicitousRegistryError,
                UnverifiedBlindError):
            return None

    @staticmethod
    def _presentationRegistries(serder):
        """Extract disclosed issuee/presentation-registry declarations.

        Return ``None`` for an unsupported hidden issuer registry or when a
        registry-backed ACDC hides an attribute or aggregate element that could
        contain a presentation requirement. A verifier cannot distinguish an
        omitted requirement from an undisclosed one using only its digest.
        """
        if not serder.sad.get("rd"):
            # A disclosed inner rd without top-level rd is an unsupported
            # hidden issuer registry, not a presentation registry.
            attribute = serder.sad.get("a")
            if isinstance(attribute, Mapping) and attribute.get("rd"):
                return None

            # Apply the same rule to disclosed aggregate entries.
            aggregate = serder.sad.get("A")
            sections = aggregate[1:] if isinstance(aggregate, list) else [aggregate]
            if any(isinstance(section, Mapping) and section.get("rd")
                   for section in sections):
                return None

            # A genuinely registry-less ACDC has no presentation declaration.
            return []

        # Collect disclosed sections that may declare Issuee registry pairs.
        sections = []

        # Inspect the attribute section first.
        attribute = serder.sad.get("a")

        # A blinded attribute section may hide a required declaration.
        if isinstance(attribute, str):
            return None

        # Keep a disclosed attribute mapping for declaration scanning.
        if isinstance(attribute, Mapping):
            sections.append(attribute)

        # Inspect aggregate sections for additional Issuees.
        aggregate = serder.sad.get("A")

        # A blinded aggregate may hide a required declaration.
        if isinstance(aggregate, str):
            return None

        # Skip the aggregate root and inspect its disclosed entries.
        if isinstance(aggregate, list):

            # Every inspected aggregate entry must be a mapping.
            if any(not isinstance(section, Mapping) for section in aggregate[1:]):
                return None
            sections.extend(aggregate[1:])

        # Support the single disclosed aggregate mapping form.
        elif isinstance(aggregate, Mapping):
            sections.append(aggregate)

        # Preserve unique Issuee and registry declarations in wire order.
        declarations = []
        for section in sections:

            # Read the presentation registry and its controlling Issuee.
            regk = section.get("rd")
            issuee = section.get("i")

            # Ignore sections that do not declare the complete pair.
            if not regk or not issuee:
                continue

            # Validate both identifiers before trusting the declaration.
            try:
                Saider(qb64=regk)
                Prefixer(qb64=issuee)
            except Exception:
                return None

            # Deduplicate declarations repeated across disclosed sections.
            if (issuee, regk) not in declarations:
                declarations.append((issuee, regk))

        # Return every explicit presentation requirement.
        return declarations

    def _verifyPresentationAuthGraph(self, serder, nodes, order):
        """Verify every presentation registry in the DAG."""

        required = []

        # Walk the already validated DAG in deterministic order.
        for said in order:

            # Resolve this node and its attached proof stream.
            nest = nodes[said]

            # Read the ACDC body from either parsed representation.
            acdc = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Extract this node's Issuee registry declarations.
            declarations = self._presentationRegistries(acdc)

            # Reject hidden or malformed declarations.
            if declarations is None:
                return None

            # Bind each declaration to this node's local proofs.
            for issuee, regk in declarations:
                # The declaration is the issuer's signal that this Issuee must
                # authenticate the grant through this node-local registry.
                required.append((said, issuee, regk, nest))

        # Load the receiver timestamp that freezes registry history.
        cache = self.hby.db.kramTMSC.get(
            keys=(serder.pre, serder.ked.get("x", ""), serder.said))

        # A presentation requirement needs a completed KRAM acceptance.
        if required and (cache is None or not cache.rdt):
            return None

        # Collect Issuees authenticated through presentation registries.
        tethered = set()

        # Vet every declared registry independently.
        for said, issuee, regk, nest in required:
            # Resolve the latest disclosed binding as of KRAM acceptance.
            sourceSeals = nest.get("ssts", []) if isinstance(nest, dict) else nest.ssts
            record = self._vetRegistry(regk=regk,
                                       proofs=self._blindProofs(nest),
                                       target=serder.said,
                                       controller=issuee,
                                       cutoff=cache.rdt,
                                       sourceSeals=sourceSeals,
                                       requireSource=True)

            # Require a valid binding anchored before the KRAM-accepted send.
            if record is None:
                return None

            # Record the Issuee authenticated by this registry.
            tethered.add(issuee)

        # Return all presentation-authenticated Issuees.
        return tethered

    def verifyEvidence(self, serder, *, tsgs=None, cigars=None, sourceSeals=None,
                       invalid=False, missing=None):
        """Select verified non-sender evidence accepted by this IPEX route.

        Exchanger first removes cryptographically invalid attachments.  Grants
        then apply the stricter IPEX freshness rule against each endorser's
        current Kever and prefer a valid seal over signatures from the same AID.
        Grants drop unresolved optional evidence after Exchanger requests the
        missing KEL. Other verbs reject foreign, invalid, or unresolved evidence.
        """
        # Normalize optional evidence collections for filtering.
        tsgs = tsgs if tsgs is not None else []
        cigars = cigars if cigars is not None else []
        sourceSeals = sourceSeals if sourceSeals is not None else []

        # Keep unresolved coordinates distinct from invalid attachments.
        missing = missing if missing is not None else []

        # Derive the policy branch from the concrete IPEX route.
        verb = serder.ked["r"].rsplit("/", 1)[-1]

        # Only Grant accepts supplemental grantor evidence.
        if verb == Ipex.grant:
            # Collect endorsements tied to current endorser key states.
            freshTsgs = []
            for prefixer, number, diger, sigers in tsgs:
                # Resolve the endorser's current verified state.
                kever = self.hby.db.kevers.get(prefixer.qb64)
                # Require exact current establishment coordinates.
                if (kever is not None
                        and number.sn == kever.lastEst.s
                        and diger.qb64 == kever.lastEst.d):
                    # Preserve this current transferable endorsement.
                    freshTsgs.append((prefixer, number, diger, sigers))

            # Collect source seals valid against current anchorer state.
            freshSeals = []
            for prefixer, number, diger in sourceSeals:
                # Resolve the anchorer's current verified state.
                kever = self.hby.db.kevers.get(prefixer.qb64)
                # Drop unknown anchorers and stale references.
                if kever is None or number.sn < kever.lastEst.s:
                    continue
                # Current establishment references must match lastEst.
                if number.sn == kever.lastEst.s:
                    if diger.qb64 != kever.lastEst.d:
                        continue
                else:
                    # Later references may only name interaction events.
                    event = self.hby.db.evts.get(keys=(prefixer.qb64b, diger.qb64b))
                    if event is None or event.ilk != Ilks.ixn:
                        continue
                # Preserve this fresh source reference.
                freshSeals.append((prefixer, number, diger))

            # A valid current seal is the stronger factor for an AID, so do not
            # retain a redundant signature endorsement from that same AID.
            sealers = {prefixer.qb64 for prefixer, _, _ in freshSeals}
            freshTsgs = [tsg for tsg in freshTsgs if tsg[0].qb64 not in sealers]
            freshCigars = [cigar for cigar in cigars
                           if cigar.verfer.qb64 not in sealers]

            # Return only verified factors; unresolved extras are dropped.
            return freshTsgs, freshCigars, freshSeals

        # Reject supplemental evidence on every non-Grant IPEX verb.
        if tsgs or cigars or sourceSeals or invalid or missing:
            return None

        # Accept an evidence-free non-Grant message.
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

    def handle(self, serder, attachments=None, nests=None, sscs=None):
        """Emit a notifier record for an accepted IPEX message.

        Parameters:
            serder (Serder): Accepted IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused by the
                current notifier path.
            nests (list | None): Parsed V2 nested artifacts, unused by the
                notifier path.
            sscs (list | None): Sender source-seal couples, unused after verify.

        Returns:
            None
        """
        attrs = serder.ked["a"]
        self.notifier.add(attrs=dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"],
        ))

def apply(hab, recp, message, modifiers=None, attrs=None, dt=None, kind=None, gvrsn=None, *, ax=None):
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
            requires an explicit single-DAG disclosure plan at
            ``modifiers["dp"]``.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.

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

    # ax should be passed as a separate parameter, not in the attrs
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message
    mods = dict(modifiers) if modifiers else {}

    if ("dp" not in mods
            or not _validSingleDagList(mods["dp"], list)
            or not _validDisclosurePath(mods["dp"][0])):
        raise ValueError("modifiers['dp'] is required and must carry one disclose-path list per DAG")

    # Validate ax and add it to the body
    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

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
          kind=None, gvrsn=None, modifiers=None, attrs=None, *, ax=None):
    """Create a signed V2 IPEX ``offer`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable offer message.
        origin (Serder | bytes | bytearray | None): Optional origin ACDC node
            for the offer DAG. When provided, its SAID is copied into
            ``a.o[0]``. When omitted, the offer may negotiate only through its
            disclose-path plan.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            additional metadata-DAG nodes carried after ``origin``. Passing a
            list, including ``[]``, means the offer carries a nested DAG.
        apply (Serder | None): Optional prior ``apply`` exchange.
        recp (str | None): Recipient AID. Defaults to the prior ``apply``
            sender; must be supplied directly for an offer-first exchange
            opened with no prior.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        modifiers (dict | None): Optional query-section fields for ``q``.
        attrs (dict | None): Optional extra payload fields.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.

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
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message

    # Retrieve dp from modifiers if present. When the offer answers an apply,
    # inherit the requested disclose-path plan unless the caller overrides it.
    # Offer-first flows have no earlier disclosure request to inherit, so they
    # must provide their own explicit disclosure plan.
    mods = dict(modifiers) if modifiers else {}
    if "dp" not in mods:
        if apply is not None:
            aq = apply.ked.get("q")
            if isinstance(aq, dict) and "dp" in aq:
                mods["dp"] = aq["dp"]
        else:
            raise ValueError("modifiers['dp'] is required when no prior apply is provided")

    # Offer uses the same canonical q.dp builder contract as apply.
    if not _validSingleDagList(mods["dp"], list) or not _validDisclosurePath(mods["dp"][0]):
        raise ValueError("modifiers['dp'] must carry one disclose-path list per DAG")
    if apply is None and not mods["dp"][0]:
        raise ValueError("offer-first modifiers['dp'] must include at least one disclosure-path entry")

    # Validate ax if present
    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

    # If prior apply is present, validate ax consistency between the offer and the prior
    if apply is not None:

        # Retrieve the ax field of the prior
        applyAx = apply.ked.get("a", {}).get("ax", [False])
        offerAx = data.get("ax", [False])
        applyRequiresAnchor = applyAx[0] is True
        offerRequiresAnchor = offerAx[0] is True

        if applyRequiresAnchor and not offerRequiresAnchor:
            raise ValueError("offer must echo the prior apply's anchoring requirement")

    # Offer may either negotiate only via dp, name a metadata root SAID, or
    # carry a full metadata DAG whose shape mirrors the later grant DAG.
    nests = None
    if origin is not None:
        originSerder = _streamSerder(origin)
        if originSerder.proto != Protocols.acdc or originSerder.ilk not in DisclosedNodeIlks:
            raise ValueError("offer origin must identify a disclosed ACDC node")
        data["o"] = [originSerder.said]
    elif artifacts:
        raise ValueError("offer artifacts require an origin")

    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        if origin is None:
            if artifacts:
                raise ValueError("offer artifacts require an origin")
        else:
            nests = [_normalizeNodeStream(origin)]
            for artifact in artifacts:
                nests.append(_normalizeNodeStream(artifact))

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

    data = dict(m=message)
    
    offerAx = offer.ked.get("a", {}).get("ax", [False])
    offerRequiresAnchor = offerAx[0] is True
    if offerRequiresAnchor:
        data["ax"] = [True]

    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=offer.said,
        route="/ipex/agree",
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder,
                          anchor=offerRequiresAnchor, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def grant(hab, recp, message, origin, artifacts=None, agree=None,
          dt=None, kind=None, gvrsn=None, attrs=None, *, apply=None, ax=None,
          endorsers=None, anchorers=None):
    """Create a signed V2 IPEX ``grant`` exchange with nested disclosure artifacts.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the disclosure.
        message (str): Human-readable disclosure message.
        origin (Serder | bytes | bytearray): Origin ACDC node identified in
            ``a.o[0]`` and carried as the first nested artifact.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            additional disclosed ACDC nodes carried after ``origin``.
        agree (Serder | None): Optional prior ``agree`` exchange.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        attrs (dict | None): Optional extra payload fields.
        apply (Serder | None): Optional prior ``apply`` for a direct
            apply-to-grant flow. Mutually exclusive with ``agree``.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.
        endorsers (list[Hab] | None): Additional local grantors that sign the
            grant. The sender remains the KRAM-authenticated outer sender.
        anchorers (list[Hab] | None): Explicit local AIDs that KEL-anchor the
            grant. None preserves the truthy-``ax`` sender-anchor default; an
            empty list leaves anchoring to a presentation registry.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Make sure there is only one prior
    if agree is not None and apply is not None:
        raise ValueError("agree and apply are mutually exclusive grant priors")

    previous = agree if agree is not None else apply
    prior = previous.said if previous is not None else ""
    
    if previous is None:
        if not recp:
            raise ValueError("recp is required when no prior exchange is provided")
        xid = Diger(ser=Noncer().qb64b).qb64
    else:
        if not previous.ked.get("ri", ""):
            raise ValueError("prior exchange has no explicit receiver")
        if hab.pre != previous.ked["ri"]:
            raise ValueError("sender does not match prior exchange receiver")
        if recp != previous.ked["i"]:
            raise ValueError("recp does not match prior exchange sender")
        pxid = previous.ked.get("x", "")
        if pxid:
            xid = pxid
        else:
            xid = ""
    data = dict(attrs) if attrs is not None else {}
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message

    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

    grantAx = data.get("ax", [False])
    grantRequiresAnchor = grantAx[0] is True
    if previous is not None:
        previousAx = previous.ked.get("a", {}).get("ax", [False])
        previousRequiresAnchor = previousAx[0] is True
        if grantRequiresAnchor != previousRequiresAnchor:
            raise ValueError("grant must echo the prior exchange's anchoring requirement")

    # Grant mirrors offer framing: a.o[0] names the origin node, and any later
    # nests are more disclosed ACDC nodes from that same origin DAG.
    data["o"] = [_streamSerder(origin).said]
    nests = [_normalizeNodeStream(origin)]

    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        for artifact in artifacts:
            nests.append(_normalizeNodeStream(artifact))

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
    # Preserve None as the signal for default sender anchoring.
    explicitAnchorers = None if anchorers is None else list(anchorers)

    # Anchor with the sender only when ax is true and no list overrides it.
    senderAnchor = grantRequiresAnchor and explicitAnchorers is None

    # Allow callers to name the sender explicitly among anchorers.
    if explicitAnchorers is not None:
        # Iterate over a copy because the sender entry is removed in place.
        for anchorer in list(explicitAnchorers):
            # Convert an explicit sender entry into the implied source couple.
            if anchorer.pre == hab.pre:
                senderAnchor = True

                # Avoid emitting a redundant explicit source triple.
                explicitAnchorers.remove(anchorer)

    # Sign and attach all selected sender, endorser, and anchorer factors.
    atc = bytearray(_sign(hab=hab, serder=serder, nests=nests,
                          anchor=senderAnchor,
                          endorsers=endorsers,
                          anchorers=explicitAnchorers,
                          gvrsn=gvrsn))
    # Return attachments separately from the immutable EXN body.
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
    grantAx = grant.ked.get("a", {}).get("ax", [False])
    grantRequiresAnchor = grantAx[0] is True
    data = dict(m=message)
    if grantRequiresAnchor:
        data["ax"] = [True]

    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=grant.said,
        route="/ipex/admit",
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder,
                          anchor=grantRequiresAnchor, gvrsn=gvrsn))
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


def loadHandlers(hby, exc, notifier, rgy=None):
    """Register handlers for the six V2 IPEX verb routes.

    Parameters:
        hby (Habery): Habitat environment and backing database.
        exc (Exchanger): Exchange router to register handlers on.
        notifier: Notifier-like object passed through to each handler.
        rgy (Regery | None): Optional local registry manager reused by every
            IPEX handler for verifier-side registry proof checks.

    Returns:
        None
    """
    exc.addHandler(IpexHandler(resource="/ipex/apply", hby=hby, notifier=notifier, rgy=rgy))
    exc.addHandler(IpexHandler(resource="/ipex/offer", hby=hby, notifier=notifier, rgy=rgy))
    exc.addHandler(IpexHandler(resource="/ipex/agree", hby=hby, notifier=notifier, rgy=rgy))
    exc.addHandler(IpexHandler(resource="/ipex/grant", hby=hby, notifier=notifier, rgy=rgy))
    exc.addHandler(IpexHandler(resource="/ipex/admit", hby=hby, notifier=notifier, rgy=rgy))
    exc.addHandler(IpexHandler(resource="/ipex/spurn", hby=hby, notifier=notifier, rgy=rgy))
