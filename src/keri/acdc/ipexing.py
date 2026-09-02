# -*- encoding: utf-8 -*-
"""
keri.acdc.ipexing module

IPEx protocol service support (Issuance and Presentation Exchange)

"""

from collections import deque, namedtuple
from collections.abc import Mapping

from hio.help import ogler

from .. import Kinds, Protocols
from ..kering import Colds, Ilks, Vrsn_2_0, sniff
from ..core import (BlindState, Blinder, BoundState, Counter, Codens, Diger, GenDex, Noncer,
                    Number, Saider, Serdery, Texter, exchange, messagize)
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

DisclosedNodeIlks = (None, Ilks.acm, Ilks.ace, Ilks.act, Ilks.acg)

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


def _validSingleDagList(value, itemtype, *, allow_empty=False):
    """Validate one of the single-item list fields used by single-DAG IPEX.

    Parameters:
        value: Candidate wire value for a single-DAG field such as ``o`` or
            ``ax``.
        itemtype (type): Required Python type for each outer-list entry.
        allow_empty (bool): When True, ``[]`` is accepted in addition to a
            one-item list. This is used only for today's unanchored ``ax``
            behavior.

    Returns:
        bool: True when ``value`` matches the current single-DAG wire shape,
            False otherwise.
    """

    # The single-DAG outer-wire contract for `o` and `ax` is a list that can
    # later grow for multi-DAG without changing field type.
    if not isinstance(value, list):
        return False

    # We currently only support one DAG (until Multi DAG), so at most one entry is allowed.
    # `allow_empty=True` is used only for today's unanchored `ax=[]` behavior;
    # every other caller requires exactly one entry in the outer list.
    if len(value) > 1 or (not allow_empty and len(value) != 1):
        return False

    # The inner item type differs by field:
    # - `o` carries one origin SAID string
    # - `ax` carries zero or one booleans
    return all(isinstance(item, itemtype) for item in value)


def _validDisclosurePath(value):
    """Validate ``q.dp`` as one disclose-path list for the current DAG.

    Parameters:
        value: Candidate ``q.dp`` wire value.

    Returns:
        bool: True when ``value`` is a list whose entries are disclosure-path
            triples of ``[schema SAID, DAG path, ACDC paths]``, False
            otherwise.
    """
    return (isinstance(value, list)
            and all(isinstance(item, list)
                    and len(item) == 3
                    and isinstance(item[0], str)
                    and isinstance(item[1], str)
                    and isinstance(item[2], list)
                    for item in value))


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

    def verify(self, serder, attachments=None, nests=None):
        """Validate the verb, prior link, and single-response rule.

        Parameters:
            serder (Serder): Incoming IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused in the
                current linear workflow validation.
            nests (list | None): Parsed V2 nested artifacts. In the current
                single-DAG workflow only ``grant`` may disclose nested ACDC
                nodes; ``offer`` stays metadata-only.

        Returns:
            bool: True when the message is valid for the linear IPEX workflow,
                False otherwise.
        """
        nests = nests if nests is not None else []
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
        # optional list field and remains syntax-only for this ticket.
        if not isinstance(attrs, dict) or "m" not in attrs or not isinstance(q, dict):
            return False
        if "ax" in attrs and not _validSingleDagList(attrs["ax"], bool, allow_empty=True):
            return False

        # Stage 2: apply/offer carry disclose-paths. Offer may optionally name
        # or carry a metadata DAG in `a.o[0]`, while grant must name and carry
        # the final disclosed DAG root.
        if verb in (Ipex.apply, Ipex.offer):
            if "dp" not in q or not _validDisclosurePath(q["dp"]):
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
        elif not self._verifyReplyChain(verb=verb, serder=serder, dig=dig):
            return False

        # Stage 4: when an offer carries a metadata DAG, or when a grant
        # carries the final disclosure DAG, the nests must describe one exact
        # reachable graph rooted at the message's `a.o[0]`.
        if verb == Ipex.offer and nests:
            if self._walkGraph(origin=attrs["o"][0], nests=nests) is None:
                return False
        elif verb == Ipex.grant:
            walked = self._walkGraph(origin=attrs["o"][0], nests=nests)
            if walked is None:
                return False

            # Stage 5: after the disclosed graph shape is accepted, each walked
            # registry-backed node must vet its own node-local proof group.
            if not self._verifyIssuerAuthGraph(nodes=walked[0], order=walked[1]):
                return False

        return True

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
            bool: True when the reply points to an allowed prior message, keeps
                sender/receiver roles consistent, and does not duplicate an
                existing response; False otherwise.
        """
        pserder, _ = cloneMessage(self.hby, said=dig)
        if pserder is None:
            return False

        # Replies must point at the allowed prior verb in the linear IPEX chain.
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

        if self.response(pserder) is not None:
            return False

        return True

    def _walkGraph(self, origin, nests):
        """Walk the disclosed origin DAG and return the visited node order.

        Parameters:
            origin (str): SAID of the origin node named by ``a.o[0]``.
            nests (list): Parsed nested ACDC node substreams carried by the
                grant message.

        Returns:
            tuple | None: ``(nodes, order)`` when the disclosed nests form one
                exact DAG rooted at ``origin``; otherwise ``None``.
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

        # Walk the graph BFS, reject if any edge fails to resolve to a carried nest
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
                # `e` must stay directly walkable as a mapping or list of mappings.
                #  A compacted edge SAID/string fails closed.
                if isinstance(edges, Mapping):
                    blocks = [edges]
                elif isinstance(edges, list) and all(isinstance(edge, Mapping) for edge in edges):
                    blocks = edges
                else:
                    return None

                # Walk each edge block, reject if any edge fails to resolve to a nest
                for edge in blocks:
                    for label, node in edge.items():
                        if label in ("d", "o"):
                            continue
                        if not isinstance(node, Mapping):
                            return None
                        edgeSaid = node.get("n")
                        if not isinstance(edgeSaid, str):
                            return None
                        try:
                            Saider(qb64=edgeSaid)
                        except Exception:
                            return None
                        if edgeSaid not in nodes:
                            return None
                        if edgeSaid not in seen:
                            queue.append(edgeSaid)

        # If any carried nest was never reached, the payload is not one exact DAG.
        if len(seen) != len(nodes):
            return None

        return nodes, order

    def _verifyIssuerAuthGraph(self, nodes, order):
        """Verify issuer-auth proof groups for each walked disclosed DAG node.

        Parameters:
            nodes (dict): Mapping of disclosed node SAID to parsed nest.
            order (list): Breadth-first walk order returned by ``_walkGraph``.

        Returns:
            bool: True when every walked node either has no registry binding or
                vets successfully against its node-local proof group.
        """
        # Run proof verification in graph order so each registry-backed node is
        # checked against the exact nested substream that carried its body.
        for said in order:
            nest = nodes[said]
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
            if not self._verifyIssuerAuthNode(serder=nserder, nest=nest):
                return False

        return True

    def _verifyIssuerAuthNode(self, serder, nest):
        """Verify the issuer-auth proof carried on one disclosed ACDC node.

        This hook only applies to registry-backed credentials. When the ACDC
        body has a top-level ``rd`` field, that field names the registry whose
        TEL history must authenticate the node. The proof material is expected
        to live on the same nested substream as the ACDC body. 
        In other words, one disclosed DAG node is:

        ``ACDC body + that node's issuer-auth attachment group``

        Workflow:
            1. Read ``rd`` from the ACDC body. If there is no ``rd``, this node
               is not registry-backed and there is nothing to vet here.
            2. Read the node-local blind proof group (`bsqs` or `bsss`) from the
               parsed nest and normalize the parsed tuples back into the crew
               shape expected by ``Blinder``.
            3. Require exactly one blinded state proof for this node's registry
               root event. Missing or multiple proofs fail closed.
            4. Load the registry inception event and subsequent TEL updates from
               the local ``Regery`` store.
            5. Call ``regeventing.vet(...)`` with the ACDC, the disclosed blind
               proof, and the persisted TEL evidence so registry anchoring and
               ACDC binding are checked in one place.

        Parameters:
            serder (Serder): The disclosed ACDC node being verified.
            nest (dict | object): The parsed nested substream that carried the
                node. It must expose any attached blind proof groups as ``bsqs``
                or ``bsss``.

        Returns:
            bool: ``True`` when the node is either not registry-backed or its
            node-local proof vets successfully against local TEL evidence;
            otherwise ``False``.
        """
        regk = serder.sad.get("rd")
        if regk:
            # Registry-backed ACDCs must carry their proof group on the node's own
            # nest so issuer-auth evidence travels with the ACDC it authenticates.
            bsqs = nest.get("bsqs", []) if isinstance(nest, dict) else nest.bsqs
            bsss = nest.get("bsss", []) if isinstance(nest, dict) else nest.bsss

            # The parser gives us primitive instances. Rebuild those into the
            # canonical crew form so regeventing.vetBlind() sees the expected
            # cast (d as qb64 digest, u/td/bd as nonce strings, ts as text).
            proofs = []
            for proof in bsqs:
                crew = BlindState(d=proof[0].qb64,
                                  u=proof[1].nonce,
                                  td=proof[2].nonce,
                                  ts=proof[3].text)
                proofs.append(Blinder(crew=crew))

            for proof in bsss:
                crew = BoundState(d=proof[0].qb64,
                                  u=proof[1].nonce,
                                  td=proof[2].nonce,
                                  ts=proof[3].text,
                                  bn=proof[4].sn,
                                  bd=proof[5].nonce)
                proofs.append(Blinder(crew=crew))

            # The proof group must disclose exactly one blinded state for the registry's root event.
            if len(proofs) != 1:
                return False

            # Reuse an injected Regery when available. Otherwise reopen the local
            # registry store for this Habery so IPEX can vet against persisted TEL
            # evidence without changing the public handler API.
            if self.rgy is None:
                from .registraring import Regery
                self.rgy = Regery(hby=self.hby,
                                  name=self.hby.name,
                                  base=self.hby.base,
                                  temp=self.hby.temp)

            # The proof group only discloses one event's blinded state. The TEL
            # chain itself is loaded from the local registry store and passed into
            # regeventing.vet(), which checks anchoring and ACDC binding.
            rip = self.rgy.store.seqEvent(regk, 0)
            head = self.rgy.store.headEvent(regk)
            if rip is None or head is None:
                return False

            updates = []
            for sn in range(1, int(head.sad["n"], 16) + 1):
                if not (update := self.rgy.store.seqEvent(regk, sn)):
                    return False
                updates.append(update)

            from . import regeventing
            try:
                regeventing.vet(rip=rip,
                                updates=updates,
                                db=self.hby.db,
                                acdc=serder,
                                blinder=proofs[0])
            except Exception:
                return False

        return True

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
            requires an explicit single-DAG disclosure plan at
            ``modifiers["dp"]``.

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

    # Validate dp field, it must be the DAG's disclose-path list.
    if "dp" not in mods or not _validDisclosurePath(mods["dp"]):
        raise ValueError("modifiers['dp'] is required and must be a list of disclosure-path triples")

    # Validate ax field, must be a list of booleans, is allowed to be empty
    if "ax" in data and not _validSingleDagList(data["ax"], bool, allow_empty=True):
        raise ValueError("attrs['ax'] must be [] or a one-item list of booleans")

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

    # Retrieve dp from modifiers if present. When the offer answers an apply,
    # inherit the requested disclose-path plan unless the caller overrides it.
    mods = dict(modifiers) if modifiers else {}
    if "dp" not in mods and apply is not None:
        aq = apply.ked.get("q")
        if isinstance(aq, dict) and "dp" in aq:
            mods["dp"] = aq["dp"]
    mods.setdefault("dp", [])     # defaults to an empty list if none is provided

    # Validate dp field, it must be a list of lists.
    if not _validDisclosurePath(mods["dp"]):
        raise ValueError("modifiers['dp'] must be a list of disclosure-path triples")

    # Validate the ax field if present. It must be a list of booleans
    if "ax" in data and not _validSingleDagList(data["ax"], bool, allow_empty=True):
        raise ValueError("attrs['ax'] must be [] or a one-item list of booleans")

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
        origin (Serder | bytes | bytearray): Origin ACDC node identified in
            ``a.o[0]`` and carried as the first nested artifact.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            additional disclosed ACDC nodes carried after ``origin``.
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

    # Validate ax field, it must be a list of bool, it's allowed to be empty
    if "ax" in data and not _validSingleDagList(data["ax"], bool, allow_empty=True):
        raise ValueError("attrs['ax'] must be [] or a one-item list of booleans")

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
