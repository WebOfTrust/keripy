# -*- encoding: utf-8 -*-
"""
tests.acdc.test_ipexing module

"""
from datetime import timedelta

import pytest
from keri import Kinds, Vrsn_2_0
from keri.acdc import (Regery, Registrar, acdcmap, blindate, apply as ipexApply, admit as ipexAdmit,
                       agree as ipexAgree, grant as ipexGrant,
                       loadHandlers, offer as ipexOffer, regcept,
                       spurn as ipexSpurn)
from keri.app import openCF, openHby
from keri.core import (Blinder, Codens, Counter, GenDex, Kevery, Kramer, Noncer, Parser,
                       messagize,
                       SerderKERI, Serdery, Texter, exchange)
from keri.kering import Colds, sniff
from keri.help import helping
from keri.peer import Exchanger, cloneMessage, serializeMessage

# Patch it to a function to assert correct behavior
class Recorder:
    """Collect notifier payloads emitted during dispatch tests."""

    def __init__(self):
        """Initialize an empty recorder."""
        self.items = []

    def add(self, attrs):
        """Append one notifier payload."""
        self.items.append(attrs)

# Helper functions
def _serder(stream):
    """Extract the message serder from a bare or nested artifact stream."""
    ims = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)
    if ims and sniff(ims) != Colds.msg:
        ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
        if ctr.name in (
            Codens.NonNativeBodyGroup,
            Codens.BigNonNativeBodyGroup
        ):
            return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                  genus=GenDex.KERI,
                                                  svrsn=Vrsn_2_0)
        if ims and sniff(ims) != Colds.msg:
            ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
            if ctr.name in (
                Codens.NonNativeBodyGroup,
                Codens.BigNonNativeBodyGroup
            ):
                return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                      genus=GenDex.KERI,
                                                      svrsn=Vrsn_2_0)

    return Serdery(version=Vrsn_2_0).reap(ims=ims,
                                          genus=GenDex.KERI,
                                          svrsn=Vrsn_2_0)


def _nest(stream):
    """Wrap an artifact as a parser-friendly V2 nested substream."""
    raw = bytes(stream.raw) if hasattr(stream, "raw") else bytes(stream)
    serder = _serder(raw)
    body = raw[:serder.size]
    atc = raw[serder.size:]
    if serder.kind != Kinds.cesr:
        body = Counter.enclose(qb64=Texter(raw=body).qb64b,
                               code=Codens.NonNativeBodyGroup,
                               version=Vrsn_2_0)

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
    return Counter.enclose(qb64=nested,
                           code=Codens.BodyWithAttachmentGroup,
                           version=Vrsn_2_0)


def _proofed(acdc, *proofs):
    """Attach one node-local registry proof group to a disclosed ACDC stream."""
    # Step 4 keeps only the issuer-auth proof group on the disclosed node.
    return messagize(serder=acdc,
                     bonds=[proof.data for proof in proofs],
                     framed=False,
                     gvrsn=Vrsn_2_0)


def _anchor(hab, registry, serder, *, framed=False):
    """Create a KEL interaction event that seals one registry event."""
    seal = dict(i=registry.regk, s=serder.sad["n"], d=serder.said)
    anc = hab.interact(data=[seal], framed=framed, gvrsn=Vrsn_2_0)
    assert registry.anchorMsg(serder.said) is True
    return anc


def _edge(label, node, *, op="I2I", schema=None):
    """Create a simple edge block that points at another disclosed ACDC node."""
    target = dict(d="", n=node.said, o=op)
    if schema is not None:
        target["s"] = schema
    return dict(d="", **{label: target})

# Tests
def test_ipex_v2_builders_parse_happypath():
    """Build each V2 IPEX verb and prove the resulting streams parse cleanly."""
    with openHby(name="ipex-v2-builders",
                 base="test") as hby:

        # Create hab
        hab = hby.makeHab(name="test")

        # Build artifacts
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        # Extract schema from acdc
        schema = acdc.sad["s"]["$id"]

        # Build apply message
        applyExn, applyAtc = ipexApply(hab=hab,
                                          recp=hab.pre,
                                          message="Please issue a credential",
                                          attrs=dict(role="member", ax=[False]),
                                          modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))

        # Build Offer message chained to apply 
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       origin=acdc,
                                       attrs=dict(ax=[False]),
                                       apply=applyExn)

        # Build an agree chained to the offer
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                          message="I agree to the offer",
                                          offer=offerExn)

        # Build the grant chained to the agree
        grantExn, grantAtc = ipexGrant(hab=hab,
                                          recp=hab.pre,
                                          message="Here is the granted credential",
                                          origin=acdc,
                                          attrs=dict(ax=[False]),
                                          agree=agreeExn)

        # Build the admit chained to the grant
        admitExn, admitAtc = ipexAdmit(hab=hab,
                                          message="Thanks for the credential",
                                          grant=grantExn)

        # Build the spurn chained to the apply
        spurnExn, spurnAtc = ipexSpurn(hab=hab,
                                          message="No thanks",
                                          spurned=applyExn)

        # Iterate through each message, assert version and receiver field
        for serder in (applyExn, offerExn, agreeExn,
                       grantExn, admitExn, spurnExn):
            assert serder.pvrsn == Vrsn_2_0
            assert "ri" in serder.ked
            assert "rp" not in serder.ked

        # Assert fields
        assert applyExn.ked["a"]["m"] == "Please issue a credential"    # message
        assert applyExn.ked["a"]["ax"] == [False]
        assert applyExn.ked["q"]["dp"] == [[[schema, "/", ["a/role"]]]]

        assert offerExn.ked["a"]["m"] == "Here is the offered credential"
        assert offerExn.ked["a"]["ax"] == [False]
        assert offerExn.ked["a"]["o"] == [acdc.said]
        assert offerExn.ked["p"] == applyExn.said       # prior
        assert offerExn.ked["q"]["dp"] == applyExn.ked["q"]["dp"]

        assert agreeExn.ked["a"]["m"] == "I agree to the offer"
        assert agreeExn.ked["p"] == offerExn.said

        assert grantExn.ked["a"]["m"] == "Here is the granted credential"
        assert grantExn.ked["a"]["o"] == [acdc.said]
        assert grantExn.ked["a"]["ax"] == [False]
        assert "iss" not in grantExn.ked["a"]
        assert "anc" not in grantExn.ked["a"]
        assert grantExn.ked["p"] == agreeExn.said

        assert admitExn.ked["a"]["m"] == "Thanks for the credential"
        assert admitExn.ked["p"] == grantExn.said

        assert spurnExn.ked["a"]["m"] == "No thanks"
        assert spurnExn.ked["p"] == applyExn.said

        # Parse the full stream for each exchange
        # Apply
        applyIms = bytearray(applyExn.raw)
        applyIms.extend(applyAtc)
        applyResults = Parser().parse(ims=applyIms,
                                                      framed=False,
                                                      processive=False)
        assert applyIms == bytearray()
        assert len(applyResults) == 1
        applyResult = applyResults[0]

        assert applyResult.serder.said == applyExn.said
        assert applyResult.serder.ked["r"] == "/ipex/apply"
        assert applyResult.serder.ked["a"] == applyExn.ked["a"]
        assert applyResult.nests == []     # No nested substream

        # Offer
        offerIms = bytearray(offerExn.raw)
        offerIms.extend(offerAtc)
        offerResults = Parser().parse(ims=offerIms,
                                                      framed=False,
                                                      processive=False)
        assert offerIms == bytearray()
        assert len(offerResults) == 1
        offerResult = offerResults[0]

        assert offerResult.serder.said == offerExn.said
        assert offerResult.serder.ked["r"] == "/ipex/offer"
        assert offerResult.serder.ked["a"] == offerExn.ked["a"]
        assert offerResult.serder.ked["p"] == applyExn.said
        assert offerResult.nests == []

        # Agree
        agreeIms = bytearray(agreeExn.raw)
        agreeIms.extend(agreeAtc)
        agreeResults = Parser().parse(ims=agreeIms,
                                                      framed=False,
                                                      processive=False)
        assert agreeIms == bytearray()
        assert len(agreeResults) == 1
        agreeResult = agreeResults[0]

        assert agreeResult.serder.said == agreeExn.said
        assert agreeResult.serder.ked["r"] == "/ipex/agree"
        assert agreeResult.serder.ked["a"] == agreeExn.ked["a"]
        assert agreeResult.serder.ked["p"] == offerExn.said
        assert agreeResult.nests == []
        
        # Grant
        grantIms = bytearray(grantExn.raw)
        grantIms.extend(grantAtc)
        grantResults = Parser().parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        grantResult = grantResults[0]

        assert grantResult.serder.said == grantExn.said
        assert grantResult.serder.ked["r"] == "/ipex/grant"
        assert grantResult.serder.ked["a"] == grantExn.ked["a"]
        assert grantResult.serder.ked["p"] == agreeExn.said
        assert [nest.serder.said for nest in grantResult.nests] == [acdc.said]

        # Admit
        admitIms = bytearray(admitExn.raw)
        admitIms.extend(admitAtc)
        admitResults = Parser().parse(ims=admitIms,
                                                      framed=False,
                                                      processive=False)
        assert admitIms == bytearray()
        assert len(admitResults) == 1
        admitResult = admitResults[0]

        assert admitResult.serder.said == admitExn.said
        assert admitResult.serder.ked["r"] == "/ipex/admit"
        assert admitResult.serder.ked["a"] == admitExn.ked["a"]
        assert admitResult.serder.ked["p"] == grantExn.said
        assert admitResult.nests == []

        # Spurn
        spurnIms = bytearray(spurnExn.raw)
        spurnIms.extend(spurnAtc)
        spurnResults = Parser().parse(ims=spurnIms,
                                                      framed=False,
                                                      processive=False)
        assert spurnIms == bytearray()
        assert len(spurnResults) == 1
        spurnResult = spurnResults[0]

        assert spurnResult.serder.said == spurnExn.said
        assert spurnResult.serder.ked["r"] == "/ipex/spurn"
        assert spurnResult.serder.ked["a"] == spurnExn.ked["a"]
        assert spurnResult.serder.ked["p"] == applyExn.said
        assert spurnResult.nests == []


def test_ipex_v2_accepts_empty_ax_list_as_unanchored():
    """Single-DAG IPEX accepts [] for ax as explicit unanchored intent."""
    with openHby(name="ipex-v2-empty-ax",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        schema = acdc.sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        applyExn, applyAtc = ipexApply(hab=hab,
                                       recp=hab.pre,
                                       message="Please issue a credential",
                                       attrs=dict(role="member", ax=[]),
                                       modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       origin=acdc,
                                       attrs=dict(ax=[]),
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                       message="I agree to the offer",
                                       offer=offerExn)
        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the granted credential",
                                       origin=acdc,
                                       attrs=dict(ax=[]),
                                       agree=agreeExn)

        for exn, atc in (
            (applyExn, applyAtc),
            (offerExn, offerAtc),
            (agreeExn, agreeAtc),
            (grantExn, grantAtc),
        ):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        assert applyExn.ked["a"]["ax"] == []
        assert offerExn.ked["a"]["ax"] == []
        assert grantExn.ked["a"]["ax"] == []

        assert hby.db.exns.get(keys=(applyExn.said,)).ked["a"]["ax"] == []
        assert hby.db.exns.get(keys=(offerExn.said,)).ked["a"]["ax"] == []
        assert hby.db.exns.get(keys=(grantExn.said,)).ked["a"]["ax"] == []


def test_ipex_v2_grant_carries_multiple_dag_nodes():
    """Grant can carry multiple disclosed ACDC nodes in one origin DAG."""
    with openHby(name="ipex-v2-grant-updates",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        child = acdcmap(israid=hab.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       edge=_edge("holder", child),
                       iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the disclosed DAG",
                                       origin=acdc,
                                       artifacts=[child])

        assert grantExn.ked["a"]["o"] == [acdc.said]
        assert "iss" not in grantExn.ked["a"]
        assert "anc" not in grantExn.ked["a"]

        grantIms = bytearray(grantExn.raw)
        grantIms.extend(grantAtc)
        grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        assert [nest.serder.said for nest in grantResults[0].nests] == [
            acdc.said,
            child.said,
        ]

        dispatch = bytearray(grantExn.raw)
        dispatch.extend(grantAtc)
        Parser(version=Vrsn_2_0).parse(ims=dispatch, framed=False, exc=exc)
        assert dispatch == bytearray()

        storedGrant = hby.db.exns.get(keys=(grantExn.said,))
        assert storedGrant is not None
        assert storedGrant.ked["a"]["o"] == [acdc.said]
        assert "iss" not in storedGrant.ked["a"]


def test_ipex_v2_builders_reject_registry_events_as_disclosed_nodes():
    """Offer/grant builders must reject TEL events in disclosed DAG node slots."""
    with openHby(name="ipex-v2-bad-node-builder",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        acdc = acdcmap(israid=holder.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        rip = regcept(israid=holder.pre)

        with pytest.raises(ValueError, match="disclosed ACDC node"):
            ipexOffer(hab=holder,
                      recp=verifier.pre,
                      message="Here is the bad offer",
                      origin=rip)

        with pytest.raises(ValueError, match="disclosed ACDC nodes"):
            ipexGrant(hab=holder,
                      recp=verifier.pre,
                      message="Here is the bad grant",
                      origin=rip)

        with pytest.raises(ValueError, match="disclosed ACDC nodes"):
            ipexGrant(hab=holder,
                      recp=verifier.pre,
                      message="Here is the bad grant artifact",
                      origin=acdc,
                      artifacts=[rip])


def test_ipex_v2_offer_builder_accepts_metadata_dag_nodes():
    """Offer may carry a metadata DAG and later grant the full disclosed DAG."""
    with openHby(name="ipex-v2-bad-offer-duplicate-node",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")

        # Build the final disclosed DAG first: the grant will later carry these
        # full ACDC bodies, including the private attribute values.
        child = acdcmap(israid=holder.pre,
                        uuid=Noncer().qb64,
                        attribute=dict(d="", u=Noncer().qb64, role="member"),
                        iseaid=verifier.pre)
        origin = acdcmap(israid=holder.pre,
                         uuid=Noncer().qb64,
                         attribute=dict(d="", u=Noncer().qb64, LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         rule=dict(d="", l="Use only for onboarding."),
                         iseaid=verifier.pre)
        schema = origin.sad["s"]["$id"]

        # The offer carries metadata variants of those same nodes instead:
        # top-level `u` is emptied, private sections stay compacted to SAIDs,
        # and only the root's rule text is disclosed up front.
        offerChild = acdcmap(israid=holder.pre,
                             uuid="",
                             schema=child.sad["s"]["$id"],
                             attribute=child.sad["a"]["d"])
        offerOrigin = acdcmap(israid=holder.pre,
                              uuid="",
                              schema=origin.sad["s"]["$id"],
                              attribute=origin.sad["a"]["d"],
                              edge=_edge("holder", offerChild),
                              rule=origin.sad["r"])

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Please disclose the credential DAG",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", []],
                                                           [schema, "/e/holder", []]]]))
        offerExn, offerAtc = ipexOffer(hab=holder,
                                       recp=verifier.pre,
                                       message="Here are the terms",
                                       origin=offerOrigin,
                                       artifacts=[offerChild],
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=verifier,
                                       message="I agree to the terms",
                                       offer=offerExn)
        grantExn, grantAtc = ipexGrant(hab=holder,
                                       recp=verifier.pre,
                                       message="Here is the granted credential",
                                       origin=origin,
                                       artifacts=[child],
                                       agree=agreeExn)

        for exn, atc in ((applyExn, applyAtc),
                         (offerExn, offerAtc),
                         (agreeExn, agreeAtc),
                         (grantExn, grantAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        storedOffer = hby.db.exns.get(keys=(offerExn.said,))
        storedGrant = hby.db.exns.get(keys=(grantExn.said,))
        assert storedOffer is not None
        assert storedGrant is not None
        assert storedOffer.ked["a"]["o"] == [offerOrigin.said]
        assert storedGrant.ked["a"]["o"] == [origin.said]
        assert storedOffer.ked["a"]["o"] != storedGrant.ked["a"]["o"]
        assert storedOffer.ked["q"]["dp"] == [[[schema, "/", []],
                                              [schema, "/e/holder", []]]]

        offerWire = bytearray(serializeMessage(hby, offerExn.said, framed=True))
        offerResults = Parser(version=Vrsn_2_0).parse(ims=offerWire,
                                                      framed=False,
                                                      processive=False)
        assert offerWire == bytearray()
        assert len(offerResults) == 1
        assert [nest.serder.said for nest in offerResults[0].nests] == [offerOrigin.said, offerChild.said]
        assert offerResults[0].nests[0].serder.sad["u"] == ""
        assert isinstance(offerResults[0].nests[0].serder.sad["a"], str)
        assert isinstance(offerResults[0].nests[0].serder.sad["r"], dict)
        assert offerResults[0].nests[0].serder.sad["r"]["l"] == "Use only for onboarding."
        assert offerResults[0].nests[1].serder.sad["u"] == ""
        assert isinstance(offerResults[0].nests[1].serder.sad["a"], str)

        grantWire = bytearray(serializeMessage(hby, grantExn.said, framed=True))
        grantResults = Parser(version=Vrsn_2_0).parse(ims=grantWire,
                                                      framed=False,
                                                      processive=False)
        assert grantWire == bytearray()
        assert len(grantResults) == 1
        assert [nest.serder.said for nest in grantResults[0].nests] == [origin.said, child.said]
        assert grantResults[0].nests[0].serder.sad["u"] != ""
        assert isinstance(grantResults[0].nests[0].serder.sad["a"], dict)
        assert grantResults[0].nests[0].serder.sad["a"]["LEI"] == "254900OPPU84GM83MG36"
        assert grantResults[0].nests[1].serder.sad["u"] != ""
        assert isinstance(grantResults[0].nests[1].serder.sad["a"], dict)
        assert grantResults[0].nests[1].serder.sad["a"]["role"] == "member"

        assert [item["r"] for item in recorder.items] == [
            "/exn/ipex/apply",
            "/exn/ipex/offer",
            "/exn/ipex/agree",
            "/exn/ipex/grant",
        ]


def test_ipex_v2_rejects_offer_with_unexpected_nested_artifacts():
    """Inbound offer verification rejects invalid nested payloads."""
    with openHby(name="ipex-v2-bad-offer-tel-node",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        rip = regcept(israid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", rip),
                         iseaid=hab.pre)

        # Build a syntactically valid offer body, then re-endorse it with an
        # invalid nested DAG that points at a TEL event instead of an ACDC node.
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=origin,
                           message="Here is the forged credential DAG")

        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(origin), _nest(rip)]))
        del atc[:exn.size]

        ims = bytearray(exn.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_offer_can_name_origin_without_disclosing_the_dag():
    """Offer may name a DAG origin SAID without carrying any disclosed node nests."""
    with openHby(name="ipex-v2-bad-offer-dangling-edge",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        child = acdcmap(israid=holder.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=holder.pre)
        origin = acdcmap(israid=holder.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         iseaid=holder.pre)
        schema = origin.sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Prove over-21",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offerExn, offerAtc = ipexOffer(hab=holder,
                                       message="Here are the terms",
                                       origin=origin,
                                       apply=applyExn)

        for exn, atc in ((applyExn, applyAtc), (offerExn, offerAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        assert hby.db.exns.get(keys=(applyExn.said,)) is not None
        storedOffer = hby.db.exns.get(keys=(offerExn.said,))
        assert storedOffer is not None
        assert storedOffer.ked["a"]["o"] == [origin.said]
        assert storedOffer.ked["q"]["dp"] == applyExn.ked["q"]["dp"]

        storedOfferMsg = serializeMessage(hby, offerExn.said, framed=True)
        storedOfferIms = bytearray(storedOfferMsg)
        storedOfferResults = Parser(version=Vrsn_2_0).parse(ims=storedOfferIms,
                                                            framed=False,
                                                            processive=False)
        assert storedOfferIms == bytearray()
        assert len(storedOfferResults) == 1
        assert storedOfferResults[0].nests == []
        assert recorder.items == [
            {"r": "/exn/ipex/apply", "d": applyExn.said, "m": "Prove over-21"},
            {"r": "/exn/ipex/offer", "d": offerExn.said, "m": "Here are the terms"},
        ]


def test_ipex_v2_offer_accepts_reachable_partial_metadata_subgraph():
    """Offer may disclose a reachable metadata subgraph without full closure."""
    with openHby(name="ipex-v2-offer-partial-subgraph",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")

        grandchild = acdcmap(israid=holder.pre,
                             uuid="",
                             attribute=dict(d="", role="member"))
        child = acdcmap(israid=holder.pre,
                        uuid="",
                        attribute=dict(d="", department="kitchen"),
                        edge=_edge("member", grandchild))
        origin = acdcmap(israid=holder.pre,
                         uuid="",
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("department", child),
                         iseaid=verifier.pre)
        schema = origin.sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Show me the metadata path",
                                       attrs={},
                                       modifiers=dict(dp=[[[schema, "/", []],
                                                           [schema, "/e/department", []]]]))
        # Carry only the disclosed root plus one reachable metadata child.
        # The child's farther edge to `grandchild` is intentionally omitted.
        offerExn, offerAtc = ipexOffer(hab=holder,
                                       recp=verifier.pre,
                                       message="Here is the partial metadata DAG",
                                       origin=origin,
                                       artifacts=[child],
                                       apply=applyExn)

        for exn, atc in ((applyExn, applyAtc), (offerExn, offerAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        storedOffer = hby.db.exns.get(keys=(offerExn.said,))
        assert storedOffer is not None
        assert storedOffer.ked["a"]["o"] == [origin.said]

        offerWire = bytearray(serializeMessage(hby, offerExn.said, framed=True))
        offerResults = Parser(version=Vrsn_2_0).parse(ims=offerWire,
                                                      framed=False,
                                                      processive=False)
        assert offerWire == bytearray()
        assert len(offerResults) == 1
        assert [nest.serder.said for nest in offerResults[0].nests] == [origin.said, child.said]
        assert recorder.items == [
            {"r": "/exn/ipex/apply", "d": applyExn.said, "m": "Show me the metadata path"},
            {"r": "/exn/ipex/offer", "d": offerExn.said, "m": "Here is the partial metadata DAG"},
        ]


def test_ipex_v2_rejects_offer_with_unreachable_nested_node():
    """Offer DAG nests must describe exactly one reachable metadata graph."""
    with openHby(name="ipex-v2-bad-offer-extra-node",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        child = acdcmap(israid=holder.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=holder.pre)
        extra = acdcmap(israid=holder.pre,
                        attribute=dict(d="", department="kitchen"),
                        iseaid=holder.pre)
        origin = acdcmap(israid=holder.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         iseaid=holder.pre)
        schema = origin.sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexOffer(hab=holder,
                             recp=verifier.pre,
                             message="Here is the overstuffed DAG",
                             origin=origin,
                             artifacts=[child, extra],
                             modifiers=dict(dp=[[[schema, "/", []],
                                                 [schema, "/e/holder", []]]]))

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_missing_edged_node():
    """Grant must include every ACDC node referenced by the origin DAG."""
    with openHby(name="ipex-v2-bad-grant-dangling-edge",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        child = acdcmap(israid=hab.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the incomplete DAG",
                             origin=origin)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_accepts_grant_with_section_level_edge_nonce():
    """Grant accepts an expanded edge section that carries its own nonce."""
    with openHby(name="ipex-v2-grant-edge-section-u",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        child = acdcmap(israid=hab.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=dict(d="",
                                   u=Noncer().qb64,
                                   holder=dict(d="", n=child.said, o="I2I")),
                         iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the expanded edge-section DAG",
                             origin=origin,
                             artifacts=[child])

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is not None
        assert recorder.items == [{"r": "/exn/ipex/grant",
                                   "d": exn.said,
                                   "m": "Here is the expanded edge-section DAG"}]


def test_ipex_v2_accepts_grant_with_nested_edge_group():
    """Grant accepts nested edge groups and walks their far-node leaves."""
    with openHby(name="ipex-v2-grant-edge-group",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        child0 = acdcmap(israid=hab.pre,
                         attribute=dict(d="", role="member"),
                         iseaid=hab.pre)
        child1 = acdcmap(israid=hab.pre,
                         attribute=dict(d="", department="kitchen"),
                         iseaid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=dict(d="",
                                   u=Noncer().qb64,
                                   either=dict(d="",
                                               o="OR",
                                               member=dict(d="", n=child0.said, o="I2I"),
                                               staff=dict(d="", n=child1.said, o="I2I"))),
                         iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the grouped-edge DAG",
                             origin=origin,
                             artifacts=[child0, child1])

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is not None
        assert recorder.items == [{"r": "/exn/ipex/grant",
                                   "d": exn.said,
                                   "m": "Here is the grouped-edge DAG"}]


def test_ipex_v2_rejects_grant_with_duplicate_disclosed_node():
    """Grant must not carry the same disclosed ACDC node more than once."""
    with openHby(name="ipex-v2-bad-grant-duplicate-node",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        child = acdcmap(israid=hab.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the duplicated DAG",
                             origin=origin,
                             artifacts=[child, child])

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_nonwalkable_compact_edges():
    """Grant rejects ACDCs whose edge block is compacted to a non-walkable value."""
    with openHby(name="ipex-v2-bad-grant-compact-edge",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         iseaid=hab.pre)
        sad = dict(origin.sad)
        sad["e"] = regcept(israid=hab.pre).said
        compactOrigin = type(origin)(sad=sad, makify=True)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the compacted DAG",
                             origin=compactOrigin)

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_unreachable_nested_node():
    """Grant must not carry extra nested ACDCs outside the origin DAG."""
    with openHby(name="ipex-v2-bad-grant-extra-node",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        child = acdcmap(israid=hab.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=hab.pre)
        extra = acdcmap(israid=hab.pre,
                        attribute=dict(d="", department="kitchen"),
                        iseaid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         edge=_edge("holder", child),
                         iseaid=hab.pre)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        exn, atc = ipexGrant(hab=hab,
                             recp=hab.pre,
                             message="Here is the overstuffed DAG",
                             origin=origin,
                             artifacts=[child, extra])

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_allows_grant_origin_to_differ_from_offer_origin():
    """Offer and grant may carry different root SAIDs when offer uses metadata ACDCs."""
    with openHby(name="ipex-v2-offer-metadata-origin",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        offerMeta = acdcmap(israid=hab.pre,
                            attribute=dict(d="", rules="club-entry"),
                            iseaid=hab.pre)
        grantOrigin = acdcmap(israid=hab.pre,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              iseaid=hab.pre)
        schema = grantOrigin.sad["s"]["$id"]
        applyExn, applyAtc = ipexApply(hab=hab,
                                       recp=hab.pre,
                                       message="Please issue a credential",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the metadata offer",
                                       origin=offerMeta,
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                       message="I agree to the metadata offer",
                                       offer=offerExn)

        for exn, atc in ((applyExn, applyAtc),
                         (offerExn, offerAtc),
                         (agreeExn, agreeAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the granted credential",
                                       origin=grantOrigin,
                                       agree=agreeExn)
        grantIms = bytearray(grantExn.raw)
        grantIms.extend(grantAtc)
        Parser(version=Vrsn_2_0).parse(ims=grantIms, framed=False, exc=exc)
        assert grantIms == bytearray()
        assert offerExn.ked["a"]["o"] == [offerMeta.said]
        assert grantExn.ked["a"]["o"] == [grantOrigin.said]
        assert offerExn.ked["a"]["o"] != grantExn.ked["a"]["o"]
        assert hby.db.exns.get(keys=(grantExn.said,)) is not None
        assert [item["r"] for item in recorder.items] == [
            "/exn/ipex/apply",
            "/exn/ipex/offer",
            "/exn/ipex/agree",
            "/exn/ipex/grant",
        ]


def test_ipex_v2_dispatch_linear_and_spurn():
    """Exercise linear routing, rejection, and spurn handling through Exchanger."""
    with openHby(name="ipex-v2-dispatch",
                 base="test") as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        schema = acdc.sad["s"]["$id"]

        # Create recorder
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Build a happy path chain: apply -> offer -> agree -> grant -> admit
        apply0, apply0Atc = ipexApply(hab=hab,
                                        recp=hab.pre,
                                        message="Please issue a credential",
                                        attrs=dict(role="member"),
                                        modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offer0, offer0Atc = ipexOffer(hab=hab,
                                      message="Here is the offered credential",
                                      origin=acdc,
                                      apply=apply0)
        agree0, agree0Atc = ipexAgree(hab=hab,
                                        message="I agree to the offer",
                                        offer=offer0)
        grant0, grant0Atc = ipexGrant(hab=hab,
                                        recp=hab.pre,
                                        message="Here is the granted credential",
                                        origin=acdc,
                                        agree=agree0)
        admit0, admit0Atc = ipexAdmit(hab=hab,
                                        message="Thanks for the credential",
                                        grant=grant0)

        # Try to parse the offer before apply
        offer0Ims = bytearray(offer0.raw)
        offer0Ims.extend(offer0Atc)
        Parser().parse(ims=offer0Ims, framed=False, exc=exc)
        assert offer0Ims == bytearray()
        
        # Assert it was rejected and not stored in db since its prior was not accepted yet
        assert hby.db.exns.get(keys=(offer0.said,)) is None

        # Parse the apply first 
        apply0Ims = bytearray(apply0.raw)
        apply0Ims.extend(apply0Atc)
        Parser().parse(ims=apply0Ims, framed=False, exc=exc)
        assert apply0Ims == bytearray()

        # Assert that the apply was accepted and stored
        storedApply = hby.db.exns.get(keys=(apply0.said,))
        assert storedApply is not None
        assert storedApply.ked["a"]["m"] == "Please issue a credential"
        assert storedApply.ked["a"]["role"] == "member"
        assert storedApply.ked["q"]["dp"] == [[[schema, "/", ["a/role"]]]]

        # Parse the rest of the chain
        offer0Ims = bytearray(offer0.raw)
        offer0Ims.extend(offer0Atc)
        Parser().parse(ims=offer0Ims, framed=False, exc=exc)
        assert offer0Ims == bytearray()

        agree0Ims = bytearray(agree0.raw)
        agree0Ims.extend(agree0Atc)
        Parser().parse(ims=agree0Ims, framed=False, exc=exc)
        assert agree0Ims == bytearray()

        grant0Ims = bytearray(grant0.raw)
        grant0Ims.extend(grant0Atc)
        Parser().parse(ims=grant0Ims, framed=False, exc=exc)
        assert grant0Ims == bytearray()

        admit0Ims = bytearray(admit0.raw)
        admit0Ims.extend(admit0Atc)
        Parser().parse(ims=admit0Ims, framed=False, exc=exc)
        assert admit0Ims == bytearray()

        # Assert that they were accepted and stored
        for serder in (offer0, agree0, grant0, admit0):
            assert hby.db.exns.get(keys=(serder.said,)) is not None

        storedOffer = hby.db.exns.get(keys=(offer0.said,))
        assert storedOffer.ked["a"]["m"] == "Here is the offered credential"
        assert storedOffer.ked["a"]["o"] == [acdc.said]
        assert "acdc" not in storedOffer.ked["a"]
        assert storedOffer.ked["q"]["dp"] == apply0.ked["q"]["dp"]
        assert storedOffer.ked["p"] == apply0.said

        storedOfferMsg = serializeMessage(hby, offer0.said, framed=True)
        storedOfferIms = bytearray(storedOfferMsg)
        storedOfferResults = Parser(version=Vrsn_2_0).parse(ims=storedOfferIms,
                                                            framed=False,
                                                            processive=False)
        assert storedOfferIms == bytearray()
        assert len(storedOfferResults) == 1
        assert storedOfferResults[0].nests == []

        storedAgree = hby.db.exns.get(keys=(agree0.said,))
        assert storedAgree.ked["a"]["m"] == "I agree to the offer"
        assert storedAgree.ked["p"] == offer0.said

        storedGrant = hby.db.exns.get(keys=(grant0.said,))
        assert storedGrant.ked["a"]["m"] == "Here is the granted credential"
        assert storedGrant.ked["a"]["o"] == [acdc.said]
        assert "iss" not in storedGrant.ked["a"]
        assert "anc" not in storedGrant.ked["a"]
        assert storedGrant.ked["p"] == agree0.said

        storedAdmit = hby.db.exns.get(keys=(admit0.said,))
        assert storedAdmit.ked["a"]["m"] == "Thanks for the credential"
        assert storedAdmit.ked["p"] == grant0.said

        # Build a spurn against apply
        dupSpurn, dupSpurnAtc = ipexSpurn(hab=hab,
                                              message="This should be rejected",
                                              spurned=apply0)

        # Parse it
        dupSpurnIms = bytearray(dupSpurn.raw)
        dupSpurnIms.extend(dupSpurnAtc)
        Parser().parse(ims=dupSpurnIms, framed=False, exc=exc)
        assert dupSpurnIms == bytearray()

        # Assert it was not accepted 
        assert hby.db.exns.get(keys=(dupSpurn.said,)) is None

        # Agree-backed grants are not spurnable, so callers now fail fast.
        with pytest.raises(ValueError):
            ipexSpurn(hab=hab,
                      message="This follow-on grant cannot be spurned",
                      spurned=grant0)

        # Build a bare grant
        grant1, grant1Atc = ipexGrant(hab=hab,
                                        recp=hab.pre,
                                        message="Bare grant without agreement",
                                        origin=acdc)

        # Build a spurn against that grant
        spurn1, spurn1Atc = ipexSpurn(hab=hab,
                                        message="I reject this grant",
                                        spurned=grant1)

        # Parse both
        grant1Ims = bytearray(grant1.raw)
        grant1Ims.extend(grant1Atc)
        Parser().parse(ims=grant1Ims, framed=False, exc=exc)
        assert grant1Ims == bytearray()

        spurn1Ims = bytearray(spurn1.raw)
        spurn1Ims.extend(spurn1Atc)
        Parser().parse(ims=spurn1Ims, framed=False, exc=exc)
        assert spurn1Ims == bytearray()

        # Assert that a flow-starting grant is valid and can also be explicitly spurned
        assert hby.db.exns.get(keys=(grant1.said,)) is not None
        assert hby.db.exns.get(keys=(spurn1.said,)) is not None

        with pytest.raises(ValueError):
            ipexOffer(hab=hab, message="Bare offer without receiver", origin=acdc)

        # Build a bare offer with the committed origin and explicit receiver;
        # the starter generates its own xid and still supports a valid spurn
        # against it.
        offer1, offer1Atc = ipexOffer(hab=hab,
                                      message="Bare offer for spurn path",
                                      origin=acdc,
                                      recp=hab.pre)
        assert offer1.ked["x"] != ""
        spurn2, spurn2Atc = ipexSpurn(hab=hab,
                                      message="I reject this offer",
                                      spurned=offer1)

        offer1Ims = bytearray(offer1.raw)
        offer1Ims.extend(offer1Atc)
        Parser().parse(ims=offer1Ims, framed=False, exc=exc)
        assert offer1Ims == bytearray()

        spurn2Ims = bytearray(spurn2.raw)
        spurn2Ims.extend(spurn2Atc)
        Parser().parse(ims=spurn2Ims, framed=False, exc=exc)
        assert spurn2Ims == bytearray()

        assert hby.db.exns.get(keys=(offer1.said,)) is not None
        assert hby.db.exns.get(keys=(spurn2.said,)) is not None

        # Assert routes and their coressponding message  
        routes = {item["r"] for item in recorder.items}
        assert routes == {
            "/exn/ipex/apply",
            "/exn/ipex/offer",
            "/exn/ipex/agree",
            "/exn/ipex/grant",
            "/exn/ipex/admit",
            "/exn/ipex/spurn",
        }
        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/apply", "Please issue a credential"),
            ("/exn/ipex/offer", "Here is the offered credential"),
            ("/exn/ipex/agree", "I agree to the offer"),
            ("/exn/ipex/grant", "Here is the granted credential"),
            ("/exn/ipex/admit", "Thanks for the credential"),
            ("/exn/ipex/grant", "Bare grant without agreement"),
            ("/exn/ipex/spurn", "I reject this grant"),
            ("/exn/ipex/offer", "Bare offer for spurn path"),
            ("/exn/ipex/spurn", "I reject this offer"),
        ]


def test_ipex_v2_nontransferable_nested_artifacts():
    """Exercise the cigar signing path with nested IPEX artifacts."""
    
    # Set up non-transferable hab, recorder, exchanger and load IPEX handlers
    with openHby(name="ipex-v2-nontrans",
                 base="test") as hby:
        hab = hby.makeHab(name="test", transferable=False)
        assert not hab.kever.prefixer.transferable
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Registry Inception
        registry = regcept(israid=hab.pre)

        # Create one ACDC node for the nested grant body
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        schema = acdc.sad["s"]["$id"]

        # Build IPEX messages
        applyExn, applyAtc = ipexApply(hab=hab,
                                       recp=hab.pre,
                                       message="Please issue a credential",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       origin=acdc,
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                       message="I agree to the offer",
                                       offer=offerExn)
        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the granted credential",
                                       origin=acdc,
                                       agree=agreeExn)

        # Parse Offer for assertions
        offerIms = bytearray(offerExn.raw)
        offerIms.extend(offerAtc)
        offerResults = Parser().parse(ims=offerIms,
                                                      framed=False,
                                                      processive=False)
        assert offerIms == bytearray()
        assert len(offerResults) == 1
        offerResult = offerResults[0]
        assert offerResult.nests == []

        # Parse Grant for assertions
        grantIms = bytearray(grantExn.raw)
        grantIms.extend(grantAtc)
        grantResults = Parser().parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        grantResult = grantResults[0]
        assert grantResult.nests[0].serder.said == acdc.said
        assert len(grantResult.nests) == 1

        # Dispatch the whole chain
        for exn, atc in ((applyExn, applyAtc),
                         (offerExn, offerAtc),
                         (agreeExn, agreeAtc),
                         (grantExn, grantAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser().parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        # Assert they were all processed and stored
        for serder in (applyExn, offerExn, agreeExn, grantExn):
            assert hby.db.exns.get(keys=(serder.said,)) is not None

        # Check recorder for correct route/message pairs
        assert [(item["r"], item["m"]) for item in recorder.items] == [
            ("/exn/ipex/apply", "Please issue a credential"),
            ("/exn/ipex/offer", "Here is the offered credential"),
            ("/exn/ipex/agree", "I agree to the offer"),
            ("/exn/ipex/grant", "Here is the granted credential"),
        ]


def test_ipex_v2_rejects_unsupported_nested_frame():
    """Reject a carried artifact that starts with an unsupported CESR frame."""
    with openHby(name="ipex-v2-bad-frame",
                 base="test") as hby:
        hab = hby.makeHab(name="test")
        bad = Counter.enclose(qb64=b'',
                              code=Codens.AttachmentGroup,
                              version=Vrsn_2_0)

        with pytest.raises(ValueError, match="unsupported leading frame"):
            ipexGrant(hab=hab,
                      recp=hab.pre,
                      message="Here is the granted credential",
                      origin=bad)


def test_ipex_v2_rejects_offer_without_dp():
    with openHby(name="ipex-v2-bad-offer-dp",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Create one local AID that acts as both sender and receiver for the EXN
        hab = hby.makeHab(name="test")
        
        # Set up recorder, exchanger and load IPEX Handlers
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        # Build a normal offer first, then remove q.dp to prove the V2 handler
        # fails closed on the required disclosure-plan field.
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential")
        sad = dict(exn.ked)
        sad["q"] = {}
        badOffer = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badOffer,
                                    framed=False,
                                    gvrsn=Vrsn_2_0))
        del atc[:badOffer.size]

        # Rebuild the tampered wire message with the malformed signed body.
        ims = bytearray(badOffer.raw)
        ims.extend(atc)

        Parser().parse(ims=ims, framed=False, exc=exc)

        # The parser consumed the whole stream even though the handler rejected the EXN
        assert ims == bytearray()

        # Rejected offers must not be persisted as accepted exchange messages
        assert hby.db.exns.get(keys=(badOffer.said,)) is None

        # Rejected offers must also not create user-facing IPEX notifications
        assert recorder.items == []


def test_ipex_v2_accepts_offer_with_missing_origin_attr_without_throwing():
    with openHby(name="ipex-v2-bad-offer-origin",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential")
        sad = dict(exn.ked)
        sad["a"] = dict(exn.ked["a"])
        sad["a"].pop("o")
        badOffer = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badOffer,
                                    framed=False,
                                    gvrsn=Vrsn_2_0))
        del atc[:badOffer.size]

        ims = bytearray(badOffer.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        stored = hby.db.exns.get(keys=(badOffer.said,))
        assert stored is not None
        assert "o" not in stored.ked["a"]
        assert recorder.items == [{"r": "/exn/ipex/offer", "d": badOffer.said, "m": "Here is the offered credential"}]


def test_ipex_v2_rejects_offer_with_nonstring_origin_without_throwing():
    with openHby(name="ipex-v2-bad-offer-origin-type",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential")
        sad = dict(exn.ked)
        sad["a"] = dict(exn.ked["a"])
        sad["a"]["o"] = 123
        badOffer = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badOffer,
                                    framed=False,
                                    gvrsn=Vrsn_2_0))
        del atc[:badOffer.size]

        ims = bytearray(badOffer.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(badOffer.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_offer_with_forged_nested_artifact():
    with openHby(name="ipex-v2-bad-offer-origin-nest",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=hab.pre)
        origin = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         iseaid=hab.pre)
        sibling = acdcmap(israid=hab.pre,
                          attribute=dict(d="", rules="club-entry"),
                          iseaid=hab.pre)

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=origin,
                           message="Here is the offered credential")

        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(sibling)]))
        del atc[:exn.size]

        ims = bytearray(exn.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_invalid_origin_said_without_throwing():
    with openHby(name="ipex-v2-bad-grant-origin-said",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           origin=acdc)
        sad = dict(exn.ked)
        sad["a"] = dict(exn.ked["a"])
        sad["a"]["o"] = ["not-a-said"]
        badGrant = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badGrant,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(acdc)]))
        del atc[:badGrant.size]

        ims = bytearray(badGrant.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(badGrant.said,)) is None
        assert recorder.items == []


def test_ipex_v2_rejects_grant_without_origin_nested_artifact():
    with openHby(name="ipex-v2-bad-grant-origin",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        # Set up recorder, exchanger and load IPEX Handlers
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Create the registry and ACDC referenced by the grant
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        sibling = acdcmap(israid=hab.pre,
                          attribute=dict(d="", status="member"),
                          iseaid=hab.pre)

        # Build a correct grant body that carries the origin plus one linked sibling node.
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           origin=acdc,
                           artifacts=[sibling])

        # Re-endorse the same body but omit the origin artifact. In V2 the grant
        # must carry the presentation/ACDC as the first nested artifact matching a.o.
        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(sibling)]))

        # Strip the body returned by `endorse`; we only want the tampered attachments
        del atc[:exn.size]

        # Rebuild the malformed wire message: valid grant body, but the first
        # nested artifact no longer matches the origin SAID in a.o.
        ims = bytearray(exn.raw)
        ims.extend(atc)

        # Parse through the exchanger/IPEX route 
        Parser().parse(ims=ims, framed=False, exc=exc)

        # The parser should drain the input even though the IPEX handler rejects it
        assert ims == bytearray()

        # A rejected grant must not be saved as an accepted EXN
        assert hby.db.exns.get(keys=(exn.said,)) is None

        # A rejected grant must not create a user-facing IPEX notification
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_missing_origin_attr_without_throwing():
    with openHby(name="ipex-v2-bad-grant-acdc",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")

        # Set up recorder, exchanger and load IPEX Handlers
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Create the registry artifacts carried by the malformed grant.
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        # Start from a valid grant, then remove `a.o` and re-sign it so the
        # parser reaches the handler with a malformed but otherwise authentic body.
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           origin=acdc)
        sad = dict(exn.ked)
        sad["a"] = dict(exn.ked["a"])
        sad["a"].pop("o")
        badGrant = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badGrant,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(acdc)]))
        del atc[:badGrant.size]

        ims = bytearray(badGrant.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        # The parser should drain the input even though the handler rejects it,
        # proving malformed grant bodies fail closed instead of throwing.
        assert ims == bytearray()
        assert hby.db.exns.get(keys=(badGrant.said,)) is None
        assert recorder.items == []


def test_ipex_v2_responders_set_receiver():
    """Responder verbs address the prior's sender and come from the prior's receiver.

    apply and grant already thread ``receiver=recp``; offer, agree, admit, and
    spurn respond to a prior message whose sender is the party to address, so
    their receiver derives from that prior's ``i`` field. An offer opened with no
    prior (the offer-first bootstrap) takes an explicit ``recp`` instead.
    """
    with openHby(name="ipex-v2-receiver",
                 base="test") as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")

        registry = regcept(israid=holder.pre)
        acdc = acdcmap(israid=holder.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        schema = acdc.sad["s"]["$id"]

        # verifier applies to holder
        applyExn, _ = ipexApply(hab=verifier,
                                recp=holder.pre,
                                message="Prove over-21",
                                attrs=dict(role="member"),
                                modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        assert applyExn.ked["i"] == verifier.pre
        assert applyExn.ked["ri"] == holder.pre

        # holder offers, addressing the applicant (apply's sender) by derivation
        offerExn, _ = ipexOffer(hab=holder,
                                message="Here are the terms",
                                origin=acdc,
                                apply=applyExn)
        assert offerExn.ked["i"] == holder.pre
        assert offerExn.ked["ri"] == verifier.pre

        # verifier agrees, addressing the holder (offer's sender)
        agreeExn, _ = ipexAgree(hab=verifier,
                                message="I agree",
                                offer=offerExn)
        assert agreeExn.ked["ri"] == holder.pre

        # holder grants to verifier
        grantExn, _ = ipexGrant(hab=holder,
                                recp=verifier.pre,
                                message="Disclosure",
                                origin=acdc,
                                agree=agreeExn)
        assert grantExn.ked["ri"] == verifier.pre

        # verifier admits, addressing the holder (grant's sender)
        admitExn, _ = ipexAdmit(hab=verifier,
                                message="Thanks",
                                grant=grantExn)
        assert admitExn.ked["ri"] == holder.pre

        # holder spurns the apply, addressing its sender (verifier)
        spurnExn, _ = ipexSpurn(hab=holder,
                                message="No thanks",
                                spurned=applyExn)
        assert spurnExn.ked["ri"] == verifier.pre

        # offer-first bootstrap: no prior apply, so the caller supplies the
        # committed origin plus explicit recp, and the builder generates xid.
        bootExn, _ = ipexOffer(hab=holder,
                               message="Opening offer",
                               origin=acdc,
                               recp=verifier.pre)
        assert bootExn.ked["p"] == ""
        assert bootExn.ked["ri"] == verifier.pre
        assert bootExn.ked["x"] != ""

        # An explicit recp that matches the prior-derived receiver is still valid.
        overrideExn, _ = ipexAgree(hab=verifier,
                                   message="I agree",
                                   offer=offerExn,
                                   recp=holder.pre)
        assert overrideExn.ked["ri"] == holder.pre


def test_ipex_v2_builders_reject_prior_party_mismatches_and_caller_xid():
    """Prior-based builders reject party mismatches and no longer accept caller-supplied xid."""
    with openHby(name="ipex-v2-prior-party-mismatch",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Create the honest holder, the honest verifier, and an unrelated third party
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        mallory = hby.makeHab(name="mallory")

        # Create one credential payload so the later grant builder has a real origin artifact
        registry = regcept(israid=holder.pre)
        acdc = acdcmap(israid=holder.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        # Reuse the credential schema in the apply disclosure request.
        schema = acdc.sad["s"]["$id"]

        # Start a valid apply-first thread from the verifier to the holder.
        applyExn, _ = ipexApply(hab=verifier,
                                recp=holder.pre,
                                message="Prove over-21",
                                attrs=dict(role="member"),
                                modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        # Continue with the valid holder response that derives its receiver and xid from the apply.
        offerExn, _ = ipexOffer(hab=holder,
                                message="Here are the terms",
                                origin=acdc,
                                apply=applyExn)
        # Continue with the valid verifier response back to the holder.
        agreeExn, _ = ipexAgree(hab=verifier,
                                message="I agree",
                                offer=offerExn)
        # Build one valid grant so the admit-path negative checks have a real prior.
        grantExn, _ = ipexGrant(hab=holder,
                                recp=verifier.pre,
                                message="Disclosure",
                                origin=acdc,
                                agree=agreeExn)

        # Set 1: an unrelated third party cannot consume any response slot in the thread.
        # Mallory cannot answer someone else's apply as if it were the holder.
        with pytest.raises(ValueError):
            ipexOffer(hab=mallory, message="Bad sender", origin=acdc, apply=applyExn)
        # Mallory cannot answer the offer as if it were the verifier.
        with pytest.raises(ValueError):
            ipexAgree(hab=mallory, message="Bad sender", offer=offerExn)
        # Mallory cannot send the grant even if it targets the right verifier.
        with pytest.raises(ValueError):
            ipexGrant(hab=mallory,
                      recp=verifier.pre,
                      message="Bad sender",
                      origin=acdc,
                      agree=agreeExn)
        # Mallory cannot acknowledge the grant as if it were the verifier.
        with pytest.raises(ValueError):
            ipexAdmit(hab=mallory, message="Bad sender", grant=grantExn)
        # Mallory cannot spurn the original apply as if it were the holder.
        with pytest.raises(ValueError):
            ipexSpurn(hab=mallory, message="Bad sender", spurned=applyExn)

        # Set 2: honest participants still cannot redirect replies to an unrelated receiver.
        # The real holder cannot override the derived receiver with a different target.
        with pytest.raises(ValueError):
            ipexOffer(hab=holder,
                      message="Bad receiver",
                      origin=acdc,
                      apply=applyExn,
                      recp=mallory.pre)
        # The verifier cannot redirect the agree to someone other than the prior sender.
        with pytest.raises(ValueError):
            ipexAgree(hab=verifier, message="Bad receiver", offer=offerExn, recp=mallory.pre)
        # The holder cannot point the grant at a recipient other than the agreeing verifier.
        with pytest.raises(ValueError):
            ipexGrant(hab=holder,
                      recp=mallory.pre,
                      message="Bad receiver",
                      origin=acdc,
                      agree=agreeExn)
        # The real verifier cannot redirect the admit to anyone other than the grant sender.
        with pytest.raises(ValueError):
            ipexAdmit(hab=verifier, message="Bad receiver", grant=grantExn, recp=mallory.pre)
        # The holder cannot redirect the spurn away from the original verifier.
        with pytest.raises(ValueError):
            ipexSpurn(hab=holder, message="Bad receiver", spurned=applyExn, recp=mallory.pre)

        # Set 3: callers can no longer override xid on any builder because the
        # builder API owns thread identity completely.
        with pytest.raises(TypeError):
            ipexOffer(hab=holder, message="Bad xid", origin=acdc, apply=applyExn, xid="F" * 44)
        with pytest.raises(TypeError):
            ipexAgree(hab=verifier, message="Bad xid", offer=offerExn, xid="F" * 44)
        with pytest.raises(TypeError):
            ipexGrant(hab=holder,
                      recp=verifier.pre,
                      message="Bad xid",
                      origin=acdc,
                      agree=agreeExn,
                      xid="F" * 44)
        with pytest.raises(TypeError):
            ipexAdmit(hab=verifier, message="Bad xid", grant=grantExn, xid="F" * 44)
        with pytest.raises(TypeError):
            ipexSpurn(hab=holder, message="Bad xid", spurned=applyExn, xid="F" * 44)
        with pytest.raises(TypeError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Bad xid",
                      attrs=dict(role="member"),
                      modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
                      xid="F" * 44)

        # Set 4: every flow starter still needs a recipient, but now generates
        # xid internally without accepting one from the caller.
        # Offer-first flows reject a starter with no recipient.
        with pytest.raises(ValueError):
            ipexOffer(hab=holder, message="Bare offer", origin=acdc)
        # Supplying the origin plus recipient is enough for an offer-first opener.
        bareOffer, _ = ipexOffer(hab=holder, message="Bare offer", origin=acdc, recp=verifier.pre)
        assert bareOffer.ked["p"] == ""
        assert bareOffer.ked["ri"] == verifier.pre
        assert bareOffer.ked["x"] != ""
        assert bareOffer.ked["a"]["o"] == [acdc.said]
        # Supplying xid directly is no longer supported at all.
        with pytest.raises(TypeError):
            ipexOffer(hab=holder,
                      message="Bare offer",
                      origin=acdc,
                      recp=verifier.pre,
                      xid="E" * 44)
        # Grant-first flows follow the same auto-generated-xid rule.
        bareGrant, _ = ipexGrant(hab=holder,
                                 recp=verifier.pre,
                                 message="Bare grant",
                                 origin=acdc)
        assert bareGrant.ked["p"] == ""
        assert bareGrant.ked["ri"] == verifier.pre
        assert bareGrant.ked["x"] != ""
        # Apply starts a new thread too, so an empty receiver must still be rejected immediately.
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp="",
                      message="Missing receiver",
                      attrs=dict(role="member"),
                      modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        # Apply now generates xid internally when the caller omits it.
        bareApply, _ = ipexApply(hab=verifier,
                                 recp=holder.pre,
                                 message="Generated xid",
                                 attrs=dict(role="member"),
                                 modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        assert bareApply.ked["p"] == ""
        assert bareApply.ked["ri"] == holder.pre
        assert bareApply.ked["x"] != ""
        assert bareApply.ked["q"]["dp"] == [[[schema, "/", ["a/role"]]]]

        # Set 5: apply still enforces its own disclosure-plan contract after starter fields pass.
        # Even with recp present and xid auto-generated, apply still requires an explicit disclosure plan.
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Missing disclosure plan",
                      attrs=dict(role="member"))
        # The disclosure-plan field must also have the expected list structure.
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Bad disclosure plan type",
                      modifiers=dict(dp="not-a-list"))
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Flat disclosure plan is no longer accepted",
                      modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Bad disclosure plan nesting",
                      modifiers=dict(dp=[[[[schema, "/", ["a/role"]]]]]))


def test_ipex_v2_rejects_third_party_prior_response_without_throwing():
    """A third party cannot consume the response slot for someone else's IPEX thread."""
    with openHby(name="ipex-v2-third-party-response",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        mallory = hby.makeHab(name="mallory")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        registry = regcept(israid=holder.pre)
        acdc = acdcmap(israid=holder.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        schema = acdc.sad["s"]["$id"]

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Prove over-21",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        offerExn, offerAtc = ipexOffer(hab=holder,
                                       message="Here are the terms",
                                       origin=acdc,
                                       apply=applyExn)

        for exn, atc in ((applyExn, applyAtc), (offerExn, offerAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()

        recorder.items.clear()

        badAgree = exchange(sender=mallory.pre,
                            receiver=holder.pre,
                            prior=offerExn.said,
                            route="/ipex/agree",
                            attributes=dict(m="Mallory cannot accept this"),
                            pvrsn=Vrsn_2_0,
                            gvrsn=Vrsn_2_0,
                            kind=mallory.kever.serder.kind)
        atc = bytearray(mallory.endorse(serder=badAgree, framed=False, gvrsn=Vrsn_2_0))
        del atc[:badAgree.size]

        ims = bytearray(badAgree.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(badAgree.said,)) is None
        assert recorder.items == []

        selfAgree = exchange(sender=holder.pre,
                             receiver=holder.pre,
                             prior=offerExn.said,
                             route="/ipex/agree",
                             attributes=dict(m="Holder cannot accept its own offer"),
                             pvrsn=Vrsn_2_0,
                             gvrsn=Vrsn_2_0,
                             kind=holder.kever.serder.kind)
        atc = bytearray(holder.endorse(serder=selfAgree, framed=False, gvrsn=Vrsn_2_0))
        del atc[:selfAgree.size]

        ims = bytearray(selfAgree.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(selfAgree.said,)) is None
        assert recorder.items == []


def test_ipex_v2_blindable_registry_roundtrip():
    """Grant a blindable V2 registry update through IPEX and recover it."""
    with openHby(name="ipex-v2-blindable",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="ipex-v2-blindable", temp=True)
        try:
            # Create and anchor a registry before issuing any credential state
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blindable", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Build one ACDC that explicitly declares this registry as its governing rd
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Issue one blindable registry update and capture the anchoring KEL event for it
            issuedBlinder, iss = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, iss, framed=False)

            # Wire an exchanger with IPEX handlers so the grant can be parsed end to end
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            # Grant the registry-backed ACDC through one IPEX message, carrying
            # its issuer-auth proof group on the same disclosed node.
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Blindable disclosure",
                                           origin=_proofed(acdc, issuedBlinder))

            # Parse the transmitted EXN stream and ensure the whole message is consumed
            grantIms = bytearray(grantExn.raw)
            grantIms.extend(grantAtc)
            Parser(version=Vrsn_2_0).parse(ims=grantIms, framed=False, exc=exc)
            assert grantIms == bytearray()

            # Reload the stored EXN body and verify the V2 nested artifacts live in enst
            stored, pathed = cloneMessage(hby, grantExn.said)
            assert stored is not None
            assert pathed == {}
            nests = [bytearray(nest.encode("utf-8") if isinstance(nest, str) else nest)
                     for nest in hby.db.enst.get(keys=(grantExn.said,))]
            parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray().join(nests),
                                                    framed=True,
                                                    processive=False)
            assert [nest.serder.said for nest in parsed] == [acdc.said]
            assert len(parsed[0].bsqs) == 1
            proof = parsed[0].bsqs[0]
            assert proof[0].qb64 == issuedBlinder.said
            assert proof[1].nonce == issuedBlinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "issued"
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"])
            assert unblinder is not None
            assert unblinder.state == "issued"

            # Serializing the whole stored message should round-trip the same
            # nested node and its proof-group attachment section.
            msg = serializeMessage(hby, grantExn.said, framed=True)
            ims = bytearray(msg)
            results = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                     framed=False,
                                                     processive=False)
            assert ims == bytearray()
            assert len(results) == 1
            assert [nest.serder.said for nest in results[0].nests] == [acdc.said]
            assert len(results[0].nests[0].bsqs) == 1
            proof = results[0].nests[0].bsqs[0]
            assert proof[0].qb64 == issuedBlinder.said
            assert proof[1].nonce == issuedBlinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "issued"
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"])
            assert unblinder is not None
            assert unblinder.state == "issued"
        finally:
            rgy.close()


def test_ipex_v2_rejects_registry_backed_grant_without_node_proof_group():
    """A grant with rd must carry exactly one node-local registry proof group."""
    with openHby(name="ipex-v2-missing-node-proof",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="ipex-v2-missing-node-proof", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="missing-proof", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued, framed=False)

            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            # The nested origin carries the registry-backed ACDC body only, so
            # the handler must fail closed instead of guessing at alternates.
            exn, atc = ipexGrant(hab=hab,
                                 recp=hab.pre,
                                 message="Missing node-local proof",
                                 origin=acdc)

            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

            assert ims == bytearray()
            assert hby.db.exns.get(keys=(exn.said,)) is None
            assert recorder.items == []
        finally:
            rgy.close()


def test_ipex_v2_escrows_registry_backed_grant_until_tel_evidence_arrives():
    """Recipient keeps a registry-backed grant retryable until TEL evidence is loaded."""
    with (openHby(name="ipex-v2-proof-escrow-issuer",
                  base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="ipex-v2-proof-escrow-recipient",
                  base="test",
                  version=Vrsn_2_0) as recipientHby):
        issuerHab = issuerHby.makeHab(name="issuer")
        recipientHab = recipientHby.makeHab(name="recipient")
        issuerRgy = Regery(hby=issuerHby, name="ipex-v2-proof-escrow-issuer", temp=True)
        recipientRgy = Regery(hby=recipientHby, name="ipex-v2-proof-escrow-recipient", temp=True)
        try:
            registrar = Registrar(rgy=issuerRgy)
            registry = registrar.makeRegistry(name="proof-escrow", prefix=issuerHab.pre)
            rip = issuerRgy.store.event(registry.regk)
            ripAnc = _anchor(issuerHab, registry, rip, framed=True)

            acdc = acdcmap(israid=issuerHab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=recipientHab.pre)
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            issuedAnc = _anchor(issuerHab, registry, issued, framed=False)

            recipientRemoteKvy = Kevery(db=recipientHby.db, lax=False, local=False)
            Parser(version=Vrsn_2_0).parse(
                ims=bytearray(issuerHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)),
                kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(ripAnc), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuedAnc),
                                           framed=False,
                                           kvy=recipientRemoteKvy)

            recorder = Recorder()
            exc = Exchanger(hby=recipientHby, handlers=[])
            loadHandlers(hby=recipientHby, exc=exc, notifier=recorder, rgy=recipientRgy)

            grantExn, grantAtc = ipexGrant(hab=issuerHab,
                                           recp=recipientHab.pre,
                                           message="Waiting on observer TEL",
                                           origin=_proofed(acdc, issuedBlinder))

            ims = bytearray(grantExn.raw)
            ims.extend(grantAtc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

            assert ims == bytearray()
            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is not None
            assert recorder.items == []
            assert list(exc.cues) == [dict(kin="proof", said=grantExn.said)]

            # Simulate the disclosee learning the issuer's TEL later, for
            # example by fetching it from observers after the first grant parse.
            recipientRgy.store.accept(registry.regk, 0, rip)
            recipientRgy.store.accept(registry.regk, 1, issued)

            exc.processEscrow()

            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is not None
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is None
            assert recorder.items == [
                {"r": "/exn/ipex/grant", "d": grantExn.said, "m": "Waiting on observer TEL"},
            ]
            assert list(exc.cues) == [
                dict(kin="proof", said=grantExn.said),
                dict(kin="saved", said=grantExn.said),
            ]
        finally:
            recipientRgy.close()
            issuerRgy.close()


def test_ipex_v2_blind_registry_update_roundtrip():
    """Grant a blind ``bup`` registry update through a full linear V2 IPEX exchange."""
    with openHby(name="ipex-v2-blind-registry",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="ipex-v2-blind-registry", temp=True)
        try:
            # Create and anchor a real registry so the blind update can be accepted into the TEL
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blind", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Build one ACDC whose rd points at the new registry
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            schema = acdc.sad["s"]["$id"]

            # Commit one blindable registry update and capture both the blinder and the KEL event that sealed it
            blinder, bup = registrar.issue(registry, acdc=acdc, state="revoked")
            _anchor(hab, registry, bup, framed=False)

            # The accepted TEL should now contain the registry inception followed by the blindable update
            assert rgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert rgy.store.seqEvent(registry.regk, 1).said == bup.said
            assert rgy.store.headEvent(registry.regk).said == bup.said
            assert bup.ilk == "bup"
            assert bup.sad["rd"] == registry.regk
            assert bup.sad["p"] == rip.said
            assert bup.sad["b"] == blinder.said
            assert "td" not in bup.sad
            assert "ts" not in bup.sad

            # Wire an exchanger with the V2 IPEX handlers and build one full apply -> offer -> agree -> grant -> admit chain
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            applyExn, applyAtc = ipexApply(hab=hab,
                                           recp=hab.pre,
                                           message="Please issue the blind credential",
                                           attrs=dict(flow="blind"),
                                           modifiers=dict(dp=[[[schema, "/", []]]]))
            offerExn, offerAtc = ipexOffer(hab=hab,
                                           message="Here is the blind credential",
                                           origin=acdc,
                                           apply=applyExn)
            agreeExn, agreeAtc = ipexAgree(hab=hab,
                                           message="I agree to the blind credential",
                                           offer=offerExn)
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Here is the blind registry disclosure",
                                           origin=_proofed(acdc, blinder),
                                           agree=agreeExn)
            admitExn, admitAtc = ipexAdmit(hab=hab,
                                           message="Thanks for the blind credential",
                                           grant=grantExn)

            # Parse and dispatch the full exchange in order so the accepted IPEX chain is stored
            for exn, atc in ((applyExn, applyAtc),
                             (offerExn, offerAtc),
                             (agreeExn, agreeAtc),
                             (grantExn, grantAtc),
                             (admitExn, admitAtc)):
                ims = bytearray(exn.raw)
                ims.extend(atc)
                Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
                assert ims == bytearray()

            # All accepted EXNs should now exist in the exchange database
            for serder in (applyExn, offerExn, agreeExn, grantExn, admitExn):
                assert hby.db.exns.get(keys=(serder.said,)) is not None

            # The grant body should name the exact artifacts it transported
            storedGrant = hby.db.exns.get(keys=(grantExn.said,))
            assert storedGrant.ked["p"] == agreeExn.said
            assert storedGrant.ked["a"]["o"] == [acdc.said]
            assert "iss" not in storedGrant.ked["a"]
            assert "anc" not in storedGrant.ked["a"]

            # The stored message should round-trip with the same nested ACDC and
            # the node-local blind proof group used to vet it.
            msg = serializeMessage(hby, grantExn.said, framed=True)
            ims = bytearray(msg)
            results = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                     framed=False,
                                                     processive=False)
            assert ims == bytearray()
            assert len(results) == 1
            assert [nest.serder.said for nest in results[0].nests] == [acdc.said]
            assert len(results[0].nests[0].bsqs) == 1
            proof = results[0].nests[0].bsqs[0]
            assert proof[0].qb64 == blinder.said
            assert proof[1].nonce == blinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "revoked"
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"])
            assert unblinder is not None
            assert unblinder.state == "revoked"

            # The notifier should report the accepted linear IPEX exchange in send order
            assert [(item["r"], item["m"]) for item in recorder.items] == [
                ("/exn/ipex/apply", "Please issue the blind credential"),
                ("/exn/ipex/offer", "Here is the blind credential"),
                ("/exn/ipex/agree", "I agree to the blind credential"),
                ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                ("/exn/ipex/admit", "Thanks for the blind credential"),
            ]
        finally:
            rgy.close()


def test_ipex_v2_blind_registry_update_roundtrip_through_kram(fakeHelpingClock):
    """Route one blind-registry IPEX exchange through Kevery.processMsg and KRAM.

    This covers both the happy path and a recovery case where an IPEX `offer`
    arrives outside the KRAM timeliness window, gets dropped, is resent with a
    fresh in-window timestamp, and the exchange proceeds normally from there.
    """
    # Keep the KRAM cache timings local to this test so the window assertions
    # below read directly against the exact policy in force.
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    # Drive all message timestamps and receive-time checks from one mutable
    # clock so the test can create one stale delivery and then recover by
    # retrying from the advanced current time.
    clock = fakeHelpingClock
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # Unpack the cache timings we assert against:
    # d  = allowed clock drift
    # sl = short-lag timeliness window for single-key / current-est auth
    # xl = total exchange lifetime measured from xdt
    d = kramConfig["kram"]["caches"]["~"][0]
    sl = kramConfig["kram"]["caches"]["~"][1]
    xl = kramConfig["kram"]["caches"]["~"][3]

    with openHby(name="ipex-v2-blind-registry-kram",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Create two habs: sender and recipient
        hab = hby.makeHab(name="test")
        recipient = hby.makeHab(name="recipient")
        rgy = Regery(hby=hby, name="ipex-v2-blind-registry-kram", temp=True)
        try:
            # Build a blindable registry and commit one issuance-state update
            # so the grant can carry actual registry disclosure artifacts.
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blind-kram", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Issue one credential bound to that registry for the recipient.
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=recipient.pre)
            schema = acdc.sad["s"]["$id"]

            # Commit one blindable state update and capture the KEL event that
            # anchors it so the IPEX grant can disclose the full package.
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued, framed=False)

            # IPEX builders sign transferable messages against lastEst. After the
            # registry anchors, make current key state an establishment event again
            # so KRAM can authenticate the live IPEX wire with current tsgs.
            hab.rotate(framed=True,
                       version=Vrsn_2_0,
                       kind=hab.kever.serder.kind,
                       gvrsn=Vrsn_2_0)

            # Wire the real IPEX exchanger so accepted messages are both KRAM-
            # authenticated and dispatched through the usual handler path.
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            with openCF(name="ipex-v2-kram", base="test", temp=True) as cf:
                cf.put(kramConfig)
                kvy = Kevery(db=hby.db,
                             lax=False,
                             local=False,
                             kramer=Kramer(db=hby.db, cf=cf),
                             exc=exc)
                assert kvy.kramer.enabled is True

                # Drive each message timestamp from the fake clock directly. The
                # clock starts at the apply, advances to create one stale offer,
                # then continues forward as each accepted message is built.
                applyStamp = helping.nowIso8601()
                applyExn, applyAtc = ipexApply(hab=recipient,
                                               recp=hab.pre,
                                               message="Please issue the blind credential",
                                               attrs={},
                                               modifiers=dict(dp=[[[schema, "/", []]]]),
                                               dt=applyStamp)
                applyReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # Deliver apply first so the later offer retry can legally answer
                # it in the IPEX handler chain.
                applyIms = bytearray(applyExn.raw)
                applyIms.extend(applyAtc)
                Parser(version=Vrsn_2_0).parse(ims=applyIms, kvy=kvy)
                assert applyIms == bytearray()

                applyStored = hby.db.exns.get(keys=(applyExn.said,))
                assert applyStored is not None
                assert applyStored.ked["x"] == applyExn.ked["x"]

                applyCache = hby.db.kramTMSC.get(
                    keys=(recipient.pre, applyExn.ked["x"], applyExn.said))
                assert applyCache is not None
                assert applyCache.mdt == applyStamp
                assert applyCache.xdt == applyStamp
                assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                applyMdtMs = helping.fromIso8601(applyCache.mdt).timestamp() * 1000
                applyXdtMs = helping.fromIso8601(applyCache.xdt).timestamp() * 1000
                assert (applyReceiveMs - d - sl) <= applyMdtMs <= (applyReceiveMs + d)
                assert applyXdtMs <= applyMdtMs <= (applyXdtMs + xl)

                # Move forward a hair, build the stale offer, then advance past
                # the lower timeliness bound before attempting delivery.
                clock.advance(milliseconds=1)
                staleOfferStamp = helping.nowIso8601()
                staleOfferExn, staleOfferAtc = ipexOffer(hab=hab,
                                                         message="Here is the blind credential",
                                                         origin=acdc,
                                                         apply=applyExn,
                                                         dt=staleOfferStamp)
                clock.advance(milliseconds=d + sl + 1)
                staleOfferReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # The stale offer still points at the same transaction, but its
                # message timestamp is just outside the lower timeliness bound.
                assert staleOfferExn.ked["x"] == applyExn.ked["x"]
                staleOfferMs = helping.fromIso8601(staleOfferStamp).timestamp() * 1000
                assert staleOfferMs < (staleOfferReceiveMs - d - sl)

                # Send the first offer attempt with the stale timestamp. It must
                # be dropped by KRAM before the exchanger records it as a response
                # to the apply.
                staleOfferIms = bytearray(staleOfferExn.raw)
                staleOfferIms.extend(staleOfferAtc)

                Parser(version=Vrsn_2_0).parse(ims=staleOfferIms, kvy=kvy)

                assert staleOfferIms == bytearray()
                assert hby.db.kramTMSC.get(
                    keys=(hab.pre, applyExn.ked["x"], staleOfferExn.said)) is None
                assert hby.db.exns.get(keys=(staleOfferExn.said,)) is None
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                ]

                # Resend the same logical offer from the current fake-clock time.
                clock.advance(milliseconds=1)
                offerRetryStamp = helping.nowIso8601()
                offerExn, offerAtc = ipexOffer(hab=hab,
                                               message="Here is the blind credential",
                                               origin=acdc,
                                               apply=applyExn,
                                               dt=offerRetryStamp)
                offerReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                offerIms = bytearray(offerExn.raw)
                offerIms.extend(offerAtc)
                Parser(version=Vrsn_2_0).parse(ims=offerIms, kvy=kvy)
                assert offerIms == bytearray()

                offerStored = hby.db.exns.get(keys=(offerExn.said,))
                assert offerStored is not None
                assert offerStored.ked["x"] == applyExn.ked["x"]

                offerCache = hby.db.kramTMSC.get(
                    keys=(hab.pre, applyExn.ked["x"], offerExn.said))
                assert offerCache is not None
                assert offerCache.mdt == offerRetryStamp
                assert offerCache.xdt == applyStamp
                assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                offerMdtMs = helping.fromIso8601(offerCache.mdt).timestamp() * 1000
                offerXdtMs = helping.fromIso8601(offerCache.xdt).timestamp() * 1000
                assert (offerReceiveMs - d - sl) <= offerMdtMs <= (offerReceiveMs + d)
                assert offerXdtMs <= offerMdtMs <= (offerXdtMs + xl)

                clock.advance(milliseconds=1)
                agreeStamp = helping.nowIso8601()
                agreeExn, agreeAtc = ipexAgree(hab=recipient,
                                               message="I agree to the blind credential",
                                               offer=offerExn,
                                               dt=agreeStamp)
                agreeReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                agreeIms = bytearray(agreeExn.raw)
                agreeIms.extend(agreeAtc)
                Parser(version=Vrsn_2_0).parse(ims=agreeIms, kvy=kvy)
                assert agreeIms == bytearray()

                agreeStored = hby.db.exns.get(keys=(agreeExn.said,))
                assert agreeStored is not None
                assert agreeStored.ked["x"] == applyExn.ked["x"]

                agreeCache = hby.db.kramTMSC.get(
                    keys=(recipient.pre, applyExn.ked["x"], agreeExn.said))
                assert agreeCache is not None
                assert agreeCache.mdt == agreeStamp
                assert agreeCache.xdt == applyStamp
                assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                agreeMdtMs = helping.fromIso8601(agreeCache.mdt).timestamp() * 1000
                agreeXdtMs = helping.fromIso8601(agreeCache.xdt).timestamp() * 1000
                assert (agreeReceiveMs - d - sl) <= agreeMdtMs <= (agreeReceiveMs + d)
                assert agreeXdtMs <= agreeMdtMs <= (agreeXdtMs + xl)

                clock.advance(milliseconds=500)
                grantStamp = helping.nowIso8601()
                grantExn, grantAtc = ipexGrant(hab=hab,
                                               recp=recipient.pre,
                                               message="Here is the blind registry disclosure",
                                               origin=_proofed(acdc, issuedBlinder),
                                               agree=agreeExn,
                                               dt=grantStamp)
                grantReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                grantIms = bytearray(grantExn.raw)
                grantIms.extend(grantAtc)
                Parser(version=Vrsn_2_0).parse(ims=grantIms, kvy=kvy)
                assert grantIms == bytearray()

                grantStored = hby.db.exns.get(keys=(grantExn.said,))
                assert grantStored is not None
                assert grantStored.ked["x"] == applyExn.ked["x"]

                grantCache = hby.db.kramTMSC.get(
                    keys=(hab.pre, applyExn.ked["x"], grantExn.said))
                assert grantCache is not None
                assert grantCache.mdt == grantStamp
                assert grantCache.xdt == applyStamp
                assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                grantMdtMs = helping.fromIso8601(grantCache.mdt).timestamp() * 1000
                grantXdtMs = helping.fromIso8601(grantCache.xdt).timestamp() * 1000
                assert (grantReceiveMs - d - sl) <= grantMdtMs <= (grantReceiveMs + d)
                assert grantXdtMs <= grantMdtMs <= (grantXdtMs + xl)

                clock.advance(milliseconds=d)
                admitStamp = helping.nowIso8601()
                admitExn, admitAtc = ipexAdmit(hab=recipient,
                                               message="Thanks for the blind credential",
                                               grant=grantExn,
                                               dt=admitStamp)
                admitReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                admitIms = bytearray(admitExn.raw)
                admitIms.extend(admitAtc)
                Parser(version=Vrsn_2_0).parse(ims=admitIms, kvy=kvy)
                assert admitIms == bytearray()

                admitStored = hby.db.exns.get(keys=(admitExn.said,))
                assert admitStored is not None
                assert admitStored.ked["x"] == applyExn.ked["x"]

                admitCache = hby.db.kramTMSC.get(
                    keys=(recipient.pre, applyExn.ked["x"], admitExn.said))
                assert admitCache is not None
                assert admitCache.mdt == admitStamp
                assert admitCache.xdt == applyStamp
                assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                admitMdtMs = helping.fromIso8601(admitCache.mdt).timestamp() * 1000
                admitXdtMs = helping.fromIso8601(admitCache.xdt).timestamp() * 1000
                assert (admitReceiveMs - d - sl) <= admitMdtMs <= (admitReceiveMs + d)
                assert admitXdtMs <= admitMdtMs <= (admitXdtMs + xl)

                # Re-serialize the stored grant and confirm the exact nested
                # ACDC survives the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [acdc.said]
                assert len(grantResults[0].nests[0].bsqs) == 1
                proof = grantResults[0].nests[0].bsqs[0]
                assert proof[0].qb64 == issuedBlinder.said
                assert proof[1].nonce == issuedBlinder.uuid
                assert proof[2].nonce == acdc.said
                assert proof[3].text == "issued"
                unblinder = Blinder.unblind(said=proof[0].qb64,
                                            uuid=proof[1].nonce,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"

                # Recorder order proves the whole accepted chain actually reached
                # the IPEX handlers after KRAM let each message through.
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                    ("/exn/ipex/offer", "Here is the blind credential"),
                    ("/exn/ipex/agree", "I agree to the blind credential"),
                    ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                    ("/exn/ipex/admit", "Thanks for the blind credential"),
                ]

                # The stale offer is never persisted, while the retry is, proving
                # the exchange recovered by accepting the second transmission.
                assert hby.db.exns.get(keys=(staleOfferExn.said,)) is None
                assert hby.db.exns.get(keys=(offerExn.said,)) is not None

                # The fake clock now sits at the admit timestamp because each
                # message took its own dt from the current "now" just before build.
                assert helping.nowIso8601() == admitStamp

                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                    ("/exn/ipex/offer", "Here is the blind credential"),
                    ("/exn/ipex/agree", "I agree to the blind credential"),
                    ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                    ("/exn/ipex/admit", "Thanks for the blind credential"),
                ]
        finally:
            rgy.close()


def test_ipex_v2_blind_registry_update_roundtrip_through_kram_two_haberies(fakeHelpingClock):
    """Route the blind-registry IPEX flow through KRAM with distinct Haberys."""
    clock = fakeHelpingClock

    # Keep the KRAM cache timings local to this test so every timeliness and
    # exchange-lifetime assertion below reads against one explicit policy.
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }
    # Start the fake clock at one known instant before the flow begins.
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # Unpack the windows used by the KRAM assertions:
    # d  = allowed clock drift
    # sl = short-lag timeliness window for single-key / current-est auth
    # xl = total exchange lifetime measured from xdt
    d = kramConfig["kram"]["caches"]["~"][0]
    sl = kramConfig["kram"]["caches"]["~"][1]
    xl = kramConfig["kram"]["caches"]["~"][3]

    with (openHby(name="ipex-v2-blind-registry-kram-issuer",
                  base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="ipex-v2-blind-registry-kram-recipient",
                  base="test",
                  version=Vrsn_2_0) as recipientHby):
        issuerHab = issuerHby.makeHab(name="issuer")
        recipientHab = recipientHby.makeHab(name="recipient")
        issuerRgy = Regery(hby=issuerHby,
                           name="ipex-v2-blind-registry-kram-two-haberies-issuer",
                           temp=True)
        recipientRgy = Regery(hby=recipientHby,
                              name="ipex-v2-blind-registry-kram-two-haberies-recipient",
                              temp=True)
        try:
            # Build the issuer-owned registry inside the issuer's Habery.
            registrar = Registrar(rgy=issuerRgy)
            registry = registrar.makeRegistry(name="blind-kram", prefix=issuerHab.pre)
            rip = issuerRgy.store.event(registry.regk)
            ripAnc = _anchor(issuerHab, registry, rip, framed=True)

            # Issue one credential from the issuer to the recipient so the later
            # grant can disclose a real ACDC plus real registry artifacts.
            acdc = acdcmap(israid=issuerHab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=recipientHab.pre)
            schema = acdc.sad["s"]["$id"]

            # Commit one blindable issuance-state update and capture the KEL
            # event that anchors it so the grant can carry the full package.
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            issuedAnc = _anchor(issuerHab, registry, issued, framed=False)

            # Rotate after the TEL anchors so the later IPEX exchanges sign
            # against a fresh establishment event KRAM can authenticate.
            issuerRot = issuerHab.rotate(framed=True,
                                         version=Vrsn_2_0,
                                         kind=issuerHab.kever.serder.kind,
                                         gvrsn=Vrsn_2_0)


            recipientRemoteKvy = Kevery(db=recipientHby.db, lax=False, local=False)
            issuerRemoteKvy = Kevery(db=issuerHby.db, lax=False, local=False)

            # Feed the recipient's inception into the issuer's local db so the
            # issuer can authenticate the opener that arrives from the recipient.
            recipientIcp = recipientHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(recipientIcp), kvy=issuerRemoteKvy)

            # Feed the issuer's KEL and TEL anchor material into the recipient's
            # local db so the recipient can authenticate the issuer's replies and
            # verify the registry artifacts referenced by the later grant.
            issuerIcp = issuerHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerIcp), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(ripAnc), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuedAnc),
                                           framed=False,
                                           kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerRot), kvy=recipientRemoteKvy)

            # Simulate observer retrieval by preloading the issuer's TEL chain
            # into the recipient's local Regery before the grant is verified.
            recipientRgy.store.accept(registry.regk, 0, rip)
            recipientRgy.store.accept(registry.regk, 1, issued)
            assert recipientRgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert recipientRgy.store.seqEvent(registry.regk, 1).said == issued.said

            # Give each Habery its own IPEX exchanger and recorder so the test
            # can prove which side actually received which messages.
            issuerRecorder = Recorder()
            issuerExc = Exchanger(hby=issuerHby, handlers=[])
            loadHandlers(hby=issuerHby, exc=issuerExc, notifier=issuerRecorder, rgy=issuerRgy)

            recipientRecorder = Recorder()
            recipientExc = Exchanger(hby=recipientHby, handlers=[])
            loadHandlers(hby=recipientHby, exc=recipientExc, notifier=recipientRecorder, rgy=recipientRgy)

            with (openCF(name="ipex-v2-kram-two-haberies-issuer", base="test", temp=True) as issuerCf,
                  openCF(name="ipex-v2-kram-two-haberies-recipient", base="test", temp=True) as recipientCf):
                issuerCf.put(kramConfig)
                recipientCf.put(kramConfig)
                # These "self" exchangers let each sender parse a local copy of
                # its own outbound message first. That seeds local prior-message
                # state and xdt tracking so a later counterparty reply can be
                # verified inside a separate Habery.
                issuerSelfExc = Exchanger(hby=issuerHby, handlers=[])
                recipientSelfExc = Exchanger(hby=recipientHby, handlers=[])
                issuerSelfKvy = Kevery(db=issuerHby.db,
                                       lax=False,
                                       local=False,
                                       kramer=Kramer(db=issuerHby.db, cf=issuerCf),
                                       exc=issuerSelfExc)
                recipientSelfKvy = Kevery(db=recipientHby.db,
                                          lax=False,
                                          local=False,
                                          kramer=Kramer(db=recipientHby.db, cf=recipientCf),
                                          exc=recipientSelfExc)
                issuerKvy = Kevery(db=issuerHby.db,
                                   lax=False,
                                   local=False,
                                   kramer=Kramer(db=issuerHby.db, cf=issuerCf),
                                   exc=issuerExc)
                recipientKvy = Kevery(db=recipientHby.db,
                                      lax=False,
                                      local=False,
                                      kramer=Kramer(db=recipientHby.db, cf=recipientCf),
                                      exc=recipientExc)
                assert issuerKvy.kramer.enabled is True
                assert recipientKvy.kramer.enabled is True

                # Drive each message timestamp from the fake clock directly. The
                # clock starts at the apply, advances to create one stale offer,
                # then continues forward as each accepted message is built.
                applyStamp = helping.nowIso8601()
                applyExn, applyAtc = ipexApply(hab=recipientHab,
                                               recp=issuerHab.pre,
                                               message="Please issue the blind credential",
                                               attrs={},
                                               modifiers=dict(dp=[[[schema, "/", []]]]),
                                               dt=applyStamp)
                applyReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # Parse the apply locally on the sender side first so the
                # recipient Habery records its own opener before any reply comes
                # back from the issuer.
                applyMsg = bytearray(applyExn.raw)
                applyMsg.extend(applyAtc)

                ims = bytearray(applyMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientSelfKvy)
                assert ims == bytearray()

                # Deliver the apply to the issuer side. This is the first real
                # cross-Habery inbound step in the exchange.
                ims = bytearray(applyMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerKvy)

                assert ims == bytearray()

                # The issuer must persist the inbound apply and keep the opener's
                # xid intact because later replies will inherit this xdt.
                applyStored, _ = cloneMessage(issuerHby, applyExn.said)
                assert applyStored is not None
                assert applyStored.ked["x"] == applyExn.ked["x"]

                # On the receiver side of the apply, KRAM should store both the
                # per-message cache row and the thread-wide opener time.
                applyCache = issuerHby.db.kramTMSC.get(
                    keys=(recipientHab.pre, applyExn.ked["x"], applyExn.said))
                assert applyCache is not None
                assert applyCache.mdt == applyStamp
                assert applyCache.xdt == applyStamp
                assert issuerHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                # The sender-side self-parse should also have seeded the same xid
                # opener time locally for future inbound replies.
                assert recipientHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                # Confirm the accepted apply sits inside both the receiver's
                # timeliness window and the thread's exchange-lifetime window.
                applyMdtMs = helping.fromIso8601(applyCache.mdt).timestamp() * 1000
                applyXdtMs = helping.fromIso8601(applyCache.xdt).timestamp() * 1000
                assert (applyReceiveMs - d - sl) <= applyMdtMs <= (applyReceiveMs + d)
                assert applyXdtMs <= applyMdtMs <= (applyXdtMs + xl)

                # Move forward, build the stale offer, then advance past
                # the lower timeliness bound before attempting delivery.
                clock.advance(milliseconds=1)
                staleOfferStamp = helping.nowIso8601()
                staleOfferExn, staleOfferAtc = ipexOffer(hab=issuerHab,
                                                         message="Here is the blind credential",
                                                         origin=acdc,
                                                         apply=applyExn,
                                                         dt=staleOfferStamp)
                clock.advance(milliseconds=d + sl + 1)
                staleOfferReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # The stale offer must still target the same transaction, but its
                # mdt should sit just below the lower timeliness bound.
                assert staleOfferExn.ked["x"] == applyExn.ked["x"]
                staleOfferMs = helping.fromIso8601(staleOfferStamp).timestamp() * 1000
                assert staleOfferMs < (staleOfferReceiveMs - d - sl)

                # Now deliver the stale offer to the recipient. KRAM should drop
                # it before the exchanger records or dispatches it.
                staleOfferMsg = bytearray(staleOfferExn.raw)
                staleOfferMsg.extend(staleOfferAtc)
                ims = bytearray(staleOfferMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)

                assert ims == bytearray()
                assert recipientHby.db.kramTMSC.get(
                    keys=(issuerHab.pre, applyExn.ked["x"], staleOfferExn.said)) is None
                assert recipientHby.db.exns.get(keys=(staleOfferExn.said,)) is None
                assert [(item["r"], item["m"]) for item in issuerRecorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                ]
                assert recipientRecorder.items == []

                # Resend the same logical offer from the current fake-clock time.
                clock.advance(milliseconds=1)
                offerRetryStamp = helping.nowIso8601()
                offerExn, offerAtc = ipexOffer(hab=issuerHab,
                                               message="Here is the blind credential",
                                               origin=acdc,
                                               apply=applyExn,
                                               dt=offerRetryStamp)
                offerReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # Parse the fresh offer locally on the issuer side so the issuer
                # Habery retains its own sent message as prior state.
                offerMsg = bytearray(offerExn.raw)
                offerMsg.extend(offerAtc)

                ims = bytearray(offerMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerSelfKvy)
                assert ims == bytearray()
                ims = bytearray(offerMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()

                # The recipient must store the accepted offer because the later
                # agree builder replies to this local prior message.
                storedOffer, _ = cloneMessage(recipientHby, offerExn.said)
                assert storedOffer is not None
                assert storedOffer.ked["x"] == applyExn.ked["x"]

                # Even though this is not the opener, KRAM must keep the offer's
                # own mdt while still inheriting the original apply xdt.
                offerCache = recipientHby.db.kramTMSC.get(
                    keys=(issuerHab.pre, applyExn.ked["x"], offerExn.said))
                assert offerCache is not None
                assert offerCache.mdt == offerRetryStamp
                assert offerCache.xdt == applyStamp
                assert recipientHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                # The recovered offer should now satisfy the same two KRAM
                # windows the stale one missed.
                offerMdtMs = helping.fromIso8601(offerCache.mdt).timestamp() * 1000
                offerXdtMs = helping.fromIso8601(offerCache.xdt).timestamp() * 1000
                assert (offerReceiveMs - d - sl) <= offerMdtMs <= (offerReceiveMs + d)
                assert offerXdtMs <= offerMdtMs <= (offerXdtMs + xl)

                # The recipient answers the accepted offer with an agree.
                clock.advance(milliseconds=1)
                agreeStamp = helping.nowIso8601()
                agreeExn, agreeAtc = ipexAgree(hab=recipientHab,
                                               message="I agree to the blind credential",
                                               offer=storedOffer,
                                               dt=agreeStamp)
                agreeReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # Self-parse again so the sender Habery can later verify inbound
                # replies against its own locally stored prior message.
                agreeMsg = bytearray(agreeExn.raw)
                agreeMsg.extend(agreeAtc)

                ims = bytearray(agreeMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientSelfKvy)
                assert ims == bytearray()
                ims = bytearray(agreeMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerKvy)
                assert ims == bytearray()

                storedAgree, _ = cloneMessage(issuerHby, agreeExn.said)
                assert storedAgree is not None
                assert storedAgree.ked["x"] == applyExn.ked["x"]

                # The reply keeps the same opener xdt even though its own mdt is
                # later in the exchange.
                agreeCache = issuerHby.db.kramTMSC.get(
                    keys=(recipientHab.pre, applyExn.ked["x"], agreeExn.said))
                assert agreeCache is not None
                assert agreeCache.mdt == agreeStamp
                assert agreeCache.xdt == applyStamp
                assert issuerHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                agreeMdtMs = helping.fromIso8601(agreeCache.mdt).timestamp() * 1000
                agreeXdtMs = helping.fromIso8601(agreeCache.xdt).timestamp() * 1000
                assert (agreeReceiveMs - d - sl) <= agreeMdtMs <= (agreeReceiveMs + d)
                assert agreeXdtMs <= agreeMdtMs <= (agreeXdtMs + xl)

                # The issuer now grants the disclosed credential node.
                clock.advance(milliseconds=500)
                grantStamp = helping.nowIso8601()
                grantExn, grantAtc = ipexGrant(hab=issuerHab,
                                               recp=recipientHab.pre,
                                               message="Here is the blind registry disclosure",
                                               origin=_proofed(acdc, issuedBlinder),
                                               agree=storedAgree,
                                               dt=grantStamp)
                grantReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000
                # Persist the outbound grant locally on the issuer side before
                # sending it across so the issuer still has its own prior chain.
                grantExnMsg = bytearray(grantExn.raw)
                grantExnMsg.extend(grantAtc)

                ims = bytearray(grantExnMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerSelfKvy)
                assert ims == bytearray()
                ims = bytearray(grantExnMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()

                # The recipient stores this grant locally so the final admit can
                # be built as a real reply to the accepted inbound message.
                storedGrant, _ = cloneMessage(recipientHby, grantExn.said)
                assert storedGrant is not None
                assert storedGrant.ked["x"] == applyExn.ked["x"]

                grantCache = recipientHby.db.kramTMSC.get(
                    keys=(issuerHab.pre, applyExn.ked["x"], grantExn.said))
                assert grantCache is not None
                assert grantCache.mdt == grantStamp
                assert grantCache.xdt == applyStamp
                assert recipientHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                grantMdtMs = helping.fromIso8601(grantCache.mdt).timestamp() * 1000
                grantXdtMs = helping.fromIso8601(grantCache.xdt).timestamp() * 1000
                assert (grantReceiveMs - d - sl) <= grantMdtMs <= (grantReceiveMs + d)
                assert grantXdtMs <= grantMdtMs <= (grantXdtMs + xl)

                # Close the thread with the recipient's admit.
                clock.advance(milliseconds=d)
                admitStamp = helping.nowIso8601()
                admitExn, admitAtc = ipexAdmit(hab=recipientHab,
                                               message="Thanks for the blind credential",
                                               grant=storedGrant,
                                               dt=admitStamp)
                admitReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000
                admitMsg = bytearray(admitExn.raw)
                admitMsg.extend(admitAtc)
                ims = bytearray(admitMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerKvy)
                assert ims == bytearray()

                # The issuer must store the inbound admit and keep the xid
                # consistent with the opener that started the transaction.
                storedAdmit, _ = cloneMessage(issuerHby, admitExn.said)
                assert storedAdmit is not None
                assert storedAdmit.ked["x"] == applyExn.ked["x"]

                admitCache = issuerHby.db.kramTMSC.get(
                    keys=(recipientHab.pre, applyExn.ked["x"], admitExn.said))
                assert admitCache is not None
                assert admitCache.mdt == admitStamp
                assert admitCache.xdt == applyStamp
                assert issuerHby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                admitMdtMs = helping.fromIso8601(admitCache.mdt).timestamp() * 1000
                admitXdtMs = helping.fromIso8601(admitCache.xdt).timestamp() * 1000
                assert (admitReceiveMs - d - sl) <= admitMdtMs <= (admitReceiveMs + d)
                assert admitXdtMs <= admitMdtMs <= (admitXdtMs + xl)

                # Re-serialize the stored grant from the recipient side to prove
                # the nested ACDC survived the full cross-Habery KRAM plus
                # exchanger path unchanged.
                grantMsg = serializeMessage(recipientHby, grantExn.said, framed=True)
                grantWire = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantWire,
                                                              framed=False,
                                                              processive=False)
                assert grantWire == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [acdc.said]
                assert len(grantResults[0].nests[0].bsqs) == 1

                # Recorder contents should show the issuer only saw the
                # recipient-originated messages, and the recipient only saw the
                # issuer-originated ones.
                assert [(item["r"], item["m"]) for item in issuerRecorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                    ("/exn/ipex/agree", "I agree to the blind credential"),
                    ("/exn/ipex/admit", "Thanks for the blind credential"),
                ]
                assert [(item["r"], item["m"]) for item in recipientRecorder.items] == [
                    ("/exn/ipex/offer", "Here is the blind credential"),
                    ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                ]

                # Recovery here means the stale offer never landed, the retry did
                # land, and the fake clock advanced cleanly from apply to admit.
                assert helping.nowIso8601() == admitStamp
                assert recipientHby.db.exns.get(keys=(staleOfferExn.said,)) is None
                assert recipientHby.db.exns.get(keys=(offerExn.said,)) is not None
        finally:
            recipientRgy.close()
            issuerRgy.close()


def test_ipex_v2_two_node_registry_dag_roundtrip_through_kram_two_haberies(fakeHelpingClock):
    """Run the full IPEX flow for a two-node DAG with node-local issuer-auth."""
    clock = fakeHelpingClock

    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    with (openHby(name="ipex-v2-dag-kram-issuer",
                  base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="ipex-v2-dag-kram-recipient",
                  base="test",
                  version=Vrsn_2_0) as recipientHby):
        issuerHab = issuerHby.makeHab(name="issuer")
        recipientHab = recipientHby.makeHab(name="recipient")
        issuerRgy = Regery(hby=issuerHby,
                           name="ipex-v2-dag-kram-two-haberies-issuer",
                           temp=True)
        recipientRgy = Regery(hby=recipientHby,
                              name="ipex-v2-dag-kram-two-haberies-recipient",
                              temp=True)
        try:
            # Build the issuer-owned registry and anchor its inception so the
            # recipient can later vet the origin node's blind proof group.
            registrar = Registrar(rgy=issuerRgy)
            registry = registrar.makeRegistry(name="blind-dag-kram", prefix=issuerHab.pre)
            rip = issuerRgy.store.event(registry.regk)
            ripAnc = _anchor(issuerHab, registry, rip, framed=True)

            # The disclosed DAG has a registry-backed origin node that points to
            # one child node.
            child = acdcmap(israid=issuerHab.pre,
                            attribute=dict(d="", role="member"),
                            iseaid=recipientHab.pre)
            origin = acdcmap(israid=issuerHab.pre,
                             regid=registry.regk,
                             attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                             edge=_edge("holder", child),
                             iseaid=recipientHab.pre)
            schema = origin.sad["s"]["$id"]

            issuedBlinder, issued = registrar.issue(registry, acdc=origin, state="issued")
            issuedAnc = _anchor(issuerHab, registry, issued, framed=False)

            # Rotate after the TEL anchors so the later transferable IPEX
            # messages sign against a fresh establishment event.
            issuerRot = issuerHab.rotate(framed=True,
                                         version=Vrsn_2_0,
                                         kind=issuerHab.kever.serder.kind,
                                         gvrsn=Vrsn_2_0)

            recipientRemoteKvy = Kevery(db=recipientHby.db, lax=False, local=False)
            issuerRemoteKvy = Kevery(db=issuerHby.db, lax=False, local=False)

            # Preload each side with the other side's evidence it will need to
            # authenticate the later cross-Habery exchanges.
            recipientIcp = recipientHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(recipientIcp), kvy=issuerRemoteKvy)

            issuerIcp = issuerHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerIcp), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(ripAnc), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuedAnc),
                                           framed=False,
                                           kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerRot), kvy=recipientRemoteKvy)

            # Simulate observer retrieval by preloading the issuer's TEL chain
            # into the recipient's local Regery before the grant is verified.
            recipientRgy.store.accept(registry.regk, 0, rip)
            recipientRgy.store.accept(registry.regk, 1, issued)
            assert recipientRgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert recipientRgy.store.seqEvent(registry.regk, 1).said == issued.said


            # Set up each Habery with its IPEX exchanger and recorder
            issuerRecorder = Recorder()
            issuerInboundExc = Exchanger(hby=issuerHby, handlers=[])
            loadHandlers(hby=issuerHby,
                         exc=issuerInboundExc,
                         notifier=issuerRecorder,
                         rgy=issuerRgy)

            recipientRecorder = Recorder()
            recipientInboundExc = Exchanger(hby=recipientHby, handlers=[])
            loadHandlers(hby=recipientHby,
                         exc=recipientInboundExc,
                         notifier=recipientRecorder,
                         rgy=recipientRgy)

            with (openCF(name="ipex-v2-dag-kram-issuer", base="test", temp=True) as issuerCf,
                  openCF(name="ipex-v2-dag-kram-recipient", base="test", temp=True) as recipientCf):
                issuerCf.put(kramConfig)
                recipientCf.put(kramConfig)

                # Set up local-send ingest for each Habery so each side can
                # parse its own outbound messages first without treating them
                # as true inbound IPEX events.
                issuerLocalSendExc = Exchanger(hby=issuerHby, handlers=[])
                recipientLocalSendExc = Exchanger(hby=recipientHby, handlers=[])
                issuerLocalSendKvy = Kevery(db=issuerHby.db,
                                            lax=False,
                                            local=False,
                                            kramer=Kramer(db=issuerHby.db, cf=issuerCf),
                                            exc=issuerLocalSendExc)
                recipientLocalSendKvy = Kevery(db=recipientHby.db,
                                               lax=False,
                                               local=False,
                                               kramer=Kramer(db=recipientHby.db, cf=recipientCf),
                                               exc=recipientLocalSendExc)
                issuerInboundKvy = Kevery(db=issuerHby.db,
                                          lax=False,
                                          local=False,
                                          kramer=Kramer(db=issuerHby.db, cf=issuerCf),
                                          exc=issuerInboundExc)
                recipientInboundKvy = Kevery(db=recipientHby.db,
                                             lax=False,
                                             local=False,
                                             kramer=Kramer(db=recipientHby.db, cf=recipientCf),
                                             exc=recipientInboundExc)

                # The recipient opens the thread with one disclose-path list
                # whose entries describe the one disclosed DAG.
                applyStamp = helping.nowIso8601()
                applyExn, applyAtc = ipexApply(hab=recipientHab,
                                               recp=issuerHab.pre,
                                               message="Please issue the DAG credential",
                                               attrs={},
                                               modifiers=dict(dp=[[
                                                   [schema, "/", []],
                                                   [schema, "/e/holder", []],
                                               ]]),
                                               dt=applyStamp)
                
                assert applyExn.ked["q"]["dp"] == [[
                    [schema, "/", []],
                    [schema, "/e/holder", []],
                ]]

                applyMsg = bytearray(applyExn.raw)
                applyMsg.extend(applyAtc)

                # Feed the apply to the recipient self-ingest pipeline and issuer's real inbound
                localIms = bytearray(applyMsg)
                Parser(version=Vrsn_2_0).parse(ims=localIms, kvy=recipientLocalSendKvy)
                assert localIms == bytearray()
                inboundIms = bytearray(applyMsg)
                Parser(version=Vrsn_2_0).parse(ims=inboundIms, kvy=issuerInboundKvy)
                assert inboundIms == bytearray()

                applyStored, _ = cloneMessage(issuerHby, applyExn.said)
                assert applyStored is not None
                assert applyStored.ked["x"] == applyExn.ked["x"]

                # The issuer answers with metadata only. Offer names the origin
                # SAID but does not yet disclose any ACDC node bodies.
                clock.advance(milliseconds=1)
                offerStamp = helping.nowIso8601()
                offerExn, offerAtc = ipexOffer(hab=issuerHab,
                                               message="Here is the credential DAG",
                                               origin=origin,
                                               apply=applyExn,
                                               dt=offerStamp)
                assert offerExn.ked["a"]["o"] == [origin.said]

                offerMsg = bytearray(offerExn.raw)
                offerMsg.extend(offerAtc)

                localIms = bytearray(offerMsg)
                Parser(version=Vrsn_2_0).parse(ims=localIms, kvy=issuerLocalSendKvy)
                assert localIms == bytearray()
                inboundIms = bytearray(offerMsg)
                Parser(version=Vrsn_2_0).parse(ims=inboundIms, kvy=recipientInboundKvy)
                assert inboundIms == bytearray()

                storedOffer, _ = cloneMessage(recipientHby, offerExn.said)
                assert storedOffer is not None
                assert storedOffer.ked["x"] == applyExn.ked["x"]

                offerWire = bytearray(serializeMessage(recipientHby, offerExn.said, framed=True))
                offerResults = Parser(version=Vrsn_2_0).parse(ims=offerWire,
                                                              framed=False,
                                                              processive=False)
                
                # Offer remains metadata-only through the full roundtrip.
                assert len(offerResults) == 1

                assert offerResults[0].nests == []

                # The recipient agrees to the proposed disclosure, and the
                # later grant carries the actual DAG nodes.
                clock.advance(milliseconds=1)
                agreeStamp = helping.nowIso8601()
                agreeExn, agreeAtc = ipexAgree(hab=recipientHab,
                                               message="I agree to the DAG credential",
                                               offer=storedOffer,
                                               dt=agreeStamp)

                agreeMsg = bytearray(agreeExn.raw)
                agreeMsg.extend(agreeAtc)

                localIms = bytearray(agreeMsg)
                Parser(version=Vrsn_2_0).parse(ims=localIms, kvy=recipientLocalSendKvy)
                assert localIms == bytearray()
                inboundIms = bytearray(agreeMsg)
                Parser(version=Vrsn_2_0).parse(ims=inboundIms, kvy=issuerInboundKvy)
                assert inboundIms == bytearray()

                storedAgree, _ = cloneMessage(issuerHby, agreeExn.said)
                assert storedAgree is not None
                assert storedAgree.ked["x"] == applyExn.ked["x"]

                # The issuer grants the same two-node DAG, but now the origin
                # node carries the node-local blind proof group that step 4 vets.
                clock.advance(milliseconds=1)
                grantStamp = helping.nowIso8601()
                grantExn, grantAtc = ipexGrant(hab=issuerHab,
                                               recp=recipientHab.pre,
                                               message="Here is the registry-backed DAG disclosure",
                                               origin=_proofed(origin, issuedBlinder),
                                               artifacts=[child],
                                               agree=storedAgree,
                                               dt=grantStamp)
                assert grantExn.ked["a"]["o"] == [origin.said]

                grantMsg = bytearray(grantExn.raw)
                grantMsg.extend(grantAtc)

                localIms = bytearray(grantMsg)
                Parser(version=Vrsn_2_0).parse(ims=localIms, kvy=issuerLocalSendKvy)
                assert localIms == bytearray()
                inboundIms = bytearray(grantMsg)
                Parser(version=Vrsn_2_0).parse(ims=inboundIms, kvy=recipientInboundKvy)
                assert inboundIms == bytearray()

                storedGrant, _ = cloneMessage(recipientHby, grantExn.said)
                assert storedGrant is not None
                assert storedGrant.ked["x"] == applyExn.ked["x"]

                grantWire = bytearray(serializeMessage(recipientHby, grantExn.said, framed=True))
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantWire,
                                                              framed=False,
                                                              processive=False)
                assert grantWire == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [
                    origin.said,
                    child.said,
                ]
                assert len(grantResults[0].nests[0].bsqs) == 1
                proof = grantResults[0].nests[0].bsqs[0]
                assert proof[0].qb64 == issuedBlinder.said
                assert proof[1].nonce == issuedBlinder.uuid
                assert proof[2].nonce == origin.said
                assert proof[3].text == "issued"
                unblinder = Blinder.unblind(said=proof[0].qb64,
                                            uuid=proof[1].nonce,
                                            acdc=origin.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"
                assert len(grantResults[0].nests[1].bsqs) == 0

                # The recipient closes the happy path with admit
                clock.advance(milliseconds=1)
                admitStamp = helping.nowIso8601()
                admitExn, admitAtc = ipexAdmit(hab=recipientHab,
                                               message="Thanks for the DAG credential",
                                               grant=storedGrant,
                                               dt=admitStamp)

                admitMsg = bytearray(admitExn.raw)
                admitMsg.extend(admitAtc)
                ims = bytearray(admitMsg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerInboundKvy)
                assert ims == bytearray()

                storedAdmit, _ = cloneMessage(issuerHby, admitExn.said)
                assert storedAdmit is not None
                assert storedAdmit.ked["x"] == applyExn.ked["x"]

                # A second grant that omits the child nest should now fail the
                # graph walk even though the origin still carries a valid proof.
                clock.advance(milliseconds=1)
                badGrantExn, badGrantAtc = ipexGrant(hab=issuerHab,
                                                     recp=recipientHab.pre,
                                                     message="Here is the incomplete DAG",
                                                     origin=_proofed(origin, issuedBlinder),
                                                     dt=helping.nowIso8601())
                badGrantMsg = bytearray(badGrantExn.raw)
                badGrantMsg.extend(badGrantAtc)
                Parser(version=Vrsn_2_0).parse(ims=badGrantMsg, kvy=recipientInboundKvy)
                assert badGrantMsg == bytearray()
                assert recipientHby.db.exns.get(keys=(badGrantExn.said,)) is None

                assert [(item["r"], item["m"]) for item in issuerRecorder.items] == [
                    ("/exn/ipex/apply", "Please issue the DAG credential"),
                    ("/exn/ipex/agree", "I agree to the DAG credential"),
                    ("/exn/ipex/admit", "Thanks for the DAG credential"),
                ]
                assert [(item["r"], item["m"]) for item in recipientRecorder.items] == [
                    ("/exn/ipex/offer", "Here is the credential DAG"),
                    ("/exn/ipex/grant", "Here is the registry-backed DAG disclosure"),
                ]
        finally:
            recipientRgy.close()
            issuerRgy.close()


def test_ipex_v2_offer_starts_flow_with_xid_through_kram(fakeHelpingClock):
    """An offer-first IPEX flow can start transactionally with a generated xid."""
    # Keep the KRAM cache timings local to this test so the window assertions
    # below read directly against the exact policy in force.
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }
    # Hold receiver-side "now" steady so every KRAM timeliness check below uses
    # one fixed clock reference.
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # Unpack the cache timings we assert against:
    # d  = allowed clock drift
    # sl = short-lag timeliness window for single-key / current-est auth
    # xl = total exchange lifetime measured from xdt
    d = kramConfig["kram"]["caches"]["~"][0]
    sl = kramConfig["kram"]["caches"]["~"][1]
    xl = kramConfig["kram"]["caches"]["~"][3]

    with openHby(name="ipex-v2-offer-start-kram",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        recipient = hby.makeHab(name="recipient")
        rgy = Regery(hby=hby, name="ipex-v2-offer-start-kram", temp=True)
        try:
            # Build a blindable registry and anchor one issued-state update so
            # the later grant can disclose real registry artifacts.
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blind-kram-offer", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Issue one credential to the recipient and capture the anchor event
            # that seals the blind update into the sender's KEL.
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=recipient.pre)
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued, framed=False)

            # After the anchors, rotate so the transferable IPEX messages below
            # sign against a fresh establishment event KRAM can verify.
            hab.rotate(framed=True,
                       version=Vrsn_2_0,
                       kind=hab.kever.serder.kind,
                       gvrsn=Vrsn_2_0)

            # Wire the real IPEX exchanger so accepted messages are both KRAM-
            # authenticated and dispatched through the usual handler path.
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            with openCF(name="ipex-v2-offer-kram", base="test", temp=True) as cf:
                cf.put(kramConfig)
                kvy = Kevery(db=hby.db,
                             lax=False,
                             local=False,
                             kramer=Kramer(db=hby.db, cf=cf),
                             exc=exc)

                # Freeze one receiver-side "now" and pick message datetimes that
                # all stay inside the accepted timeliness window.
                receiveDt = helping.fromIso8601(helping.nowIso8601())
                receiveMs = receiveDt.timestamp() * 1000
                offerStamp = helping.toIso8601(receiveDt - timedelta(milliseconds=2000))
                agreeStamp = helping.toIso8601(receiveDt)
                grantStamp = helping.toIso8601(receiveDt + timedelta(milliseconds=500))
                admitStamp = helping.toIso8601(receiveDt + timedelta(milliseconds=d))

                # Start a real two-party offer-first flow. The issuer opens the
                # thread with the offer, the recipient agrees, the issuer grants,
                # and the recipient admits receipt.
                offerExn, offerAtc = ipexOffer(hab=hab,
                                               message="Offer starts the blind credential flow",
                                               origin=acdc,
                                               recp=recipient.pre,
                                               dt=offerStamp)
                agreeExn, agreeAtc = ipexAgree(hab=recipient,
                                               message="I agree to the offer-first credential",
                                               offer=offerExn,
                                               dt=agreeStamp)
                grantExn, grantAtc = ipexGrant(hab=hab,
                                               recp=recipient.pre,
                                               message="Here is the offer-first blind registry disclosure",
                                               origin=_proofed(acdc, issuedBlinder),
                                               agree=agreeExn,
                                               dt=grantStamp)
                admitExn, admitAtc = ipexAdmit(hab=recipient,
                                               message="Thanks for the offer-first blind credential",
                                               grant=grantExn,
                                               dt=admitStamp)

                # Offer-first means there is no prior message, so the builder
                # generates the xid that anchors the rest of the thread.
                assert offerExn.ked["p"] == ""
                assert offerExn.ked["x"] != ""

                # Every accepted exn in the chain should keep the same xid and
                # land inside both the timeliness and exchange-lifetime windows.
                accepted = (
                    (offerExn, offerAtc, offerStamp),
                    (agreeExn, agreeAtc, agreeStamp),
                    (grantExn, grantAtc, grantStamp),
                    (admitExn, admitAtc, admitStamp),
                )

                for exn, atc, stamp in accepted:
                    ims = bytearray(exn.raw)
                    ims.extend(atc)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                    assert ims == bytearray()

                    # Once KRAM accepts the message, the IPEX exchanger should
                    # persist the exn body and preserve the exchange id.
                    stored = hby.db.exns.get(keys=(exn.said,))
                    assert stored is not None
                    assert stored.ked["x"] == offerExn.ked["x"]

                    # KRAM should also record one transaction-cache row that keeps
                    # the message's own mdt and the original offer xdt.
                    cache = hby.db.kramTMSC.get(
                        keys=(exn.ked["i"], offerExn.ked["x"], exn.said))
                    assert cache is not None
                    assert cache.mdt == stamp
                    assert cache.xdt == offerStamp
                    assert hby.db.kramXDT.get(keys=(offerExn.ked["x"],)).dts == offerStamp

                    mdtMs = helping.fromIso8601(cache.mdt).timestamp() * 1000
                    xdtMs = helping.fromIso8601(cache.xdt).timestamp() * 1000
                    # Each accepted exn must satisfy both KRAM checks:
                    # 1. message time is timely relative to receiver now
                    # 2. message time still lies within the exchange lifetime
                    assert (receiveMs - d - sl) <= mdtMs <= (receiveMs + d)
                    assert xdtMs <= mdtMs <= (xdtMs + xl)

                # Re-serialize the stored grant and confirm the exact nested ACDC
                # survives the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [acdc.said]
                assert len(grantResults[0].nests[0].bsqs) == 1
                proof = grantResults[0].nests[0].bsqs[0]
                assert proof[0].qb64 == issuedBlinder.said
                assert proof[1].nonce == issuedBlinder.uuid
                assert proof[2].nonce == acdc.said
                assert proof[3].text == "issued"
                unblinder = Blinder.unblind(said=proof[0].qb64,
                                            uuid=proof[1].nonce,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"

                # Recorder order proves the whole accepted chain actually reached
                # the IPEX handlers after KRAM let each message through.
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/offer", "Offer starts the blind credential flow"),
                    ("/exn/ipex/agree", "I agree to the offer-first credential"),
                    ("/exn/ipex/grant", "Here is the offer-first blind registry disclosure"),
                    ("/exn/ipex/admit", "Thanks for the offer-first blind credential"),
                ]
        finally:
            rgy.close()


def test_ipex_v2_grant_starts_flow_with_xid_through_kram(fakeHelpingClock):
    """A grant-first IPEX flow can start transactionally with a generated xid."""

    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }
    assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

    # d  = allowed clock drift
    # sl = short-lag timeliness window for single-key / current-est auth
    # xl = total exchange lifetime measured from xdt
    d = kramConfig["kram"]["caches"]["~"][0]
    sl = kramConfig["kram"]["caches"]["~"][1]
    xl = kramConfig["kram"]["caches"]["~"][3]

    with openHby(name="ipex-v2-grant-start-kram",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        recipient = hby.makeHab(name="recipient")
        rgy = Regery(hby=hby, name="ipex-v2-grant-start-kram", temp=True)
        try:
            # Build a blindable registry and anchor one issued-state update
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="blind-kram-grant", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Issue one credential to the recipient and capture the anchor event
            # that seals the blind update into the sender's KEL.
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=recipient.pre)
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued, framed=False)

            # After the anchors, rotate so the transferable IPEX messages below
            # sign against a fresh establishment event KRAM can verify.
            hab.rotate(framed=True,
                       version=Vrsn_2_0,
                       kind=hab.kever.serder.kind,
                       gvrsn=Vrsn_2_0)

            # Wire the real IPEX exchanger so accepted messages are both KRAM-
            # authenticated and dispatched through the usual handler path.
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            with openCF(name="ipex-v2-grant-kram", base="test", temp=True) as cf:
                cf.put(kramConfig)
                kvy = Kevery(db=hby.db,
                             lax=False,
                             local=False,
                             kramer=Kramer(db=hby.db, cf=cf),
                             exc=exc)

                # Freeze one receiver-side "now" and pick message datetimes that
                # both stay inside the accepted timeliness window.
                receiveDt = helping.fromIso8601(helping.nowIso8601())
                receiveMs = receiveDt.timestamp() * 1000
                grantStamp = helping.toIso8601(receiveDt - timedelta(milliseconds=2000))
                admitStamp = helping.toIso8601(receiveDt)

                # Start a real two-party grant-first flow. The issuer opens the
                # thread with the grant and the recipient answers with admit.
                grantExn, grantAtc = ipexGrant(hab=hab,
                                               recp=recipient.pre,
                                               message="Grant starts the blind credential flow",
                                               origin=_proofed(acdc, issuedBlinder),
                                               dt=grantStamp)
                admitExn, admitAtc = ipexAdmit(hab=recipient,
                                               message="Thanks for the grant-first blind credential",
                                               grant=grantExn,
                                               dt=admitStamp)

                # Grant-first means there is no prior message, so the builder
                # generates the xid that anchors the rest of the thread.
                assert grantExn.ked["p"] == ""
                assert grantExn.ked["x"] != ""

                # Every accepted exn in the chain should keep the same xid and
                # land inside both the timeliness and exchange-lifetime windows.
                accepted = (
                    (grantExn, grantAtc, grantStamp),
                    (admitExn, admitAtc, admitStamp),
                )

                for exn, atc, stamp in accepted:
                    ims = bytearray(exn.raw)
                    ims.extend(atc)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                    assert ims == bytearray()

                    # Once KRAM accepts the message, the IPEX exchanger should
                    # persist the exn body and preserve the exchange id.
                    stored = hby.db.exns.get(keys=(exn.said,))
                    assert stored is not None
                    assert stored.ked["x"] == grantExn.ked["x"]

                    # KRAM should also record one transaction-cache row that keeps
                    # the message's own mdt and the original grant xdt.
                    cache = hby.db.kramTMSC.get(
                        keys=(exn.ked["i"], grantExn.ked["x"], exn.said))
                    assert cache is not None
                    assert cache.mdt == stamp
                    assert cache.xdt == grantStamp
                    assert hby.db.kramXDT.get(keys=(grantExn.ked["x"],)).dts == grantStamp

                    mdtMs = helping.fromIso8601(cache.mdt).timestamp() * 1000
                    xdtMs = helping.fromIso8601(cache.xdt).timestamp() * 1000
                    # Each accepted exn must satisfy both KRAM checks:
                    # 1. message time is timely relative to receiver now
                    # 2. message time still lies within the exchange lifetime
                    assert (receiveMs - d - sl) <= mdtMs <= (receiveMs + d)
                    assert xdtMs <= mdtMs <= (xdtMs + xl)

                # Re-serialize the stored grant and confirm the exact nested ACDC
                # survives the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [acdc.said]
                assert len(grantResults[0].nests[0].bsqs) == 1
                proof = grantResults[0].nests[0].bsqs[0]
                assert proof[0].qb64 == issuedBlinder.said
                assert proof[1].nonce == issuedBlinder.uuid
                assert proof[2].nonce == acdc.said
                assert proof[3].text == "issued"
                unblinder = Blinder.unblind(said=proof[0].qb64,
                                            uuid=proof[1].nonce,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"

                # Recorder order proves the whole accepted chain actually reached
                # the IPEX handlers after KRAM let each message through.
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/grant", "Grant starts the blind credential flow"),
                    ("/exn/ipex/admit", "Thanks for the grant-first blind credential"),
                ]
        finally:
            rgy.close()


def test_ipex_v2_successive_blind_registry_updates_roundtrip():
    """Grant both successive blind ``bup`` registry updates through full linear V2 IPEX exchanges."""
    with openHby(name="ipex-v2-successive-blind-registry",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="ipex-v2-successive-blind-registry", temp=True)
        try:
            # Create and anchor one real registry before issuing any blind state updates
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="successive-blind", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Build one ACDC whose rd points at this registry for both successive disclosures
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)
            schema = acdc.sad["s"]["$id"]

            # Commit an issued blind update first and anchor it before any later lifecycle state exists
            issuedBlinder, issued = registrar.issue(registry, acdc=acdc, state="issued")
            _anchor(hab, registry, issued, framed=False)

            assert rgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert rgy.store.seqEvent(registry.regk, 1).said == issued.said
            assert rgy.store.headEvent(registry.regk).said == issued.said
            assert issued.sad["b"] == issuedBlinder.said

            # Wire one exchanger with the V2 IPEX handlers, then disclose the issued update first
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            # First disclose the issued-state credential through one full linear IPEX exchange
            issuedApplyExn, issuedApplyAtc = ipexApply(hab=hab,
                                                       recp=hab.pre,
                                                       message="Please issue the issued blind credential",
                                                       attrs=None,
                                                       modifiers=dict(dp=[[[schema, "/", []]]]))
            issuedOfferExn, issuedOfferAtc = ipexOffer(hab=hab,
                                                       message="Here is the issued blind credential",
                                                       origin=acdc,
                                                       apply=issuedApplyExn)
            issuedAgreeExn, issuedAgreeAtc = ipexAgree(hab=hab,
                                                       message="I agree to the issued blind credential",
                                                       offer=issuedOfferExn)
            issuedGrantExn, issuedGrantAtc = ipexGrant(hab=hab,
                                                       recp=hab.pre,
                                                       message="Here is the issued blind registry disclosure",
                                                       origin=_proofed(acdc, issuedBlinder),
                                                       agree=issuedAgreeExn)
            issuedAdmitExn, issuedAdmitAtc = ipexAdmit(hab=hab,
                                                       message="Thanks for the issued blind credential",
                                                       grant=issuedGrantExn)

            for exn, atc in ((issuedApplyExn, issuedApplyAtc),
                             (issuedOfferExn, issuedOfferAtc),
                             (issuedAgreeExn, issuedAgreeAtc),
                             (issuedGrantExn, issuedGrantAtc),
                             (issuedAdmitExn, issuedAdmitAtc)):
                ims = bytearray(exn.raw)
                ims.extend(atc)
                Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
                assert ims == bytearray()

            for serder in (issuedApplyExn, issuedOfferExn, issuedAgreeExn, issuedGrantExn, issuedAdmitExn):
                assert hby.db.exns.get(keys=(serder.said,)) is not None

            issuedStoredGrant = hby.db.exns.get(keys=(issuedGrantExn.said,))
            assert issuedStoredGrant.ked["p"] == issuedAgreeExn.said
            assert issuedStoredGrant.ked["a"]["o"] == [acdc.said]
            assert "iss" not in issuedStoredGrant.ked["a"]
            assert "anc" not in issuedStoredGrant.ked["a"]

            issuedMsg = serializeMessage(hby, issuedGrantExn.said, framed=True)
            issuedIms = bytearray(issuedMsg)
            issuedResults = Parser(version=Vrsn_2_0).parse(ims=issuedIms,
                                                           framed=False,
                                                           processive=False)
            assert issuedIms == bytearray()
            assert len(issuedResults) == 1
            assert [nest.serder.said for nest in issuedResults[0].nests] == [acdc.said]
            assert len(issuedResults[0].nests[0].bsqs) == 1
            proof = issuedResults[0].nests[0].bsqs[0]
            assert proof[0].qb64 == issuedBlinder.said
            assert proof[1].nonce == issuedBlinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "issued"
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"])
            assert unblinder is not None
            assert unblinder.state == "issued"

            # Commit a revoked blind update that follows the issued state
            revokedBlinder, revoked = registrar.issue(registry, acdc=acdc, state="revoked")
            _anchor(hab, registry, revoked, framed=False)

            # The accepted TEL should now show the full rip -> bup -> bup lifecycle
            assert rgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert rgy.store.seqEvent(registry.regk, 1).said == issued.said
            assert rgy.store.seqEvent(registry.regk, 2).said == revoked.said
            assert rgy.store.headEvent(registry.regk).said == revoked.said
            assert revoked.sad["p"] == issued.said
            assert revoked.sad["b"] == revokedBlinder.said

            # Then disclose the later revoked-state snapshot through its own full linear IPEX exchange
            revokedApplyExn, revokedApplyAtc = ipexApply(hab=hab,
                                                         recp=hab.pre,
                                                         message="Please issue the revoked blind credential",
                                                         attrs=dict(flow="revoked"),
                                                         modifiers=dict(dp=[[[schema, "/", []]]]))
            revokedOfferExn, revokedOfferAtc = ipexOffer(hab=hab,
                                                         message="Here is the revoked blind credential",
                                                         origin=acdc,
                                                         apply=revokedApplyExn)
            revokedAgreeExn, revokedAgreeAtc = ipexAgree(hab=hab,
                                                         message="I agree to the revoked blind credential",
                                                         offer=revokedOfferExn)
            revokedGrantExn, revokedGrantAtc = ipexGrant(hab=hab,
                                                         recp=hab.pre,
                                                         message="Here is the revoked blind registry disclosure",
                                                         origin=_proofed(acdc, revokedBlinder),
                                                         agree=revokedAgreeExn)
            revokedAdmitExn, revokedAdmitAtc = ipexAdmit(hab=hab,
                                                         message="Thanks for the revoked blind credential",
                                                         grant=revokedGrantExn)

            for exn, atc in ((revokedApplyExn, revokedApplyAtc),
                             (revokedOfferExn, revokedOfferAtc),
                             (revokedAgreeExn, revokedAgreeAtc),
                             (revokedGrantExn, revokedGrantAtc),
                             (revokedAdmitExn, revokedAdmitAtc)):
                ims = bytearray(exn.raw)
                ims.extend(atc)
                Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
                assert ims == bytearray()

            for serder in (revokedApplyExn, revokedOfferExn, revokedAgreeExn, revokedGrantExn, revokedAdmitExn):
                assert hby.db.exns.get(keys=(serder.said,)) is not None

            revokedStoredGrant = hby.db.exns.get(keys=(revokedGrantExn.said,))
            assert revokedStoredGrant.ked["p"] == revokedAgreeExn.said
            assert revokedStoredGrant.ked["a"]["o"] == [acdc.said]
            assert "iss" not in revokedStoredGrant.ked["a"]
            assert "anc" not in revokedStoredGrant.ked["a"]

            revokedMsg = serializeMessage(hby, revokedGrantExn.said, framed=True)
            revokedIms = bytearray(revokedMsg)
            revokedResults = Parser(version=Vrsn_2_0).parse(ims=revokedIms,
                                                             framed=False,
                                                             processive=False)
            assert revokedIms == bytearray()
            assert len(revokedResults) == 1
            assert [nest.serder.said for nest in revokedResults[0].nests] == [acdc.said]
            assert len(revokedResults[0].nests[0].bsqs) == 1
            proof = revokedResults[0].nests[0].bsqs[0]
            assert proof[0].qb64 == revokedBlinder.said
            assert proof[1].nonce == revokedBlinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "revoked"
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"])
            assert unblinder is not None
            assert unblinder.state == "revoked"

            # The notifier should reflect both full disclosures in the order they were sent
            assert [(item["r"], item["m"]) for item in recorder.items] == [
                ("/exn/ipex/apply", "Please issue the issued blind credential"),
                ("/exn/ipex/offer", "Here is the issued blind credential"),
                ("/exn/ipex/agree", "I agree to the issued blind credential"),
                ("/exn/ipex/grant", "Here is the issued blind registry disclosure"),
                ("/exn/ipex/admit", "Thanks for the issued blind credential"),
                ("/exn/ipex/apply", "Please issue the revoked blind credential"),
                ("/exn/ipex/offer", "Here is the revoked blind credential"),
                ("/exn/ipex/agree", "I agree to the revoked blind credential"),
                ("/exn/ipex/grant", "Here is the revoked blind registry disclosure"),
                ("/exn/ipex/admit", "Thanks for the revoked blind credential"),
            ]
        finally:
            rgy.close()
