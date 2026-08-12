# -*- encoding: utf-8 -*-
"""
tests.acdc.test_ipexing module

"""
import pytest
from keri import Kinds, Vrsn_2_0
from keri.acdc import (Regery, Registrar, acdcmap, blindate, apply as ipexApply, admit as ipexAdmit,
                       agree as ipexAgree, grant as ipexGrant,
                       loadHandlers, offer as ipexOffer, regcept,
                       spurn as ipexSpurn)
from keri.app import openHby
from keri.core import Blinder, Codens, Counter, GenDex, Parser, Serdery, Texter
from keri.kering import Colds, sniff
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


def _anchor(hab, registry, serder, *, framed=False):
    """Create a KEL interaction event that seals one registry event."""
    seal = dict(i=registry.regk, s=serder.sad["n"], d=serder.said)
    anc = hab.interact(data=[seal], framed=framed, gvrsn=Vrsn_2_0)
    assert registry.anchorMsg(serder.said) is True
    return anc

# Tests
def test_ipex_v2_builders_parse_happypath():
    """Build each V2 IPEX verb and prove the resulting streams parse cleanly."""
    with openHby(name="ipex-v2-builders",
                 base="test",
                 version=Vrsn_2_0) as hby:

        # Create hab
        hab = hby.makeHab(name="test")

        # Build artifacts
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)
        anc = hab.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)
        
        # Extract schema from acdc
        schema = acdc.sad["s"]["$id"]

        # Parse anchor event to get the serder
        ancSerder = _serder(anc)

        # Build apply message
        applyExn, applyAtc = ipexApply(hab=hab,
                                          recp=hab.pre,
                                          message="Please issue a credential",
                                          schema=schema,
                                          attrs=dict(role="member"))

        # Build Offer message chained to apply 
        offerExn, offerAtc = ipexOffer(hab=hab,
                                          message="Here is the offered credential",
                                          acdc=acdc,
                                          apply=applyExn)

        # Build an agree chained to the offer
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                          message="I agree to the offer",
                                          offer=offerExn)

        # Build the grant chained to the agree
        grantExn, grantAtc = ipexGrant(hab=hab,
                                          recp=hab.pre,
                                          message="Here is the granted credential",
                                          acdc=acdc,
                                          iss=_nest(iss),
                                          anc=anc,
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
        assert applyExn.ked["a"]["s"] == schema     # schema
        assert applyExn.ked["a"]["a"] == dict(role="member")
        assert applyExn.ked["a"]["i"] == hab.pre

        assert offerExn.ked["a"]["m"] == "Here is the offered credential"
        assert offerExn.ked["p"] == applyExn.said       # prior
        assert offerExn.ked["a"]["acdc"] == acdc.said

        assert agreeExn.ked["a"]["m"] == "I agree to the offer"
        assert agreeExn.ked["p"] == offerExn.said

        assert grantExn.ked["a"]["m"] == "Here is the granted credential"
        assert grantExn.ked["a"]["i"] == hab.pre
        assert grantExn.ked["a"]["acdc"] == acdc.said
        assert grantExn.ked["a"]["iss"] == iss.said     # issuance
        assert grantExn.ked["a"]["anc"] == ancSerder.said       # anchor
        assert grantExn.ked["p"] == agreeExn.said

        assert admitExn.ked["a"]["m"] == "Thanks for the credential"
        assert admitExn.ked["p"] == grantExn.said

        assert spurnExn.ked["a"]["m"] == "No thanks"
        assert spurnExn.ked["p"] == applyExn.said

        # Parse the full stream for each exchange
        # Apply
        applyIms = bytearray(applyExn.raw)
        applyIms.extend(applyAtc)
        applyResults = Parser(version=Vrsn_2_0).parse(ims=applyIms,
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
        offerResults = Parser(version=Vrsn_2_0).parse(ims=offerIms,
                                                      framed=False,
                                                      processive=False)
        assert offerIms == bytearray()
        assert len(offerResults) == 1
        offerResult = offerResults[0]

        assert offerResult.serder.said == offerExn.said
        assert offerResult.serder.ked["r"] == "/ipex/offer"
        assert offerResult.serder.ked["a"] == offerExn.ked["a"]
        assert offerResult.serder.ked["p"] == applyExn.said
        assert [nest.serder.said for nest in offerResult.nests] == [acdc.said]

        # Agree
        agreeIms = bytearray(agreeExn.raw)
        agreeIms.extend(agreeAtc)
        agreeResults = Parser(version=Vrsn_2_0).parse(ims=agreeIms,
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
        grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        grantResult = grantResults[0]

        assert grantResult.serder.said == grantExn.said
        assert grantResult.serder.ked["r"] == "/ipex/grant"
        assert grantResult.serder.ked["a"] == grantExn.ked["a"]
        assert grantResult.serder.ked["p"] == agreeExn.said
        assert [nest.serder.said for nest in grantResult.nests] == [
            acdc.said,
            iss.said,
            ancSerder.said,
        ]

        # Admit
        admitIms = bytearray(admitExn.raw)
        admitIms.extend(admitAtc)
        admitResults = Parser(version=Vrsn_2_0).parse(ims=admitIms,
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
        spurnResults = Parser(version=Vrsn_2_0).parse(ims=spurnIms,
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


def test_ipex_v2_dispatch_linear_and_spurn():
    """Exercise linear routing, rejection, and spurn handling through Exchanger."""
    with openHby(name="ipex-v2-dispatch",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)
        anc = hab.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)
        schema = acdc.sad["s"]["$id"]

        # Create recorder
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Build a happy path chain: apply -> offer -> agree -> grant -> admit
        apply0, apply0Atc = ipexApply(hab=hab,
                                        recp=hab.pre,
                                        message="Please issue a credential",
                                        schema=schema,
                                        attrs=dict(role="member"))
        offer0, offer0Atc = ipexOffer(hab=hab,
                                        message="Here is the offered credential",
                                        acdc=acdc,
                                        apply=apply0)
        agree0, agree0Atc = ipexAgree(hab=hab,
                                        message="I agree to the offer",
                                        offer=offer0)
        grant0, grant0Atc = ipexGrant(hab=hab,
                                        recp=hab.pre,
                                        message="Here is the granted credential",
                                        acdc=acdc,
                                        iss=iss,
                                        anc=anc,
                                        agree=agree0)
        admit0, admit0Atc = ipexAdmit(hab=hab,
                                        message="Thanks for the credential",
                                        grant=grant0)

        # Try to parse the offer before apply
        offer0Ims = bytearray(offer0.raw)
        offer0Ims.extend(offer0Atc)
        Parser(version=Vrsn_2_0).parse(ims=offer0Ims, framed=False, exc=exc)
        assert offer0Ims == bytearray()
        
        # Assert it was rejected and not stored in db since its prior was not accepted yet
        assert hby.db.exns.get(keys=(offer0.said,)) is None

        # Parse the apply first 
        apply0Ims = bytearray(apply0.raw)
        apply0Ims.extend(apply0Atc)
        Parser(version=Vrsn_2_0).parse(ims=apply0Ims, framed=False, exc=exc)
        assert apply0Ims == bytearray()

        # Assert that the apply was accepted and stored
        storedApply = hby.db.exns.get(keys=(apply0.said,))
        assert storedApply is not None
        assert storedApply.ked["a"]["m"] == "Please issue a credential"
        assert storedApply.ked["a"]["a"] == dict(role="member")
        assert storedApply.ked["a"]["i"] == hab.pre

        # Parse the rest of the chain
        offer0Ims = bytearray(offer0.raw)
        offer0Ims.extend(offer0Atc)
        Parser(version=Vrsn_2_0).parse(ims=offer0Ims, framed=False, exc=exc)
        assert offer0Ims == bytearray()

        agree0Ims = bytearray(agree0.raw)
        agree0Ims.extend(agree0Atc)
        Parser(version=Vrsn_2_0).parse(ims=agree0Ims, framed=False, exc=exc)
        assert agree0Ims == bytearray()

        grant0Ims = bytearray(grant0.raw)
        grant0Ims.extend(grant0Atc)
        Parser(version=Vrsn_2_0).parse(ims=grant0Ims, framed=False, exc=exc)
        assert grant0Ims == bytearray()

        admit0Ims = bytearray(admit0.raw)
        admit0Ims.extend(admit0Atc)
        Parser(version=Vrsn_2_0).parse(ims=admit0Ims, framed=False, exc=exc)
        assert admit0Ims == bytearray()

        # Assert that they were accepted and stored
        for serder in (offer0, agree0, grant0, admit0):
            assert hby.db.exns.get(keys=(serder.said,)) is not None

        storedOffer = hby.db.exns.get(keys=(offer0.said,))
        assert storedOffer.ked["a"]["m"] == "Here is the offered credential"
        assert storedOffer.ked["a"]["acdc"] == acdc.said
        assert storedOffer.ked["p"] == apply0.said

        storedAgree = hby.db.exns.get(keys=(agree0.said,))
        assert storedAgree.ked["a"]["m"] == "I agree to the offer"
        assert storedAgree.ked["p"] == offer0.said

        storedGrant = hby.db.exns.get(keys=(grant0.said,))
        assert storedGrant.ked["a"]["m"] == "Here is the granted credential"
        assert storedGrant.ked["a"]["i"] == hab.pre
        assert storedGrant.ked["a"]["acdc"] == acdc.said
        assert storedGrant.ked["a"]["iss"] == iss.said
        assert storedGrant.ked["a"]["anc"] == _serder(anc).said
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
        Parser(version=Vrsn_2_0).parse(ims=dupSpurnIms, framed=False, exc=exc)
        assert dupSpurnIms == bytearray()

        # Assert it was not accepted 
        assert hby.db.exns.get(keys=(dupSpurn.said,)) is None

        # Build a bare grant
        grant1, grant1Atc = ipexGrant(hab=hab,
                                        recp=hab.pre,
                                        message="Bare grant without agreement",
                                        acdc=acdc,
                                        iss=_nest(iss))

        # Build a spurn against that grant
        spurn1, spurn1Atc = ipexSpurn(hab=hab,
                                        message="Grant spurn should be rejected",
                                        spurned=grant1)

        # Parse both
        grant1Ims = bytearray(grant1.raw)
        grant1Ims.extend(grant1Atc)
        Parser(version=Vrsn_2_0).parse(ims=grant1Ims, framed=False, exc=exc)
        assert grant1Ims == bytearray()

        spurn1Ims = bytearray(spurn1.raw)
        spurn1Ims.extend(spurn1Atc)
        Parser(version=Vrsn_2_0).parse(ims=spurn1Ims, framed=False, exc=exc)
        assert spurn1Ims == bytearray()

        # Assert that bare grant is valid but spurn against grant is not
        assert hby.db.exns.get(keys=(grant1.said,)) is not None
        assert hby.db.exns.get(keys=(spurn1.said,)) is None

        # Build a bare offer and a valid spurn against that offer
        offer1, offer1Atc = ipexOffer(hab=hab,
                                      message="Bare offer for spurn path",
                                      acdc=acdc)
        spurn2, spurn2Atc = ipexSpurn(hab=hab,
                                      message="I reject this offer",
                                      spurned=offer1)

        offer1Ims = bytearray(offer1.raw)
        offer1Ims.extend(offer1Atc)
        Parser(version=Vrsn_2_0).parse(ims=offer1Ims, framed=False, exc=exc)
        assert offer1Ims == bytearray()

        spurn2Ims = bytearray(spurn2.raw)
        spurn2Ims.extend(spurn2Atc)
        Parser(version=Vrsn_2_0).parse(ims=spurn2Ims, framed=False, exc=exc)
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
            ("/exn/ipex/offer", "Bare offer for spurn path"),
            ("/exn/ipex/spurn", "I reject this offer"),
        ]


def test_ipex_v2_nontransferable_nested_artifacts():
    """Exercise the cigar signing path with nested IPEX artifacts."""
    
    # Set up non-transferable hab, recorder, exchanger and load IPEX handlers
    with openHby(name="ipex-v2-nontrans",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test", transferable=False)
        assert not hab.kever.prefixer.transferable
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Registry Inception
        registry = regcept(israid=hab.pre)

        # Create ACDC, ISS and an ANC
        acdc = acdcmap(israid=hab.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)
        anc = hab.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)
        ancSerder = _serder(anc)
        schema = acdc.sad["s"]["$id"]

        # Build IPEX messages
        applyExn, applyAtc = ipexApply(hab=hab,
                                       recp=hab.pre,
                                       message="Please issue a credential",
                                       schema=schema,
                                       attrs=dict(role="member"))
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       acdc=acdc,
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                       message="I agree to the offer",
                                       offer=offerExn)
        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the granted credential",
                                       acdc=acdc,
                                       iss=iss,
                                       anc=anc,
                                       agree=agreeExn)

        # Parse Offer for assertions
        offerIms = bytearray(offerExn.raw)
        offerIms.extend(offerAtc)
        offerResults = Parser(version=Vrsn_2_0).parse(ims=offerIms,
                                                      framed=False,
                                                      processive=False)
        assert offerIms == bytearray()
        assert len(offerResults) == 1
        offerResult = offerResults[0]
        assert offerResult.nests[0].serder.said == acdc.said

        # Parse Grant for assertions
        grantIms = bytearray(grantExn.raw)
        grantIms.extend(grantAtc)
        grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                      framed=False,
                                                      processive=False)
        assert grantIms == bytearray()
        assert len(grantResults) == 1
        grantResult = grantResults[0]
        assert grantResult.nests[0].serder.said == acdc.said
        assert grantResult.nests[1].serder.said == iss.said
        assert grantResult.nests[2].serder.said == ancSerder.said

        # Dispatch the whole chain
        for exn, atc in ((applyExn, applyAtc),
                         (offerExn, offerAtc),
                         (agreeExn, agreeAtc),
                         (grantExn, grantAtc)):
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
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
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        bad = Counter.enclose(qb64=b'',
                              code=Codens.AttachmentGroup,
                              version=Vrsn_2_0)

        with pytest.raises(ValueError, match="unsupported leading frame"):
            ipexOffer(hab=hab,
                      message="Here is the offered credential",
                      acdc=bad)


def test_ipex_v2_rejects_offer_with_mismatched_nested_acdc():
    with openHby(name="ipex-v2-bad-offer-nest",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Create one local AID that acts as both sender and receiver for the EXN
        hab = hby.makeHab(name="test")
        
        # Set up recorder, exchanger and load IPEX Handlers
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Build a registry event so both candidate ACDCs have a realistic registry id
        registry = regcept(israid=hab.pre)

        good = acdcmap(israid=hab.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        # This second ACDC is valid-looking but has a different SAID from the offered one.
        bad = acdcmap(israid=hab.pre,
                      regid=registry.said,
                      attribute=dict(d="", LEI="000000BADNEST00000000"),
                      iseaid=hab.pre)

        # Build a normal offer first; the signed body now promises `good.said`
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           message="Here is the offered credential",
                           acdc=good)

        # Replace the nested stream with `bad`, while leaving the signed EXN body untouched
        # The handler should compare the body SAID to the nested SAID and reject the mismatch
        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(bad)]))
        # `endorse` returns body + attachments; strip the body so we can pair the original body
        # with our deliberately wrong attachment stream.
        del atc[:exn.size]

        # Rebuild the tampered wire message: original signed body plus mismatched nested ACDC
        ims = bytearray(exn.raw)
        ims.extend(atc)

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        # The parser consumed the whole stream even though the handler rejected the EXN
        assert ims == bytearray()

        # Rejected offers must not be persisted as accepted exchange messages
        assert hby.db.exns.get(keys=(exn.said,)) is None

        # Rejected offers must also not create user-facing IPEX notifications
        assert recorder.items == []


def test_ipex_v2_rejects_grant_with_missing_nested_artifact():
    with openHby(name="ipex-v2-bad-grant-nest",
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
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        # Create the TEL issuance event that the grant body says should accompany the ACDC
        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)

        # Create the anchoring KEL event that the grant body also says should be present
        anc = hab.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)

        # Build a correct grant body that references all three artifacts: acdc, iss, and anc
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           acdc=acdc,
                           iss=iss,
                           anc=anc)

        # Re-endorse the same body but omit `iss` from the nested streams
        # This proves the handler rejects a body that promises an artifact it did not carry
        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(acdc), _nest(anc)]))

        # Strip the body returned by `endorse`; we only want the tampered attachments
        del atc[:exn.size]

        # Rebuild the malformed wire message: valid grant body, incomplete nested artifacts
        ims = bytearray(exn.raw)
        ims.extend(atc)

        # Parse through the exchanger/IPEX route 
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        # The parser should drain the input even though the IPEX handler rejects it
        assert ims == bytearray()

        # A rejected grant must not be saved as an accepted EXN
        assert hby.db.exns.get(keys=(exn.said,)) is None

        # A rejected grant must not create a user-facing IPEX notification
        assert recorder.items == []


def test_ipex_v2_responders_set_receiver():
    """Responder verbs address the prior's sender; offer honors an explicit recp.

    apply and grant already thread ``receiver=recp``; offer, agree, admit, and
    spurn respond to a prior message whose sender is the party to address, so
    their receiver derives from that prior's ``i`` field. An offer opened with no
    prior (the offer-first bootstrap) takes an explicit ``recp`` instead.
    """
    with openHby(name="ipex-v2-receiver",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")

        registry = regcept(israid=holder.pre)
        acdc = acdcmap(israid=holder.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
    
        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)
        anc = holder.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)
        schema = acdc.sad["s"]["$id"]

        # verifier applies to holder
        applyExn, _ = ipexApply(hab=verifier,
                                recp=holder.pre,
                                message="Prove over-21",
                                schema=schema,
                                attrs=dict(role="member"))
        assert applyExn.ked["i"] == verifier.pre
        assert applyExn.ked["ri"] == holder.pre

        # holder offers, addressing the applicant (apply's sender) by derivation
        offerExn, _ = ipexOffer(hab=holder,
                                message="Here are the terms",
                                acdc=acdc,
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
                                acdc=acdc,
                                iss=_nest(iss),
                                anc=anc,
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

        # offer-first bootstrap: no prior apply, explicit recp fixes the receiver
        bootExn, _ = ipexOffer(hab=holder,
                               message="Opening offer",
                               acdc=acdc,
                               recp=verifier.pre)
        assert bootExn.ked["p"] == ""
        assert bootExn.ked["ri"] == verifier.pre

        # an explicit recp overrides the derived receiver
        overrideExn, _ = ipexAgree(hab=verifier,
                                   message="I agree",
                                   offer=offerExn,
                                   recp=holder.pre)
        assert overrideExn.ked["ri"] == holder.pre


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
            _, iss = registrar.issue(registry, acdc=acdc, state="issued")
            anc = _anchor(hab, registry, iss, framed=False)
            ancSerder = _serder(anc)

            # Wire an exchanger with IPEX handlers so the grant can be parsed end to end
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

            # Grant the blindable ACDC plus its registry artifacts through one IPEX message
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Blindable disclosure",
                                           acdc=acdc,
                                           iss=iss,
                                           anc=anc)

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
            assert [nest.serder.said for nest in parsed] == [
                acdc.said,
                iss.said,
                ancSerder.said,
            ]

            # Serializing the whole stored message should round-trip the same nested substreams
            msg = serializeMessage(hby, grantExn.said, framed=True)
            ims = bytearray(msg)
            results = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                     framed=False,
                                                     processive=False)
            assert ims == bytearray()
            assert len(results) == 1
            assert [nest.serder.said for nest in results[0].nests] == [
                acdc.said,
                iss.said,
                ancSerder.said,
            ]
        finally:
            rgy.close()


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
            bupAnc = _anchor(hab, registry, bup, framed=False)
            bupAncSerder = _serder(bupAnc)

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
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

            applyExn, applyAtc = ipexApply(hab=hab,
                                           recp=hab.pre,
                                           message="Please issue the blind credential",
                                           schema=schema,
                                           attrs=dict(flow="blind"))
            offerExn, offerAtc = ipexOffer(hab=hab,
                                           message="Here is the blind credential",
                                           acdc=acdc,
                                           apply=applyExn)
            agreeExn, agreeAtc = ipexAgree(hab=hab,
                                           message="I agree to the blind credential",
                                           offer=offerExn)
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Here is the blind registry disclosure",
                                           acdc=acdc,
                                           iss=bup,
                                           anc=bupAnc,
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
            assert storedGrant.ked["a"]["acdc"] == acdc.said
            assert storedGrant.ked["a"]["iss"] == bup.said
            assert storedGrant.ked["a"]["anc"] == bupAncSerder.said

            # The stored message should round-trip with the same nested ACDC, blind update, and anchoring KEL event
            msg = serializeMessage(hby, grantExn.said, framed=True)
            ims = bytearray(msg)
            results = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                     framed=False,
                                                     processive=False)
            assert ims == bytearray()
            assert len(results) == 1
            assert [nest.serder.said for nest in results[0].nests] == [
                acdc.said,
                bup.said,
                bupAncSerder.said,
            ]

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
            issuedAnc = _anchor(hab, registry, issued, framed=False)
            issuedAncSerder = _serder(issuedAnc)

            assert rgy.store.seqEvent(registry.regk, 0).said == rip.said
            assert rgy.store.seqEvent(registry.regk, 1).said == issued.said
            assert rgy.store.headEvent(registry.regk).said == issued.said
            assert issued.sad["b"] == issuedBlinder.said

            # Wire one exchanger with the V2 IPEX handlers, then disclose the issued update first
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

            # First disclose the issued-state credential through one full linear IPEX exchange
            issuedApplyExn, issuedApplyAtc = ipexApply(hab=hab,
                                                       recp=hab.pre,
                                                       message="Please issue the issued blind credential",
                                                       schema=schema)
            issuedOfferExn, issuedOfferAtc = ipexOffer(hab=hab,
                                                       message="Here is the issued blind credential",
                                                       acdc=acdc,
                                                       apply=issuedApplyExn)
            issuedAgreeExn, issuedAgreeAtc = ipexAgree(hab=hab,
                                                       message="I agree to the issued blind credential",
                                                       offer=issuedOfferExn)
            issuedGrantExn, issuedGrantAtc = ipexGrant(hab=hab,
                                                       recp=hab.pre,
                                                       message="Here is the issued blind registry disclosure",
                                                       acdc=acdc,
                                                       iss=issued,
                                                       anc=issuedAnc,
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
            assert issuedStoredGrant.ked["a"]["acdc"] == acdc.said
            assert issuedStoredGrant.ked["a"]["iss"] == issued.said
            assert issuedStoredGrant.ked["a"]["anc"] == issuedAncSerder.said

            issuedMsg = serializeMessage(hby, issuedGrantExn.said, framed=True)
            issuedIms = bytearray(issuedMsg)
            issuedResults = Parser(version=Vrsn_2_0).parse(ims=issuedIms,
                                                           framed=False,
                                                           processive=False)
            assert issuedIms == bytearray()
            assert len(issuedResults) == 1
            assert [nest.serder.said for nest in issuedResults[0].nests] == [
                acdc.said,
                issued.said,
                issuedAncSerder.said,
            ]

            issuedCarriedBup = issuedResults[0].nests[1].serder
            issuedUnblinder = Blinder.unblind(said=issuedCarriedBup.sad["b"],
                                              uuid=issuedBlinder.uuid,
                                              acdc=acdc.said,
                                              states=["issued", "revoked"])
            assert issuedUnblinder is not None
            assert issuedUnblinder.state == "issued"
            assert issuedUnblinder.acdc == acdc.said
            assert issuedUnblinder.crew == issuedBlinder.crew

            # Commit a revoked blind update that follows the issued state
            revokedBlinder, revoked = registrar.issue(registry, acdc=acdc, state="revoked")
            revokedAnc = _anchor(hab, registry, revoked, framed=False)
            revokedAncSerder = _serder(revokedAnc)

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
                                                         schema=schema,
                                                         attrs=dict(flow="revoked"))
            revokedOfferExn, revokedOfferAtc = ipexOffer(hab=hab,
                                                         message="Here is the revoked blind credential",
                                                         acdc=acdc,
                                                         apply=revokedApplyExn)
            revokedAgreeExn, revokedAgreeAtc = ipexAgree(hab=hab,
                                                         message="I agree to the revoked blind credential",
                                                         offer=revokedOfferExn)
            revokedGrantExn, revokedGrantAtc = ipexGrant(hab=hab,
                                                         recp=hab.pre,
                                                         message="Here is the revoked blind registry disclosure",
                                                         acdc=acdc,
                                                         iss=revoked,
                                                         anc=revokedAnc,
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
            assert revokedStoredGrant.ked["a"]["acdc"] == acdc.said
            assert revokedStoredGrant.ked["a"]["iss"] == revoked.said
            assert revokedStoredGrant.ked["a"]["anc"] == revokedAncSerder.said

            revokedMsg = serializeMessage(hby, revokedGrantExn.said, framed=True)
            revokedIms = bytearray(revokedMsg)
            revokedResults = Parser(version=Vrsn_2_0).parse(ims=revokedIms,
                                                             framed=False,
                                                             processive=False)
            assert revokedIms == bytearray()
            assert len(revokedResults) == 1
            assert [nest.serder.said for nest in revokedResults[0].nests] == [
                acdc.said,
                revoked.said,
                revokedAncSerder.said,
            ]

            revokedCarriedBup = revokedResults[0].nests[1].serder
            revokedUnblinder = Blinder.unblind(said=revokedCarriedBup.sad["b"],
                                               uuid=revokedBlinder.uuid,
                                               acdc=acdc.said,
                                               states=["issued", "revoked"])
            assert revokedUnblinder is not None
            assert revokedUnblinder.state == "revoked"
            assert revokedUnblinder.acdc == acdc.said
            assert revokedUnblinder.crew == revokedBlinder.crew

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
