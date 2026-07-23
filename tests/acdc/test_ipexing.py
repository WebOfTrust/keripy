# -*- encoding: utf-8 -*-
"""
tests.acdc.test_ipexing module

"""
import pytest
from keri import Kinds, Vrsn_2_0
from keri.acdc import (acdcmap, apply as ipexApply, admit as ipexAdmit,
                       agree as ipexAgree, grant as ipexGrant,
                       loadHandlers, offer as ipexOffer, regcept,
                       spurn as ipexSpurn, update)
from keri.app import openHby
from keri.core import Codens, Counter, GenDex, Parser, Serdery, Texter
from keri.kering import Colds, sniff
from keri.peer import Exchanger

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
        iss = update(regid=registry.said,
                     prior=registry.said,
                     acdc=acdc.said,
                     state="issued")
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
        iss = update(regid=registry.said,
                     prior=registry.said,
                     acdc=acdc.said,
                     state="issued")
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
        iss = update(regid=registry.said,
                     prior=registry.said,
                     acdc=acdc.said,
                     state="issued")
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
