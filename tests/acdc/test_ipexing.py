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
from keri.core import (Blinder, Codens, Counter, GenDex, Kevery, Kramer, Parser,
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
                                          attrs=dict(role="member"),
                                          modifiers=dict(dp=[[schema, "/", ["a/role"]]]))

        # Build Offer message chained to apply 
        offerExn, offerAtc = ipexOffer(hab=hab,
                                          message="Here is the offered credential",
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
                                          artifacts=[_nest(iss), anc],
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
        assert applyExn.ked["q"]["dp"] == [[schema, "/", ["a/role"]]]

        assert offerExn.ked["a"]["m"] == "Here is the offered credential"
        assert offerExn.ked["p"] == applyExn.said       # prior
        assert offerExn.ked["q"]["dp"] == []

        assert agreeExn.ked["a"]["m"] == "I agree to the offer"
        assert agreeExn.ked["p"] == offerExn.said

        assert grantExn.ked["a"]["m"] == "Here is the granted credential"
        assert grantExn.ked["a"]["o"] == acdc.said
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
        assert offerResult.nests == []

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


def test_ipex_v2_grant_carries_multiple_registry_updates():
    """Grant can carry multiple supporting registry-update artifacts."""
    with openHby(name="ipex-v2-grant-updates",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        issued = blindate(regid=registry.said,
                          prior=registry.said,
                          blid=Blinder.blind(acdc=acdc.said, state="issued", sn=1).said)
        revoked = blindate(regid=registry.said,
                           prior=issued.said,
                           blid=Blinder.blind(acdc=acdc.said, state="revoked", sn=2).said,
                           sn=2)

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here are the registry updates",
                                       origin=acdc,
                                       artifacts=[issued, revoked])

        assert grantExn.ked["a"]["o"] == acdc.said
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
            issued.said,
            revoked.said,
        ]

        dispatch = bytearray(grantExn.raw)
        dispatch.extend(grantAtc)
        Parser(version=Vrsn_2_0).parse(ims=dispatch, framed=False, exc=exc)
        assert dispatch == bytearray()

        storedGrant = hby.db.exns.get(keys=(grantExn.said,))
        assert storedGrant is not None
        assert storedGrant.ked["a"]["o"] == acdc.said
        assert "iss" not in storedGrant.ked["a"]


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
                                        attrs=dict(role="member"),
                                        modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        offer0, offer0Atc = ipexOffer(hab=hab,
                                        message="Here is the offered credential",
                                        apply=apply0)
        agree0, agree0Atc = ipexAgree(hab=hab,
                                        message="I agree to the offer",
                                        offer=offer0)
        grant0, grant0Atc = ipexGrant(hab=hab,
                                        recp=hab.pre,
                                        message="Here is the granted credential",
                                        origin=acdc,
                                        artifacts=[iss, anc],
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
        assert storedApply.ked["a"]["role"] == "member"
        assert storedApply.ked["q"]["dp"] == [[schema, "/", ["a/role"]]]

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
        assert "acdc" not in storedOffer.ked["a"]
        assert storedOffer.ked["q"]["dp"] == []
        assert storedOffer.ked["p"] == apply0.said

        storedAgree = hby.db.exns.get(keys=(agree0.said,))
        assert storedAgree.ked["a"]["m"] == "I agree to the offer"
        assert storedAgree.ked["p"] == offer0.said

        storedGrant = hby.db.exns.get(keys=(grant0.said,))
        assert storedGrant.ked["a"]["m"] == "Here is the granted credential"
        assert storedGrant.ked["a"]["o"] == acdc.said
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
        Parser(version=Vrsn_2_0).parse(ims=dupSpurnIms, framed=False, exc=exc)
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
                                        origin=acdc,
                                        artifacts=[_nest(iss)])

        # Build a spurn against that grant
        spurn1, spurn1Atc = ipexSpurn(hab=hab,
                                        message="I reject this grant",
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

        # Assert that a flow-starting grant is valid and can also be explicitly spurned
        assert hby.db.exns.get(keys=(grant1.said,)) is not None
        assert hby.db.exns.get(keys=(spurn1.said,)) is not None

        with pytest.raises(ValueError):
            ipexOffer(hab=hab, message="Bare offer without receiver")

        # Build a bare offer with an explicit receiver; the starter generates
        # its own xid and still supports a valid spurn against it.
        offer1, offer1Atc = ipexOffer(hab=hab,
                                      message="Bare offer for spurn path",
                                      recp=hab.pre)
        assert offer1.ked["x"] != ""
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
            ("/exn/ipex/spurn", "I reject this grant"),
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
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       apply=applyExn)
        agreeExn, agreeAtc = ipexAgree(hab=hab,
                                       message="I agree to the offer",
                                       offer=offerExn)
        grantExn, grantAtc = ipexGrant(hab=hab,
                                       recp=hab.pre,
                                       message="Here is the granted credential",
                                       origin=acdc,
                                       artifacts=[iss, anc],
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
        assert offerResult.nests == []

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

        # Build a normal offer first, then remove q.dp to prove the V2 handler
        # fails closed on the required disclosure-plan field.
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
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

        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        # The parser consumed the whole stream even though the handler rejected the EXN
        assert ims == bytearray()

        # Rejected offers must not be persisted as accepted exchange messages
        assert hby.db.exns.get(keys=(badOffer.said,)) is None

        # Rejected offers must also not create user-facing IPEX notifications
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

        # Build a correct grant body that carries the origin plus two supporting artifacts.
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           origin=acdc,
                           artifacts=[iss, anc])

        # Re-endorse the same body but omit the origin artifact. In V2 the grant
        # must carry the presentation/ACDC as the first nested artifact matching a.o.
        atc = bytearray(hab.endorse(serder=exn,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(iss), _nest(anc)]))

        # Strip the body returned by `endorse`; we only want the tampered attachments
        del atc[:exn.size]

        # Rebuild the malformed wire message: valid grant body, but the first
        # nested artifact no longer matches the origin SAID in a.o.
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
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)

        blinder = Blinder.blind(acdc=acdc.said, state="issued", sn=1).said
        iss = blindate(regid=registry.said,
                       prior=registry.said,
                       blid=blinder)
        anc = hab.msgOwnEvent(sn=0, framed=False, gvrsn=Vrsn_2_0)

        # Start from a valid grant, then remove `a.o` and re-sign it so the
        # parser reaches the handler with a malformed but otherwise authentic body.
        exn, _ = ipexGrant(hab=hab,
                           recp=hab.pre,
                           message="Here is the granted credential",
                           origin=acdc,
                           artifacts=[iss, anc])
        sad = dict(exn.ked)
        sad["a"] = dict(exn.ked["a"])
        sad["a"].pop("o")
        badGrant = SerderKERI(sad=sad, makify=True, verify=False)

        atc = bytearray(hab.endorse(serder=badGrant,
                                    framed=False,
                                    gvrsn=Vrsn_2_0,
                                    nests=[_nest(acdc), _nest(iss), _nest(anc)]))
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
                                attrs=dict(role="member"),
                                modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        assert applyExn.ked["i"] == verifier.pre
        assert applyExn.ked["ri"] == holder.pre

        # holder offers, addressing the applicant (apply's sender) by derivation
        offerExn, _ = ipexOffer(hab=holder,
                                message="Here are the terms",
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
                                artifacts=[_nest(iss), anc],
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

        # offer-first bootstrap: no prior apply, so explicit recp opens the
        # thread and the builder generates xid when omitted.
        bootExn, _ = ipexOffer(hab=holder,
                               message="Opening offer",
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
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        # Reuse the credential schema in the apply disclosure request.
        schema = acdc.sad["s"]["$id"]

        # Start a valid apply-first thread from the verifier to the holder.
        applyExn, _ = ipexApply(hab=verifier,
                                recp=holder.pre,
                                message="Prove over-21",
                                attrs=dict(role="member"),
                                modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        # Continue with the valid holder response that derives its receiver and xid from the apply.
        offerExn, _ = ipexOffer(hab=holder,
                                message="Here are the terms",
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
            ipexOffer(hab=mallory, message="Bad sender", apply=applyExn)
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
            ipexOffer(hab=holder, message="Bad receiver", apply=applyExn, recp=mallory.pre)
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
            ipexOffer(hab=holder, message="Bad xid", apply=applyExn, xid="F" * 44)
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
                      modifiers=dict(dp=[[schema, "/", ["a/role"]]]),
                      xid="F" * 44)

        # Set 4: every flow starter still needs a recipient, but now generates
        # xid internally without accepting one from the caller.
        # Offer-first flows reject a starter with no recipient.
        with pytest.raises(ValueError):
            ipexOffer(hab=holder, message="Bare offer")
        # Supplying only the recipient is now enough for an offer-first opener.
        bareOffer, _ = ipexOffer(hab=holder, message="Bare offer", recp=verifier.pre)
        assert bareOffer.ked["p"] == ""
        assert bareOffer.ked["ri"] == verifier.pre
        assert bareOffer.ked["x"] != ""
        # Supplying xid directly is no longer supported at all.
        with pytest.raises(TypeError):
            ipexOffer(hab=holder, message="Bare offer", recp=verifier.pre, xid="E" * 44)
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
                      modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        # Apply now generates xid internally when the caller omits it.
        bareApply, _ = ipexApply(hab=verifier,
                                 recp=holder.pre,
                                 message="Generated xid",
                                 attrs=dict(role="member"),
                                 modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        assert bareApply.ked["p"] == ""
        assert bareApply.ked["ri"] == holder.pre
        assert bareApply.ked["x"] != ""

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
                       regid=registry.said,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=holder.pre)
        schema = acdc.sad["s"]["$id"]

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Prove over-21",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[schema, "/", ["a/role"]]]))
        offerExn, offerAtc = ipexOffer(hab=holder,
                                       message="Here are the terms",
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
                                           origin=acdc,
                                           artifacts=[iss, anc])

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
                                           attrs=dict(flow="blind"),
                                           modifiers=dict(dp=[[schema, "/", []]]))
            offerExn, offerAtc = ipexOffer(hab=hab,
                                           message="Here is the blind credential",
                                           apply=applyExn)
            agreeExn, agreeAtc = ipexAgree(hab=hab,
                                           message="I agree to the blind credential",
                                           offer=offerExn)
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Here is the blind registry disclosure",
                                           origin=acdc,
                                           artifacts=[bup, bupAnc],
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
            assert storedGrant.ked["a"]["o"] == acdc.said
            assert "iss" not in storedGrant.ked["a"]
            assert "anc" not in storedGrant.ked["a"]

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

    # Drive all "receive time" checks from one mutable clock so we can hold the
    # accept path steady, then deliberately push one mid-flow message outside the
    # lower timeliness bound before retrying it.
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
            issuedAnc = _anchor(hab, registry, issued, framed=False)
            issuedAncSerder = _serder(issuedAnc)

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
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

            with openCF(name="ipex-v2-kram", base="test", temp=True) as cf:
                cf.put(kramConfig)
                kvy = Kevery(db=hby.db,
                             lax=False,
                             local=False,
                             kramer=Kramer(db=hby.db, cf=cf),
                             exc=exc)
                assert kvy.kramer.enabled is True

                # Freeze one receiver-side "now" and choose message datetimes that
                # intentionally land at different points inside the allowed window.
                receiveDt = helping.fromIso8601(helping.nowIso8601())
                receiveMs = receiveDt.timestamp() * 1000
                applyStamp = helping.toIso8601(receiveDt - timedelta(milliseconds=4500))
                offerRetryStamp = helping.toIso8601(receiveDt - timedelta(milliseconds=2000))
                agreeStamp = helping.toIso8601(receiveDt)
                grantStamp = helping.toIso8601(receiveDt + timedelta(milliseconds=500))
                admitStamp = helping.toIso8601(receiveDt + timedelta(milliseconds=d))

                # Build a real two-party IPEX thread. The recipient applies for
                # the credential, the issuer answers with the offer and grant,
                # and the recipient closes the thread with agree and admit.
                # The offer is handled in two passes below: first stale and
                # denied, then resent with an in-window timestamp and accepted.
                applyExn, applyAtc = ipexApply(hab=recipient,
                                               recp=hab.pre,
                                               message="Please issue the blind credential",
                                               attrs={},
                                               modifiers=dict(dp=[[schema, "/", []]]),
                                               dt=applyStamp)
                staleOfferStamp = helping.toIso8601(
                    receiveDt - timedelta(milliseconds=d + sl + 1))
                staleOfferExn, staleOfferAtc = ipexOffer(hab=hab,
                                                         message="Here is the blind credential",
                                                         apply=applyExn,
                                                         dt=staleOfferStamp)
                offerExn, offerAtc = ipexOffer(hab=hab,
                                               message="Here is the blind credential",
                                               apply=applyExn,
                                               dt=offerRetryStamp)
                agreeExn, agreeAtc = ipexAgree(hab=recipient,
                                               message="I agree to the blind credential",
                                               offer=offerExn,
                                               dt=agreeStamp)
                grantExn, grantAtc = ipexGrant(hab=hab,
                                               recp=recipient.pre,
                                               message="Here is the blind registry disclosure",
                                               origin=acdc,
                                               artifacts=[issued, issuedAnc],
                                               agree=agreeExn,
                                               dt=grantStamp)
                admitExn, admitAtc = ipexAdmit(hab=recipient,
                                               message="Thanks for the blind credential",
                                               grant=grantExn,
                                               dt=admitStamp)

                # The stale offer still points at the same transaction, but its
                # message timestamp is just outside the lower timeliness bound.
                assert staleOfferExn.ked["x"] == applyExn.ked["x"]
                staleOfferMs = helping.fromIso8601(staleOfferStamp).timestamp() * 1000
                assert staleOfferMs < (receiveMs - d - sl)

                # The recovered offer and every later accepted exn all point back
                # to the apply opener so KRAM classifies them under one transaction.
                accepted = (
                    (applyExn, applyAtc, applyStamp),
                    (offerExn, offerAtc, offerRetryStamp),
                    (agreeExn, agreeAtc, agreeStamp),
                    (grantExn, grantAtc, grantStamp),
                    (admitExn, admitAtc, admitStamp),
                )
                for serder, _, stamp in accepted:
                    assert serder.ked["x"] == applyExn.ked["x"]

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
                assert (receiveMs - d - sl) <= applyMdtMs <= (receiveMs + d)
                assert applyXdtMs <= applyMdtMs <= (applyXdtMs + xl)

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

                # Resend the same logical offer with a fresh, in-window timestamp.
                # Because the stale one never got recorded, this retry should be
                # accepted and the exchange can continue from it.
                for exn, atc, stamp in accepted[1:]:    # don't count the apply
                    ims = bytearray(exn.raw)
                    ims.extend(atc)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                    assert ims == bytearray()

                    # Once KRAM accepts the message, the IPEX exchanger should
                    # persist the exn body and preserve the exchange id.
                    stored = hby.db.exns.get(keys=(exn.said,))
                    assert stored is not None
                    assert stored.ked["x"] == applyExn.ked["x"]

                    # KRAM should also record one transaction-cache row that keeps
                    # the message's own mdt and the original apply xdt.
                    cache = hby.db.kramTMSC.get(
                        keys=(exn.ked["i"], applyExn.ked["x"], exn.said))
                    assert cache is not None
                    assert cache.mdt == stamp
                    assert cache.xdt == applyStamp
                    assert hby.db.kramXDT.get(keys=(applyExn.ked["x"],)).dts == applyStamp

                    mdtMs = helping.fromIso8601(cache.mdt).timestamp() * 1000
                    xdtMs = helping.fromIso8601(cache.xdt).timestamp() * 1000

                    # Each accepted exn must satisfy both KRAM checks:
                    # 1. message time is timely relative to receiver now
                    # 2. message time still lies within the exchange lifetime
                    assert (receiveMs - d - sl) <= mdtMs <= (receiveMs + d)
                    assert xdtMs <= mdtMs <= (xdtMs + xl)

                # Re-serialize the stored grant and confirm the exact nested ACDC,
                # blind update, and anchor survive the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [
                    acdc.said,
                    issued.said,
                    issuedAncSerder.said,
                ]

                # The carried blindable update must still unblind to the expected
                # issued state once pulled back out of the accepted IPEX grant.
                carriedBup = grantResults[0].nests[1].serder
                unblinder = Blinder.unblind(said=carriedBup.sad["b"],
                                            uuid=issuedBlinder.uuid,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"
                assert unblinder.acdc == acdc.said
                assert unblinder.crew == issuedBlinder.crew

                # Recorder order proves the whole accepted chain actually reached
                # the IPEX handlers after KRAM let each message through.
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                    ("/exn/ipex/offer", "Here is the blind credential"),
                    ("/exn/ipex/agree", "I agree to the blind credential"),
                    ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                    ("/exn/ipex/admit", "Thanks for the blind credential"),
                ]

                # The clock never had to move for the retry itself. Recovery here
                # means that a stale message can be resent with a fresh mdt and
                # the rest of the transaction still proceeds from that new offer.
                assert helping.nowIso8601() == "2021-01-01T00:00:00.000000+00:00"

                # The stale offer is never persisted, while the retry is, proving
                # the exchange recovered by accepting the second transmission.
                assert hby.db.exns.get(keys=(staleOfferExn.said,)) is None
                assert hby.db.exns.get(keys=(offerExn.said,)) is not None

                # No clock advance was required for the recovered path, so keep
                # the fake clock parked at the original receive instant.
                assert [(item["r"], item["m"]) for item in recorder.items] == [
                    ("/exn/ipex/apply", "Please issue the blind credential"),
                    ("/exn/ipex/offer", "Here is the blind credential"),
                    ("/exn/ipex/agree", "I agree to the blind credential"),
                    ("/exn/ipex/grant", "Here is the blind registry disclosure"),
                    ("/exn/ipex/admit", "Thanks for the blind credential"),
                ]
        finally:
            rgy.close()


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
            issuedAnc = _anchor(hab, registry, issued, framed=False)
            issuedAncSerder = _serder(issuedAnc)

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
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

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
                                               recp=recipient.pre,
                                               dt=offerStamp)
                agreeExn, agreeAtc = ipexAgree(hab=recipient,
                                               message="I agree to the offer-first credential",
                                               offer=offerExn,
                                               dt=agreeStamp)
                grantExn, grantAtc = ipexGrant(hab=hab,
                                               recp=recipient.pre,
                                               message="Here is the offer-first blind registry disclosure",
                                               origin=acdc,
                                               artifacts=[issued, issuedAnc],
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

                # Re-serialize the stored grant and confirm the exact nested ACDC,
                # blind update, and anchor survive the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [
                    acdc.said,
                    issued.said,
                    issuedAncSerder.said,
                ]

                # The carried blindable update must still unblind to the expected
                # issued state once pulled back out of the accepted IPEX grant.
                carriedBup = grantResults[0].nests[1].serder
                unblinder = Blinder.unblind(said=carriedBup.sad["b"],
                                            uuid=issuedBlinder.uuid,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"
                assert unblinder.acdc == acdc.said
                assert unblinder.crew == issuedBlinder.crew

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
            issuedAnc = _anchor(hab, registry, issued, framed=False)
            issuedAncSerder = _serder(issuedAnc)

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
            loadHandlers(hby=hby, exc=exc, notifier=recorder)

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
                                               origin=acdc,
                                               artifacts=[issued, issuedAnc],
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

                # Re-serialize the stored grant and confirm the exact nested ACDC,
                # blind update, and anchor survive the KRAM + exchanger path.
                grantMsg = serializeMessage(hby, grantExn.said, framed=True)
                grantIms = bytearray(grantMsg)
                grantResults = Parser(version=Vrsn_2_0).parse(ims=grantIms,
                                                              framed=False,
                                                              processive=False)
                assert grantIms == bytearray()
                assert len(grantResults) == 1
                assert [nest.serder.said for nest in grantResults[0].nests] == [
                    acdc.said,
                    issued.said,
                    issuedAncSerder.said,
                ]

                # The carried blindable update must still unblind to the expected
                # issued state once pulled back out of the accepted IPEX grant.
                carriedBup = grantResults[0].nests[1].serder
                unblinder = Blinder.unblind(said=carriedBup.sad["b"],
                                            uuid=issuedBlinder.uuid,
                                            acdc=acdc.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"
                assert unblinder.acdc == acdc.said
                assert unblinder.crew == issuedBlinder.crew

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
                                                       attrs=None,
                                                       modifiers=dict(dp=[[schema, "/", []]]))
            issuedOfferExn, issuedOfferAtc = ipexOffer(hab=hab,
                                                       message="Here is the issued blind credential",
                                                       apply=issuedApplyExn)
            issuedAgreeExn, issuedAgreeAtc = ipexAgree(hab=hab,
                                                       message="I agree to the issued blind credential",
                                                       offer=issuedOfferExn)
            issuedGrantExn, issuedGrantAtc = ipexGrant(hab=hab,
                                                       recp=hab.pre,
                                                       message="Here is the issued blind registry disclosure",
                                                       origin=acdc,
                                                       artifacts=[issued, issuedAnc],
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
            assert issuedStoredGrant.ked["a"]["o"] == acdc.said
            assert "iss" not in issuedStoredGrant.ked["a"]
            assert "anc" not in issuedStoredGrant.ked["a"]

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
                                                         attrs=dict(flow="revoked"),
                                                         modifiers=dict(dp=[[schema, "/", []]]))
            revokedOfferExn, revokedOfferAtc = ipexOffer(hab=hab,
                                                         message="Here is the revoked blind credential",
                                                         apply=revokedApplyExn)
            revokedAgreeExn, revokedAgreeAtc = ipexAgree(hab=hab,
                                                         message="I agree to the revoked blind credential",
                                                         offer=revokedOfferExn)
            revokedGrantExn, revokedGrantAtc = ipexGrant(hab=hab,
                                                         recp=hab.pre,
                                                         message="Here is the revoked blind registry disclosure",
                                                         origin=acdc,
                                                         artifacts=[revoked, revokedAnc],
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
            assert revokedStoredGrant.ked["a"]["o"] == acdc.said
            assert "iss" not in revokedStoredGrant.ked["a"]
            assert "anc" not in revokedStoredGrant.ked["a"]

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
