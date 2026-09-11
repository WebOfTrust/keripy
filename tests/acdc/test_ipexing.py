# -*- encoding: utf-8 -*-
"""
tests.acdc.test_ipexing module

"""
from datetime import timedelta

import pytest
from keri import Ilks, Kinds, Vrsn_2_0
from keri.acdc import (Regery, Registrar, acdcmap, blindate,
                       apply as ipexApply, admit as ipexAdmit,
                       agree as ipexAgree, grant as ipexGrant,
                       loadHandlers, offer as ipexOffer, regcept,
                       spurn as ipexSpurn)
from keri.app import openCF, openHby
from keri.core import (Blinder, Codens, Counter, Diger, GenDex, Kevery, Kramer, Noncer,
                       Number, Parser, Schemer, SealEvent, SealSource, messagize,
                       SerderKERI, Serdery, Texter, exchange)
from keri.db import reopenDB
from keri.kering import Colds, MissingSignatureError, sniff
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


def _edge(label, node, *, op=None, schema=None):
    """Create a simple edge block that points at another disclosed ACDC node."""
    target = dict(d="", n=node.said)
    if op is not None:
        target["o"] = op
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
                                          attrs=dict(role="member"),
                                          ax=[False],
                                          modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))

        # Build Offer message chained to apply 
        offerExn, offerAtc = ipexOffer(hab=hab,
                                       message="Here is the offered credential",
                                       origin=acdc,
                                       ax=[False],
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
                                          ax=[False],
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


def test_ipex_v2_rejects_empty_ax_list():
    """Single-DAG IPEX requires exactly one boolean when ax is present."""
    with openHby(name="ipex-v2-empty-ax",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        schema = acdcmap(israid=hab.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         iseaid=hab.pre).sad["s"]["$id"]

        with pytest.raises(ValueError):
            ipexApply(hab=hab,
                      recp=hab.pre,
                      message="Please issue a credential",
                      ax=[],
                      modifiers=dict(dp=[[[schema, "/", []]]]))


def test_ipex_v2_ax_public_parameter_validation():
    """Builders accept only an optional, one-boolean ax public parameter."""
    with openHby(name="ipex-v2-ax-parameter",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="sender")
        recipient = hby.makeHab(name="recipient")
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=recipient.pre)
        schema = acdc.sad["s"]["$id"]
        dp = dict(dp=[[[schema, "/", []]]])

        sn = hab.kever.sn
        omitted, omittedAtc = ipexApply(hab=hab,
                                        recp=recipient.pre,
                                        message="No anchoring preference",
                                        modifiers=dp)
        optional, optionalAtc = ipexApply(hab=hab,
                                          recp=recipient.pre,
                                          message="Anchoring is optional",
                                          modifiers=dp,
                                          ax=[False])
        assert "ax" not in omitted.ked["a"]
        assert optional.ked["a"]["ax"] == [False]
        assert hab.kever.sn == sn

        for exn, atc in ((omitted, omittedAtc), (optional, optionalAtc)):
            result = Parser(version=Vrsn_2_0).parse(
                ims=bytearray(exn.raw) + atc,
                framed=False,
                processive=False)[0]
            assert result.sscs == []
            assert len(result.tsgs) == 1
        
        # Test malformed ax values 
        malformed = ([], [True, False], True, ["true"])
        for ax in malformed:
            with pytest.raises(ValueError):
                ipexApply(hab=hab,
                          recp=recipient.pre,
                          message="Malformed anchoring preference",
                          modifiers=dp,
                          ax=ax)
            with pytest.raises(ValueError):
                ipexOffer(hab=hab,
                          recp=recipient.pre,
                          message="Malformed anchoring preference",
                          origin=acdc,
                          modifiers=dp,
                          ax=ax)
            with pytest.raises(ValueError):
                ipexGrant(hab=hab,
                          recp=recipient.pre,
                          message="Malformed anchoring preference",
                          origin=acdc,
                          ax=ax)
        
        # ax is a reserved attribute and cannot be set in attrs
        with pytest.raises(ValueError):
            # Validate Apply 
            ipexApply(hab=hab,
                      recp=recipient.pre,
                      message="Reserved attribute",
                      modifiers=dp,
                      attrs=dict(ax=[True]))
        with pytest.raises(ValueError):
            # Validate Offer
            ipexOffer(hab=hab,
                      recp=recipient.pre,
                      message="Reserved attribute",
                      origin=acdc,
                      modifiers=dp,
                      attrs=dict(ax=[True]))
        with pytest.raises(ValueError):
            # Validate Grant
            ipexGrant(hab=hab,
                      recp=recipient.pre,
                      message="Reserved attribute",
                      origin=acdc,
                      attrs=dict(ax=[True]))


def test_ipex_v2_ax_echo_and_anchor_construction():
    """Truthy negotiation is echoed and only binding replies create KEL anchors."""
    with openHby(name="ipex-v2-ax-builders",
                 base="test",
                 version=Vrsn_2_0) as hby:
        grantor = hby.makeHab(name="grantor")
        applicant = hby.makeHab(name="applicant")
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=applicant.pre)
        schema = acdc.sad["s"]["$id"]
        dp = dict(dp=[[[schema, "/", []]]])

        applicantSn = applicant.kever.sn
        applyExn, applyAtc = ipexApply(hab=applicant,
                                       recp=grantor.pre,
                                       message="Please anchor this exchange",
                                       modifiers=dp,
                                       ax=[True])
        assert applicant.kever.sn == applicantSn

        with pytest.raises(ValueError):
            ipexOffer(hab=grantor,
                      message="Missing echo",
                      origin=acdc,
                      apply=applyExn)
        with pytest.raises(ValueError):
            ipexOffer(hab=grantor,
                      message="False echo",
                      origin=acdc,
                      apply=applyExn,
                      ax=[False])
        with pytest.raises(ValueError):
            ipexGrant(hab=grantor,
                      recp=applicant.pre,
                      message="Missing direct-grant echo",
                      origin=acdc,
                      apply=applyExn)

        grantorSn = grantor.kever.sn
        offerExn, offerAtc = ipexOffer(hab=grantor,
                                       message="Anchored offer",
                                       origin=acdc,
                                       apply=applyExn,
                                       ax=[True])
        assert grantor.kever.sn == grantorSn

        agreeExn, agreeAtc = ipexAgree(hab=applicant,
                                       message="Anchored agreement",
                                       offer=offerExn)
        assert agreeExn.ked["a"]["ax"] == [True]
        assert applicant.kever.sn == applicantSn + 1

        with pytest.raises(ValueError):
            ipexGrant(hab=grantor,
                      recp=applicant.pre,
                      message="Missing agreement echo",
                      origin=acdc,
                      agree=agreeExn)

        grantExn, grantAtc = ipexGrant(hab=grantor,
                                       recp=applicant.pre,
                                       message="Anchored grant",
                                       origin=acdc,
                                       agree=agreeExn,
                                       ax=[True])
        admitExn, admitAtc = ipexAdmit(hab=applicant,
                                       message="Anchored admission",
                                       grant=grantExn)
        assert grantExn.ked["a"]["ax"] == [True]
        assert admitExn.ked["a"]["ax"] == [True]

        signaling = ((applyExn, applyAtc), (offerExn, offerAtc))
        binding = ((agreeExn, agreeAtc), (grantExn, grantAtc), (admitExn, admitAtc))
        for exn, atc in signaling:
            result = Parser(version=Vrsn_2_0).parse(
                ims=bytearray(exn.raw) + atc,
                framed=False,
                processive=False)[0]
            assert result.sscs == []
            assert len(result.tsgs) == 1

        for exn, atc in binding:
            result = Parser(version=Vrsn_2_0).parse(
                ims=bytearray(exn.raw) + atc,
                framed=False,
                processive=False)[0]
            assert len(result.sscs) == 1
            assert len(result.tsgs) == 1
            number, diger = result.sscs[0]
            event = hby.db.evts.get(keys=(exn.pre, diger.qb64))
            assert hby.db.kels.getLast(keys=exn.pre, on=number.sn) == diger.qb64
            assert any(seal.get("d") == exn.said for seal in event.seals)

        with pytest.raises(ValueError):
            ipexGrant(hab=grantor,
                      recp=applicant.pre,
                      message="Ambiguous prior",
                      origin=acdc,
                      agree=agreeExn,
                      apply=applyExn,
                      ax=[True])

        optionalApply, _ = ipexApply(hab=applicant,
                                      recp=grantor.pre,
                                      message="Optional direct grant",
                                      modifiers=dp,
                                      ax=[False])
        with pytest.raises(ValueError):
            ipexGrant(hab=grantor,
                      recp=applicant.pre,
                      message="Direct grant invents anchoring",
                      origin=acdc,
                      apply=optionalApply,
                      ax=[True])

        optionalOffer, _ = ipexOffer(hab=grantor,
                                      message="Optional offer",
                                      origin=acdc,
                                      apply=optionalApply,
                                      ax=[False])
        optionalAgree, _ = ipexAgree(hab=applicant,
                                      message="Optional agreement",
                                      offer=optionalOffer)
        with pytest.raises(ValueError):
            ipexGrant(hab=grantor,
                      recp=applicant.pre,
                      message="Grant invents anchoring after agreement",
                      origin=acdc,
                      agree=optionalAgree,
                      ax=[True])


def test_ipex_v2_establishment_only_anchor_construction():
    """Establishment-only senders anchor binding exchanges with rotations."""
    with openHby(name="ipex-v2-est-only-anchor",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Only the grantor opts into the establishment-only KEL policy.
        grantor = hby.makeHab(name="grantor", estOnly=True)
        recipient = hby.makeHab(name="recipient")

        # Use a simple single-node DAG so this test isolates anchor construction.
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", role="member"),
                       iseaid=recipient.pre)
        priorSn = grantor.kever.sn

        # A truthy bare grant requires _sign to create the grantor's KEL anchor.
        grantExn, grantAtc = ipexGrant(hab=grantor,
                                       recp=recipient.pre,
                                       message="Establishment-only anchored grant",
                                       origin=acdc,
                                       ax=[True])

        # EO makes the newly accepted anchor a rotation at the next sequence number.
        anchor = grantor.kever.serder
        assert anchor.ilk == Ilks.rot
        assert anchor.sn == priorSn + 1

        # The rotation must commit to this exact grant rather than the ACDC SAID.
        assert any(seal.get("d") == grantExn.said for seal in anchor.seals)

        # First parse without dispatch so the generated attachment groups are inspectable.
        result = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(grantExn.raw) + grantAtc,
            framed=False,
            processive=False)[0]

        # SealSource identifies the rotation that carries the grant commitment.
        assert len(result.sscs) == 1
        number, diger = result.sscs[0]
        assert number.sn == anchor.sn
        assert diger.qb64 == anchor.said

        # Signing happens after rotation, so the EXN signature uses the new lastEst.
        assert len(result.tsgs) == 1
        prefixer, number, diger, _ = result.tsgs[0]
        assert prefixer.qb64 == grantor.pre
        assert number.sn == anchor.sn
        assert diger.qb64 == anchor.said

        # Finally dispatch the stream to prove the V2 handler accepts this proof.
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)
        ims = bytearray(grantExn.raw) + grantAtc
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
        assert ims == bytearray()
        assert hby.db.exns.get(keys=(grantExn.said,)) is not None


def test_ipex_v2_rejects_anchor_before_current_establishment():
    """A source event before the sender's current lastEst is stale."""
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    with (openHby(name="ipex-v2-stale-anchor",
                  base="test",
                  version=Vrsn_2_0) as hby,
          openCF(name="ipex-v2-stale-anchor", base="test", temp=True) as cf):
        grantor = hby.makeHab(name="grantor")
        recipient = hby.makeHab(name="recipient")
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", role="member"),
                       iseaid=recipient.pre)

        # The builder creates an interaction after the current establishment
        # event and points the grant's source couple at that interaction.
        grantExn, grantAtc = ipexGrant(hab=grantor,
                                       recp=recipient.pre,
                                       message="Anchor predates rotation",
                                       origin=acdc,
                                       ax=[True])
        parsed = Parser(version=Vrsn_2_0).parse(
            ims=bytearray(grantExn.raw) + grantAtc,
            framed=False,
            processive=False)[0]
        anchorSn = parsed.sscs[0][0].sn

        # Rotating before first delivery advances lastEst beyond the event that
        # anchored the grant, making that source reference stale.
        grantor.rotate(gvrsn=Vrsn_2_0)
        assert anchorSn < grantor.kever.lastEst.s

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)
        cf.put(kramConfig)
        kvy = Kevery(db=hby.db,
                     lax=False,
                     local=False,
                     kramer=Kramer(db=hby.db, cf=cf),
                     exc=exc)

        # KRAM can authenticate the historical seal, but IPEX must reject it
        # because it is no longer based on the current sender key state.
        ims = bytearray(grantExn.raw) + grantAtc
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(grantExn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_anchored_flows_through_kram(fakeHelpingClock):
    """Two parties exchange anchored IPEX messages through their own KRAMs."""
    # Enable KRAM so each receiving party applies replay and timing checks before
    # handing an authenticated EXN to its local IPEX behavior.
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            # Use the wildcard timing policy because this test exercises several
            # IPEX routes and is concerned with valid, current messages.
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }
    # Keep all generated message timestamps deterministic and strictly ordered.
    clock = fakeHelpingClock

    # Give each party an independent database so no KEL or EXN evidence is
    # available to the other party unless this test explicitly transfers it.
    with (openHby(name="ipex-v2-anchored-kram-grantor",
                  base="test",
                  version=Vrsn_2_0) as grantorHby,
          openHby(name="ipex-v2-anchored-kram-applicant",
                  base="test",
                  version=Vrsn_2_0) as applicantHby):
        # The grantor controls the credential and sends offer/grant messages.
        grantor = grantorHby.makeHab(name="grantor")
        # The applicant requests, agrees to, and admits the disclosure.
        applicant = applicantHby.makeHab(name="applicant")

        # Build one non-registry ACDC so this test isolates direct KEL anchoring
        # and does not depend on the separate TEL-evidence workflow.
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=applicant.pre)
        # Reuse the generated schema SAID in each apply/offer disclosure request.
        schema = acdc.sad["s"]["$id"]
        # Request the root of the one-node DAG without selecting extra fields.
        dp = dict(dp=[[[schema, "/", []]]])

        # Install an inbound IPEX handler and notification recorder for the
        # grantor's side of the exchange.
        grantorRecorder = Recorder()
        grantorExc = Exchanger(hby=grantorHby, handlers=[])
        loadHandlers(hby=grantorHby, exc=grantorExc, notifier=grantorRecorder)

        # Install a separate inbound IPEX handler and recorder for the applicant.
        applicantRecorder = Recorder()
        applicantExc = Exchanger(hby=applicantHby, handlers=[])
        loadHandlers(hby=applicantHby, exc=applicantExc, notifier=applicantRecorder)

        # These KEL-only processors model each party learning the other party's
        # public key-event history before authenticating an inbound EXN.
        grantorRemoteKvy = Kevery(db=grantorHby.db, lax=False, local=False)
        applicantRemoteKvy = Kevery(db=applicantHby.db, lax=False, local=False)

        # Each Habery gets its own KRAM configuration and therefore maintains its
        # own replay/timing state for messages received by that party.
        with (openCF(name="ipex-v2-anchored-kram-grantor",
                     base="test", temp=True) as grantorCf,
              openCF(name="ipex-v2-anchored-kram-applicant",
                     base="test", temp=True) as applicantCf):
            # Store the same policy independently for each participant.
            grantorCf.put(kramConfig)
            applicantCf.put(kramConfig)

            # A sender first processes its own outbound EXN so its private
            # database contains the prior when a response later comes back.
            grantorSelfExc = Exchanger(hby=grantorHby, handlers=[])
            applicantSelfExc = Exchanger(hby=applicantHby, handlers=[])
            grantorSelfKvy = Kevery(db=grantorHby.db,
                                    lax=False,
                                    local=False,
                                    kramer=Kramer(db=grantorHby.db, cf=grantorCf),
                                    exc=grantorSelfExc)
            applicantSelfKvy = Kevery(db=applicantHby.db,
                                      lax=False,
                                      local=False,
                                      kramer=Kramer(db=applicantHby.db, cf=applicantCf),
                                      exc=applicantSelfExc)

            # These are the real inbound pipelines: KRAM authenticates and checks
            # the message, then the party's IPEX handler validates the workflow.
            grantorInboundKvy = Kevery(db=grantorHby.db,
                                       lax=False,
                                       local=False,
                                       kramer=Kramer(db=grantorHby.db, cf=grantorCf),
                                       exc=grantorExc)
            applicantInboundKvy = Kevery(db=applicantHby.db,
                                         lax=False,
                                         local=False,
                                         kramer=Kramer(db=applicantHby.db, cf=applicantCf),
                                         exc=applicantExc)

            # Track the last KEL sequence number transferred in each direction so
            # every newly created rotation or interaction is published once.
            synced = {
                (grantor.pre, applicant.pre): -1,
                (applicant.pre, grantor.pre): -1,
            }

            # Map the sender AID to its local-send pipeline and the counterparty's
            # independent receive/KEL pipelines.
            pipelines = {
                grantor.pre: (grantorSelfKvy, applicantHby, applicant,
                              applicantRemoteKvy, applicantInboundKvy),
                applicant.pre: (applicantSelfKvy, grantorHby, grantor,
                                 grantorRemoteKvy, grantorInboundKvy),
            }

            def publishKel(sender, receiver, remoteKvy):
                """Transfer every new sender KEL event to the receiving party."""
                # Resume after the last event already delivered in this direction.
                first = synced[(sender.pre, receiver.pre)] + 1
                # Include the current event because an anchored builder may just
                # have appended the interaction that seals the EXN being sent.
                for sn in range(first, sender.kever.sn + 1):
                    # Clone the sender's event with its controller signatures.
                    event = sender.msgOwnEvent(sn=sn,
                                               framed=True,
                                               gvrsn=Vrsn_2_0)
                    # Ingest that public event into the counterparty's KEL.
                    ims = bytearray(event)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=remoteKvy)
                    # A fully consumed stream proves the event parsed successfully.
                    assert ims == bytearray()
                # Remember the new boundary for the next message in this direction.
                synced[(sender.pre, receiver.pre)] = sender.kever.sn

            def receive(exn, atc, sender):
                """Record an outbound EXN, transfer evidence, and receive it."""
                # Resolve the two independent pipelines from the actual sender.
                senderKvy, receiverHby, receiver, remoteKvy, receiverKvy = (
                    pipelines[sender.pre]
                )
                # Combine the EXN body with signatures, source couples, and nests.
                msg = bytearray(exn.raw) + atc
                # Parse a non-processive copy so assertions can inspect attachments
                # without mutating either party's database.
                result = Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(msg),
                    framed=False,
                    processive=False)[0]

                # Persist the outbound EXN locally so a later inbound reply can
                # resolve this message as its prior in the sender's own database.
                localIms = bytearray(msg)
                Parser(version=Vrsn_2_0).parse(ims=localIms, kvy=senderKvy)
                assert localIms == bytearray()

                # Publish the sender's KEL through the event that may anchor this
                # EXN before the counterparty attempts source-seal verification.
                publishKel(sender=sender, receiver=receiver, remoteKvy=remoteKvy)

                # Deliver the same wire message to the counterparty's KRAM-enabled
                # inbound pipeline, which dispatches it to that party's handler.
                inboundIms = bytearray(msg)
                Parser(version=Vrsn_2_0).parse(ims=inboundIms, kvy=receiverKvy)
                assert inboundIms == bytearray()
                # Successful IPEX verification must persist the EXN remotely.
                assert receiverHby.db.exns.get(keys=(exn.said,)) is not None
                return result

            # The applicant opens the full five-message flow and requests that
            # the later binding messages be anchored (`ax=[True]`).
            applyExn, applyAtc = ipexApply(hab=applicant,
                                           recp=grantor.pre,
                                           message="Request anchored disclosure",
                                           modifiers=dp,
                                           dt=helping.nowIso8601(),
                                           ax=[True])
            # Apply negotiates anchoring but does not itself make a commitment.
            assert receive(applyExn, applyAtc, applicant).sscs == []

            # Give the offer a distinct timestamp within the same KRAM thread.
            clock.advance(milliseconds=1)
            # The grantor echoes the applicant's anchoring requirement.
            offerExn, offerAtc = ipexOffer(hab=grantor,
                                           message="Offer anchored disclosure",
                                           origin=acdc,
                                           apply=applyExn,
                                           dt=helping.nowIso8601(),
                                           ax=[True])
            # Offer also negotiates terms and therefore carries no source couple.
            assert receive(offerExn, offerAtc, grantor).sscs == []

            # Advance before the applicant creates its binding response.
            clock.advance(milliseconds=1)
            # Agree inherits truthy ax from the offer and anchors its own SAID in
            # a new event in the applicant's KEL.
            agreeExn, agreeAtc = ipexAgree(hab=applicant,
                                           message="Agree to anchored disclosure",
                                           offer=offerExn,
                                           dt=helping.nowIso8601())
            # The attached source couple identifies that applicant KEL event.
            assert len(receive(agreeExn, agreeAtc, applicant).sscs) == 1

            # Keep grant later than agree for KRAM's monotonic timing checks.
            clock.advance(milliseconds=1)
            # Grant discloses the ACDC and anchors the grantor's binding response.
            grantExn, grantAtc = ipexGrant(hab=grantor,
                                           recp=applicant.pre,
                                           message="Grant anchored disclosure",
                                           origin=acdc,
                                           agree=agreeExn,
                                           dt=helping.nowIso8601(),
                                           ax=[True])
            # Retain the parsed source couple for the later round-trip comparison.
            grantResult = receive(grantExn, grantAtc, grantor)
            assert len(grantResult.sscs) == 1

            # Advance before the final applicant response.
            clock.advance(milliseconds=1)
            # Admit inherits truthy ax and anchors acceptance in the applicant KEL.
            admitExn, admitAtc = ipexAdmit(hab=applicant,
                                           message="Admit anchored disclosure",
                                           grant=grantExn,
                                           dt=helping.nowIso8601())
            assert len(receive(admitExn, admitAtc, applicant).sscs) == 1

            # The applicant, as receiver of the grant, must retain its source
            # seal in the durable exchange-evidence store under the grantor.
            storedSources = applicantHby.db.ests.get(
                keys=(grantExn.said, grantor.pre))
            assert len(storedSources) == 1
            # Rebuild the accepted grant from the applicant's independent store.
            serialized = serializeMessage(applicantHby, grantExn.said, framed=True)
            # Parse the rebuilt wire message without dispatching it again.
            roundTrip = Parser(version=Vrsn_2_0).parse(
                ims=bytearray(serialized),
                framed=True,
                processive=False)[0]
            # Durable replay makes the source couple's implied sender explicit.
            assert len(roundTrip.ssts) == 1
            prefixer, number, diger = roundTrip.ssts[0]
            assert prefixer.qb64 == grantor.pre
            assert number.sn == grantResult.sscs[0][0].sn
            assert diger.qb64 == grantResult.sscs[0][1].qb64

            # Establish fresh current key states before starting another
            # signature-only negotiation after the prior flow's interactions.
            applicant.rotate(gvrsn=Vrsn_2_0)
            grantor.rotate(gvrsn=Vrsn_2_0)
            # Start a new transaction after both rotations.
            clock.advance(milliseconds=1)
            # The applicant opens a direct apply-to-grant path.
            directApply, directApplyAtc = ipexApply(hab=applicant,
                                                     recp=grantor.pre,
                                                     message="Request a direct anchored grant",
                                                     modifiers=dp,
                                                     dt=helping.nowIso8601(),
                                                     ax=[True])
            receive(directApply, directApplyAtc, applicant)

            # Place the direct grant after its apply.
            clock.advance(milliseconds=1)
            # The grantor skips offer/agree and links grant directly to apply.
            directGrant, directGrantAtc = ipexGrant(hab=grantor,
                                                     recp=applicant.pre,
                                                     message="Direct anchored grant",
                                                     origin=acdc,
                                                     apply=directApply,
                                                     dt=helping.nowIso8601(),
                                                     ax=[True])
            # The wire-level prior must be the direct apply's SAID.
            assert directGrant.ked["p"] == directApply.said
            # A truthy direct grant is binding and therefore carries one anchor.
            assert len(receive(directGrant, directGrantAtc, grantor).sscs) == 1

            # Place admit after its direct grant.
            clock.advance(milliseconds=1)
            # The applicant accepts the direct grant and echoes truthy ax.
            directAdmit, directAdmitAtc = ipexAdmit(hab=applicant,
                                                     message="Admit direct anchored grant",
                                                     grant=directGrant,
                                                     dt=helping.nowIso8601())
            assert directAdmit.ked["a"]["ax"] == [True]
            assert len(receive(directAdmit, directAdmitAtc, applicant).sscs) == 1

            # ax=False makes anchoring optional, so a valid extra source couple
            # remains acceptable even though the builder does not create one.
            clock.advance(milliseconds=1)
            # Build the optional grant body while discarding its original,
            # signature-only attachment stream.
            optional, _ = ipexGrant(hab=grantor,
                                     recp=applicant.pre,
                                     message="Optionally anchored grant",
                                     origin=acdc,
                                     dt=helping.nowIso8601(),
                                     ax=[False])
            # Manually create a valid grantor interaction that seals this EXN.
            anchor = _serder(grantor.interact(data=[dict(d=optional.said)],
                                               gvrsn=Vrsn_2_0))
            # Sign the unchanged EXN body with the grantor's current key state.
            sigers = grantor.sign(ser=optional.raw, indexed=True)
            # Construct the transferable signature group used by KRAM.
            tsgs = [(grantor.kever.prefixer,
                     Number(sn=grantor.kever.lastEst.s),
                     Diger(qb64=grantor.kever.lastEst.d),
                     sigers)]
            # Package the signature, optional source couple, and disclosed ACDC.
            optionalMsg = messagize(serder=optional,
                                     tsgs=tsgs,
                                     bonds=SealSource(s=anchor.snh, d=anchor.said),
                                     nests=[_nest(acdc)],
                                     framed=False,
                                     gvrsn=Vrsn_2_0)
            # `receive` expects only the attachment bytes after the EXN body.
            optionalAtc = bytearray(optionalMsg[optional.size:])
            optionalResult = receive(optional, optionalAtc, grantor)
            # Optional means an anchor is allowed, not that it must be absent.
            assert len(optionalResult.sscs) == 1

            # Rotate both parties before exercising the independent offer-first
            # flow so its signature state is independent of earlier interactions.
            applicant.rotate(gvrsn=Vrsn_2_0)
            grantor.rotate(gvrsn=Vrsn_2_0)
            clock.advance(milliseconds=1)
            # Offer opens this transaction, so it has no prior SAID.
            firstOffer, firstOfferAtc = ipexOffer(
                hab=grantor,
                recp=applicant.pre,
                message="Anchored offer-first exchange",
                origin=acdc,
                modifiers=dp,
                dt=helping.nowIso8601(),
                ax=[True])
            assert firstOffer.ked["p"] == ""
            # A bare offer negotiates anchoring but is not itself anchored.
            assert receive(firstOffer, firstOfferAtc, grantor).sscs == []

            # Advance before the applicant's binding agreement.
            clock.advance(milliseconds=1)
            # Agree links to the bare offer and creates an applicant KEL anchor.
            firstAgree, firstAgreeAtc = ipexAgree(
                hab=applicant,
                message="Agree to offer-first exchange",
                offer=firstOffer,
                dt=helping.nowIso8601())
            assert len(receive(firstAgree, firstAgreeAtc, applicant).sscs) == 1

            # Advance before the grantor discloses the credential.
            clock.advance(milliseconds=1)
            # Grant links to agree and commits the grantor to the disclosure.
            offerFirstGrant, offerFirstGrantAtc = ipexGrant(
                hab=grantor,
                recp=applicant.pre,
                message="Grant offer-first exchange",
                origin=acdc,
                agree=firstAgree,
                dt=helping.nowIso8601(),
                ax=[True])
            offerFirstGrantResult = receive(offerFirstGrant,
                                            offerFirstGrantAtc,
                                            grantor)
            assert len(offerFirstGrantResult.sscs) == 1

            # Advance before the applicant's final acceptance.
            clock.advance(milliseconds=1)
            # Admit links to the offer-first grant and anchors acceptance.
            offerFirstAdmit, offerFirstAdmitAtc = ipexAdmit(
                hab=applicant,
                message="Admit offer-first exchange",
                grant=offerFirstGrant,
                dt=helping.nowIso8601())
            offerFirstAdmitResult = receive(offerFirstAdmit,
                                            offerFirstAdmitAtc,
                                            applicant)
            assert len(offerFirstAdmitResult.sscs) == 1

            # Rotate again before the final independent grant-first transaction.
            applicant.rotate(gvrsn=Vrsn_2_0)
            grantor.rotate(gvrsn=Vrsn_2_0)
            clock.advance(milliseconds=1)
            # A bare grant both opens the thread and makes a binding disclosure,
            # so unlike a bare offer it immediately requires a source couple.
            bareGrant, bareGrantAtc = ipexGrant(
                hab=grantor,
                recp=applicant.pre,
                message="Anchored grant-first exchange",
                origin=acdc,
                dt=helping.nowIso8601(),
                ax=[True])
            assert bareGrant.ked["p"] == ""
            assert len(receive(bareGrant, bareGrantAtc, grantor).sscs) == 1

            # Advance before the applicant admits the bare grant.
            clock.advance(milliseconds=1)
            # Admit echoes truthy ax and records the applicant's acceptance anchor.
            bareAdmit, bareAdmitAtc = ipexAdmit(
                hab=applicant,
                message="Admit grant-first exchange",
                grant=bareGrant,
                dt=helping.nowIso8601())
            assert len(receive(bareAdmit, bareAdmitAtc, applicant).sscs) == 1

            # Prove the grantor handler saw only messages sent by the applicant.
            assert [item["r"] for item in grantorRecorder.items] == [
                "/exn/ipex/apply", "/exn/ipex/agree", "/exn/ipex/admit",
                "/exn/ipex/apply", "/exn/ipex/admit", "/exn/ipex/agree",
                "/exn/ipex/admit", "/exn/ipex/admit",
            ]
            # Prove the applicant handler saw only messages sent by the grantor.
            assert [item["r"] for item in applicantRecorder.items] == [
                "/exn/ipex/offer", "/exn/ipex/grant", "/exn/ipex/grant",
                "/exn/ipex/grant", "/exn/ipex/offer", "/exn/ipex/grant",
                "/exn/ipex/grant",
            ]


def test_ipex_v2_anchored_grant_waits_for_sender_kel_event(fakeHelpingClock):
    """An anchored grant remains retryable when its source event arrives later."""
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    with (openHby(name="ipex-v2-anchor-order-issuer",
                  base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="ipex-v2-anchor-order-recipient",
                  base="test",
                  version=Vrsn_2_0) as recipientHby):
        issuerHab = issuerHby.makeHab(name="issuer")
        recipientHab = recipientHby.makeHab(name="recipient")
        acdc = acdcmap(israid=issuerHab.pre,
                       attribute=dict(d="", role="member"),
                       iseaid=recipientHab.pre)

        remoteKvy = Kevery(db=recipientHby.db, lax=False, local=False)
        issuerInception = issuerHab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerInception), kvy=remoteKvy)

        recorder = Recorder()
        exc = Exchanger(hby=recipientHby, handlers=[])
        loadHandlers(hby=recipientHby, exc=exc, notifier=recorder)

        with openCF(name="ipex-v2-anchor-order", base="test", temp=True) as cf:
            cf.put(kramConfig)
            kvy = Kevery(db=recipientHby.db,
                         lax=False,
                         local=False,
                         kramer=Kramer(db=recipientHby.db, cf=cf),
                         exc=exc)

            grantExn, grantAtc = ipexGrant(hab=issuerHab,
                                           recp=recipientHab.pre,
                                           message="Anchor will arrive later",
                                           origin=acdc,
                                           dt=helping.nowIso8601(),
                                           ax=[True])
            anchorSn = issuerHab.kever.sn

            # Preserve the original wire message so retrieval can trigger an
            # unchanged redelivery after KRAM rejects the first attempt.
            grantMsg = bytearray(grantExn.raw) + grantAtc
            ims = bytearray(grantMsg)
            Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)

            assert ims == bytearray()
            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
            # KRAM owns missing sender-key-state handling, so the message has
            # not reached Exchanger or either of its stores yet.
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is None
            assert recipientHby.db.ests.get(
                keys=(grantExn.said, issuerHab.pre)) == []
            assert list(kvy.cues) == [
                dict(kin="keystate", aid=issuerHab.pre, sn=anchorSn),
            ]
            assert list(exc.cues) == []

            # Simulate fulfillment of KRAM's cue by importing the exact event
            # named by the sender seal reference into the recipient's KEL.
            anchor = issuerHab.msgOwnEvent(sn=anchorSn, framed=True, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(anchor), kvy=remoteKvy)
            kvy.cues.clear()

            # Redeliver the same grant after its referenced key state becomes
            # available; KRAM can now authenticate and dispatch it.
            ims = bytearray(grantMsg)
            Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)

            assert ims == bytearray()
            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is not None
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is None
            assert len(recipientHby.db.ests.get(
                keys=(grantExn.said, issuerHab.pre))) == 1
            assert recorder.items == [
                {"r": "/exn/ipex/grant", "d": grantExn.said,
                 "m": "Anchor will arrive later"},
            ]
            assert list(exc.cues) == [
                dict(kin="saved", said=grantExn.said),
            ]


def test_ipex_v2_required_anchors_fail_closed_through_kram(fakeHelpingClock):
    """Required binding messages reject missing, incorrect, or unechoed anchors."""
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    with openHby(name="ipex-v2-ax-fail-closed",
                 base="test",
                 version=Vrsn_2_0) as hby:
        # Assign the IPEX roles and keep a third AID for the non-sender proof case.
        grantor = hby.makeHab(name="grantor")
        applicant = hby.makeHab(name="applicant")
        other = hby.makeHab(name="other")

        # Every forged grant below discloses this same valid single-node DAG.
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=applicant.pre)

        # Route authenticated messages into the real V2 IPEX handlers.
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        with openCF(name="ipex-v2-ax-fail-closed", base="test", temp=True) as cf:
            # Enable KRAM so the tests cover authentication before IPEX verification.
            cf.put(kramConfig)
            kvy = Kevery(db=hby.db,
                         lax=False,
                         local=False,
                         kramer=Kramer(db=hby.db, cf=cf),
                         exc=exc)

            def forged(exn, bond=None, hab=grantor):
                """Sign an exchange with a chosen sender source reference."""
                # Give the malformed IPEX body a valid signature from its declared sender.
                sigers = hab.sign(ser=exn.raw, indexed=True)

                # Reference the sender's current establishment state for that signature.
                tsgs = [(hab.kever.prefixer,
                         Number(sn=hab.kever.lastEst.s),
                         Diger(qb64=hab.kever.lastEst.d),
                         sigers)]

                # Grant verification still needs the disclosed ACDC; replies carry no nests.
                nests = [_nest(acdc)] if exn.ked["r"] == "/ipex/grant" else None

                # Insert the selected bond independently of the valid signature material.
                return messagize(serder=exn,
                                  tsgs=tsgs,
                                  bonds=bond,
                                  nests=nests,
                                  framed=False,
                                  gvrsn=Vrsn_2_0)

            def deliver(msg):
                """Deliver one complete exchange through KRAM."""
                # Parser authenticates through KRAM and then invokes Exchanger/IPEX.
                ims = bytearray(msg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)

                # Consuming the stream proves parsing completed even when IPEX rejects it.
                assert ims == bytearray()

            def reject(exn, msg):
                """Deliver a forged exchange and assert it is not accepted."""
                deliver(msg)

                # A permanent semantic failure must be neither saved nor retryably escrowed.
                assert hby.db.exns.get(keys=(exn.said,)) is None
                assert hby.db.epse.get(keys=(exn.said,)) is None

            def response(verb, prior, message, echo=True):
                """Create an inbound binding reply with an optional ax echo."""
                # Omit ax only for the missing-echo cases; otherwise explicitly require it.
                attrs = dict(m=message)
                if echo:
                    attrs["ax"] = [True]

                # Preserve the prior's participants and transaction identifier.
                return exchange(sender=applicant.pre,
                                receiver=grantor.pre,
                                xid=prior.ked["x"],
                                prior=prior.said,
                                route=f"/ipex/{verb}",
                                stamp=helping.nowIso8601(),
                                attributes=attrs,
                                pvrsn=Vrsn_2_0,
                                gvrsn=Vrsn_2_0,
                                kind=applicant.kever.serder.kind)

            # Case 1: a truthy grant with only its valid signature lacks required KEL proof.
            missing, _ = ipexGrant(hab=grantor,
                                    recp=applicant.pre,
                                    message="Missing source couple",
                                    origin=acdc,
                                    dt=helping.nowIso8601(),
                                    ax=[True])
            grantor.rotate(gvrsn=Vrsn_2_0)
            reject(missing, forged(missing))

            # Case 2: the source sequence exists, but the supplied digest names no event there.
            badReference, _ = ipexGrant(hab=grantor,
                                         recp=applicant.pre,
                                         message="Wrong event reference",
                                         origin=acdc,
                                         dt=helping.nowIso8601(),
                                         ax=[True])
            grantor.rotate(gvrsn=Vrsn_2_0)
            wrong = SealSource(s=grantor.kever.serder.snh,
                               d=Diger(ser=b"not the referenced event").qb64)
            reject(badReference, forged(badReference, wrong))

            # Case 3: the referenced event exists but does not seal this grant's SAID.
            unsealedEvent, _ = ipexGrant(hab=grantor,
                                          recp=applicant.pre,
                                          message="Event omits the exchange SAID",
                                          origin=acdc,
                                          dt=helping.nowIso8601(),
                                          ax=[True])
            grantor.rotate(gvrsn=Vrsn_2_0)
            noDigest = SealSource(s=grantor.kever.serder.snh,
                                  d=grantor.kever.serder.said)
            reject(unsealedEvent, forged(unsealedEvent, noDigest))

            # Case 4: a valid event from another AID cannot satisfy the sender-KEL rule.
            nonSender, _ = ipexGrant(hab=grantor,
                                      recp=applicant.pre,
                                      message="Non-sender source triple",
                                      origin=acdc,
                                      dt=helping.nowIso8601(),
                                      ax=[True])
            grantor.rotate(gvrsn=Vrsn_2_0)
            otherAnchor = _serder(other.interact(data=[dict(d=nonSender.said)],
                                                  gvrsn=Vrsn_2_0))
            triple = SealEvent(i=other.pre,
                               s=otherAnchor.snh,
                               d=otherAnchor.said)
            reject(nonSender, forged(nonSender, triple))

            # Persist a truthy offer so each forged agree has a valid negotiated prior.
            fakeHelpingClock.advance(milliseconds=1)
            schema = acdc.sad["s"]["$id"]
            offerExn, offerAtc = ipexOffer(
                hab=grantor,
                recp=applicant.pre,
                message="Anchored offer",
                origin=acdc,
                modifiers=dict(dp=[[[schema, "/", []]]]),
                dt=helping.nowIso8601(),
                ax=[True])
            deliver(bytearray(offerExn.raw) + offerAtc)
            assert hby.db.exns.get(keys=(offerExn.said,)) is not None

            # Persist a truthy bare grant so each forged admit has a valid prior.
            fakeHelpingClock.advance(milliseconds=1)
            grantExn, grantAtc = ipexGrant(
                hab=grantor,
                recp=applicant.pre,
                message="Anchored grant",
                origin=acdc,
                dt=helping.nowIso8601(),
                ax=[True])
            deliver(bytearray(grantExn.raw) + grantAtc)
            assert hby.db.exns.get(keys=(grantExn.said,)) is not None

            # Apply the same three fail-closed checks to disclosee agree and admit replies.
            for verb, prior in (("agree", offerExn), ("admit", grantExn)):
                # A signature authenticates the sender but cannot replace the required anchor.
                fakeHelpingClock.advance(milliseconds=1)
                missingSource = response(verb, prior, f"{verb} missing source")
                reject(missingSource, forged(missingSource, hab=applicant))

                # Point at a real applicant event that seals the prior, not this reply.
                fakeHelpingClock.advance(milliseconds=1)
                wrongSource = response(verb, prior, f"{verb} wrong source")
                unrelated = _serder(applicant.interact(
                    data=[dict(d=prior.said)], gvrsn=Vrsn_2_0))
                bond = SealSource(s=unrelated.snh, d=unrelated.said)
                reject(wrongSource, forged(wrongSource, bond, hab=applicant))

                # Supply a valid anchor so rejection can only be caused by the omitted ax echo.
                fakeHelpingClock.advance(milliseconds=1)
                missingEcho = response(verb, prior, f"{verb} missing echo", echo=False)
                anchor = _serder(applicant.interact(
                    data=[dict(d=missingEcho.said)], gvrsn=Vrsn_2_0))
                bond = SealSource(s=anchor.snh, d=anchor.said)
                reject(missingEcho, forged(missingEcho, bond, hab=applicant))

            # Only the two valid priors should have reached the notification handler.
            assert [(item["r"], item["m"]) for item in recorder.items] == [
                ("/exn/ipex/offer", "Anchored offer"),
                ("/exn/ipex/grant", "Anchored grant"),
            ]


def test_ipex_v2_rejects_reply_only_ax_invention_through_kram(fakeHelpingClock):
    """Prior-linked replies cannot invent anchoring when their prior is false."""
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    with openHby(name="ipex-v2-ax-invention",
                 base="test",
                 version=Vrsn_2_0) as hby:
        grantor = hby.makeHab(name="grantor")
        applicant = hby.makeHab(name="applicant")
        acdc = acdcmap(israid=grantor.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=applicant.pre)
        schema = acdc.sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        with openCF(name="ipex-v2-ax-invention", base="test", temp=True) as cf:
            cf.put(kramConfig)
            kvy = Kevery(db=hby.db,
                         lax=False,
                         local=False,
                         kramer=Kramer(db=hby.db, cf=cf),
                         exc=exc)

            def deliver(msg):
                """Deliver one complete message through KRAM."""
                ims = bytearray(msg)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                assert ims == bytearray()

            def anchoredReply(exn, hab=applicant, nests=None):
                """Attach the sender's valid source couple and signature."""
                anchor = _serder(hab.interact(data=[dict(d=exn.said)],
                                               gvrsn=Vrsn_2_0))
                sigers = hab.sign(ser=exn.raw, indexed=True)
                tsgs = [(hab.kever.prefixer,
                         Number(sn=hab.kever.lastEst.s),
                         Diger(qb64=hab.kever.lastEst.d),
                         sigers)]
                return messagize(serder=exn,
                                  tsgs=tsgs,
                                  bonds=SealSource(s=anchor.snh, d=anchor.said),
                                  nests=nests,
                                  framed=False,
                                  gvrsn=Vrsn_2_0)

            offerExn, offerAtc = ipexOffer(hab=grantor,
                                           recp=applicant.pre,
                                           message="Optional offer",
                                           origin=acdc,
                                           modifiers=dict(dp=[[[schema, "/", []]]]),
                                           dt=helping.nowIso8601(),
                                           ax=[False])
            deliver(bytearray(offerExn.raw) + offerAtc)
            assert hby.db.exns.get(keys=(offerExn.said,)) is not None

            inventedAgree = exchange(sender=applicant.pre,
                                      receiver=grantor.pre,
                                      xid=offerExn.ked["x"],
                                      prior=offerExn.said,
                                      route="/ipex/agree",
                                      stamp=helping.nowIso8601(),
                                      attributes=dict(m="Invented agree", ax=[True]),
                                      pvrsn=Vrsn_2_0,
                                      gvrsn=Vrsn_2_0,
                                      kind=applicant.kever.serder.kind)
            deliver(anchoredReply(inventedAgree))
            assert hby.db.exns.get(keys=(inventedAgree.said,)) is None

            fakeHelpingClock.advance(milliseconds=1)
            applyExn, applyAtc = ipexApply(hab=applicant,
                                           recp=grantor.pre,
                                           message="Optional apply",
                                           modifiers=dict(dp=[[[schema, "/", []]]]),
                                           dt=helping.nowIso8601(),
                                           ax=[False])
            deliver(bytearray(applyExn.raw) + applyAtc)
            assert hby.db.exns.get(keys=(applyExn.said,)) is not None

            fakeHelpingClock.advance(milliseconds=1)
            inventedGrant = exchange(sender=grantor.pre,
                                     receiver=applicant.pre,
                                     xid=applyExn.ked["x"],
                                     prior=applyExn.said,
                                     route="/ipex/grant",
                                     stamp=helping.nowIso8601(),
                                     attributes=dict(m="Invented grant",
                                                     o=[acdc.said],
                                                     ax=[True]),
                                     pvrsn=Vrsn_2_0,
                                     gvrsn=Vrsn_2_0,
                                     kind=grantor.kever.serder.kind)
            deliver(anchoredReply(inventedGrant,
                                  hab=grantor,
                                  nests=[_nest(acdc)]))
            assert hby.db.exns.get(keys=(inventedGrant.said,)) is None

            grantExn, grantAtc = ipexGrant(hab=grantor,
                                           recp=applicant.pre,
                                           message="Optional grant",
                                           origin=acdc,
                                           dt=helping.nowIso8601(),
                                           ax=[False])
            deliver(bytearray(grantExn.raw) + grantAtc)
            assert hby.db.exns.get(keys=(grantExn.said,)) is not None

            inventedAdmit = exchange(sender=applicant.pre,
                                      receiver=grantor.pre,
                                      xid=grantExn.ked["x"],
                                      prior=grantExn.said,
                                      route="/ipex/admit",
                                      stamp=helping.nowIso8601(),
                                      attributes=dict(m="Invented admit", ax=[True]),
                                      pvrsn=Vrsn_2_0,
                                      gvrsn=Vrsn_2_0,
                                      kind=applicant.kever.serder.kind)
            deliver(anchoredReply(inventedAdmit))
            assert hby.db.exns.get(keys=(inventedAdmit.said,)) is None

            assert [(item["r"], item["m"]) for item in recorder.items] == [
                ("/exn/ipex/offer", "Optional offer"),
                ("/exn/ipex/apply", "Optional apply"),
                ("/exn/ipex/grant", "Optional grant"),
            ]


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
                      origin=rip,
                      modifiers=dict(dp=[[[acdc.sad["s"]["$id"], "/", []]]]))

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
                         edge=_edge("holder", child, op="E1E"),
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
                              edge=_edge("holder", offerChild, op="E1E"),
                              rule=origin.sad["r"])

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        applyExn, applyAtc = ipexApply(hab=verifier,
                                       recp=holder.pre,
                                       message="Please disclose the credential DAG",
                                       attrs=dict(role="member"),
                                       modifiers=dict(dp=[[[schema, "/", []],
                                                           [schema, "/e/holder/_/", []]]]))
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
                                              [schema, "/e/holder/_/", []]]]

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
        schema = origin.sad["s"]["$id"]

        # Build a syntactically valid offer body, then re-endorse it with an
        # invalid nested DAG that points at a TEL event instead of an ACDC node.
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=origin,
                           message="Here is the forged credential DAG",
                           modifiers=dict(dp=[[[schema, "/", []]]]))

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
                                                           [schema, "/e/department/_/", []]]]))
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
                                                 [schema, "/e/holder/_/", []]]]))

        ims = bytearray(exn.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(exn.said,)) is None
        assert recorder.items == []


def test_ipex_v2_accepts_grant_graph_shape_and_semantics():
    """Grant accepts valid edge-group shapes and valid leaf operator/schema semantics."""
    with openHby(name="ipex-v2-grant-graph-semantics",
                 base="test",
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        subject = hby.makeHab(name="subject")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        def assert_accepted(message, origin, artifacts):
            exn, atc = ipexGrant(hab=issuer,
                                 recp=subject.pre,
                                 message=message,
                                 origin=origin,
                                 artifacts=artifacts)
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()
            assert hby.db.exns.get(keys=(exn.said,)) is not None
            assert recorder.items[-1] == {"r": "/exn/ipex/grant",
                                          "d": exn.said,
                                          "m": message}

        # Case 1: an expanded edge section may carry its own nonce, and an edge
        # schema may name a different but still compatible schema that the far
        # node satisfies.
        schemaChild = acdcmap(israid=issuer.pre,
                              attribute=dict(d="", role="member"),
                              iseaid=issuer.pre)
        compatSchema = dict(schemaChild.sad["s"])
        compatSchema["title"] = "ACM Default Schema (compatible grant edge)"
        compatSchemer = Schemer(sed=compatSchema)
        hby.db.schema.pin(compatSchemer.said, compatSchemer)
        schemaOrigin = acdcmap(israid=issuer.pre,
                               attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                               edge=dict(d="",
                                         u=Noncer().qb64,
                                         holder=dict(d="",
                                                     n=schemaChild.said,
                                                     o="I2I",
                                                     s=compatSchemer.said)),
                               iseaid=subject.pre)
        assert_accepted("Here is the schema-pinned DAG",
                        schemaOrigin,
                        [schemaChild])

        # Case 2: the edge schema allows `s` on a nested edge group. IPEX
        # interprets that as one shared far-node schema pin for the group's
        # children unless a leaf provides its own `s`.
        groupedSchemaMember = acdcmap(israid=issuer.pre,
                                      attribute=dict(d="", role="member"),
                                      iseaid=issuer.pre)
        groupedSchemaStaff = acdcmap(israid=issuer.pre,
                                     attribute=dict(d="", role="staff"),
                                     iseaid=issuer.pre)
        groupedSchemaOrigin = acdcmap(israid=issuer.pre,
                                      attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                      edge=dict(d="",
                                                u=Noncer().qb64,
                                                reports=dict(d="",
                                                             s=compatSchemer.said,
                                                             member=dict(d="",
                                                                         n=groupedSchemaMember.said,
                                                                         o="I2I"),
                                                             staff=dict(d="",
                                                                        n=groupedSchemaStaff.said,
                                                                        o="I2I"))),
                                      iseaid=subject.pre)
        assert_accepted("Here is the grouped-schema DAG",
                        groupedSchemaOrigin,
                        [groupedSchemaMember, groupedSchemaStaff])

        # Case 3: a grouped OR succeeds when at least one child edge relation
        # is satisfied, instead of requiring every branch to pass.
        orMember = acdcmap(israid=issuer.pre,
                           attribute=dict(d="", role="member"),
                           iseaid=issuer.pre)
        orStaff = acdcmap(israid=issuer.pre,
                          attribute=dict(d="", department="kitchen"),
                          iseaid=subject.pre)
        groupedOrigin = acdcmap(israid=issuer.pre,
                                attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                edge=dict(d="",
                                          u=Noncer().qb64,
                                          either=dict(d="",
                                                      o="OR",
                                                      member=dict(d="", n=orMember.said, o="I2I"),
                                                      staff=dict(d="", n=orStaff.said, o="I2I"))),
                                iseaid=subject.pre)
        assert_accepted("Here is the grouped-OR DAG",
                        groupedOrigin,
                        [orMember, orStaff])

        # Case 4: a leaf edge may omit `o`. The V2 edge shape allows that, and
        # IPEX does not infer an I2I/NI2I default when the operator is absent.
        noOpChild = acdcmap(israid=issuer.pre,
                            attribute=dict(d="", role="member"),
                            iseaid=subject.pre)
        noOpOrigin = acdcmap(israid=issuer.pre,
                             attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                             edge=_edge("holder", noOpChild),
                             iseaid=subject.pre)
        assert_accepted("Here is the no-operator DAG",
                        noOpOrigin,
                        [noOpChild])


def test_ipex_v2_rejects_invalid_grant_graph_shape_and_semantics():
    """Grant rejects malformed graph closure and false leaf edge semantics."""
    with openHby(name="ipex-v2-bad-grant-graph-semantics",
                 base="test",
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        subject = hby.makeHab(name="subject")

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)
        handler = exc.routes["/ipex/grant"]

        baseChild = acdcmap(israid=issuer.pre,
                            attribute=dict(d="", role="member"),
                            iseaid=issuer.pre)
        incompatSchema = dict(baseChild.sad["s"])
        incompatSchema["title"] = "ACM Default Schema (incompatible grant edge)"
        incompatSchema["required"] = list(dict.fromkeys([*incompatSchema["required"], "z"]))
        incompatSchemer = Schemer(sed=incompatSchema)
        hby.db.schema.pin(incompatSchemer.said, incompatSchemer)

        def assert_rejected(message, origin, artifacts=None):
            before = len(recorder.items)
            exn, atc = ipexGrant(hab=issuer,
                                 recp=subject.pre,
                                 message=message,
                                 origin=origin,
                                 artifacts=artifacts)
            ims = bytearray(exn.raw)
            ims.extend(atc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()
            assert hby.db.exns.get(keys=(exn.said,)) is None
            assert len(recorder.items) == before

        # Missing referenced node: the walk is not closed.
        missingChild = acdcmap(israid=issuer.pre,
                               attribute=dict(d="", role="member"),
                               iseaid=issuer.pre)
        missingOrigin = acdcmap(israid=issuer.pre,
                                attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                edge=_edge("holder", missingChild),
                                iseaid=subject.pre)
        assert_rejected("Here is the incomplete DAG", missingOrigin)

        # Duplicate disclosed node: one DAG node must not appear twice.
        duplicateChild = acdcmap(israid=issuer.pre,
                                 attribute=dict(d="", role="member"),
                                 iseaid=issuer.pre)
        duplicateOrigin = acdcmap(israid=issuer.pre,
                                  attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                  edge=_edge("holder", duplicateChild),
                                  iseaid=subject.pre)
        assert_rejected("Here is the duplicated DAG",
                        duplicateOrigin,
                        [duplicateChild, duplicateChild])

        # Compacted edge section is not walkable.
        compactOrigin = acdcmap(israid=issuer.pre,
                                attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                iseaid=subject.pre)
        compactSad = dict(compactOrigin.sad)
        compactSad["e"] = regcept(israid=issuer.pre).said
        assert_rejected("Here is the compacted DAG",
                        type(compactOrigin)(sad=compactSad, makify=True))

        # Extra carried node must still be reachable from the origin.
        reachableChild = acdcmap(israid=issuer.pre,
                                 attribute=dict(d="", role="member"),
                                 iseaid=issuer.pre)
        extraChild = acdcmap(israid=issuer.pre,
                             attribute=dict(d="", department="kitchen"),
                             iseaid=subject.pre)
        extraOrigin = acdcmap(israid=issuer.pre,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              edge=_edge("holder", reachableChild),
                              iseaid=subject.pre)
        assert_rejected("Here is the overstuffed DAG",
                        extraOrigin,
                        [reachableChild, extraChild])

        # I2I requires the near issuer to equal the far issuee.
        wrongI2IChild = acdcmap(israid=issuer.pre,
                                attribute=dict(d="", role="member"),
                                iseaid=subject.pre)
        wrongI2IOrigin = acdcmap(israid=issuer.pre,
                                 attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                 edge=_edge("holder", wrongI2IChild, op="I2I"),
                                 iseaid=subject.pre)
        assert_rejected("Here is the I2I-violating DAG",
                        wrongI2IOrigin,
                        [wrongI2IChild])

        # E1E requires the near and far nodes to target the same issuee.
        wrongE1EChild = acdcmap(israid=issuer.pre,
                                attribute=dict(d="", department="kitchen"),
                                iseaid=issuer.pre)
        wrongE1EOrigin = acdcmap(israid=issuer.pre,
                                 attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                 edge=_edge("holder", wrongE1EChild, op="E1E"),
                                 iseaid=subject.pre)
        assert_rejected("Here is the E1E-violating DAG",
                        wrongE1EOrigin,
                        [wrongE1EChild])

        # Recognized but unevaluated operators are well-formed leaves whose
        # relation is unsatisfied, instead of malformed graph input.
        notChild = acdcmap(israid=issuer.pre,
                           attribute=dict(d="", role="member"),
                           iseaid=issuer.pre)
        notOrigin = acdcmap(israid=issuer.pre,
                            attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                            edge=_edge("holder", notChild, op="NOT"),
                            iseaid=subject.pre)
        assert_rejected("Here is the NOT-operator DAG",
                        notOrigin,
                        [notChild])
        assert handler._evaluateLeafEdge(notOrigin.sad["e"]["holder"],
                                         nodes={notChild.said: {"serder": notChild}},
                                         nserder=notOrigin,
                                         inheritedSchema=None) is False

        diChild = acdcmap(israid=issuer.pre,
                          attribute=dict(d="", role="member"),
                          iseaid=issuer.pre)
        diOrigin = acdcmap(israid=issuer.pre,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           edge=_edge("holder", diChild, op="DI2I"),
                           iseaid=subject.pre)
        assert_rejected("Here is the DI2I-operator DAG",
                        diOrigin,
                        [diChild])
        assert handler._evaluateLeafEdge(diOrigin.sad["e"]["holder"],
                                         nodes={diChild.said: {"serder": diChild}},
                                         nserder=diOrigin,
                                         inheritedSchema=None) is False

        # List-valued leaf operators are not supported
        listOpChild = acdcmap(israid=issuer.pre,
                              attribute=dict(d="", role="member"),
                              iseaid=issuer.pre)
        listOpOrigin = acdcmap(israid=issuer.pre,
                               attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                               edge=_edge("holder", listOpChild, op=["I2I"]),
                               iseaid=subject.pre)
        assert_rejected("Here is the list-valued leaf-operator DAG",
                        listOpOrigin,
                        [listOpChild])

        # Unknown edge operators are not supported
        bogusChild = acdcmap(israid=issuer.pre,
                             attribute=dict(d="", role="member"),
                             iseaid=issuer.pre)
        bogusOrigin = acdcmap(israid=issuer.pre,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              edge=_edge("holder", bogusChild, op="BOGUS"),
                              iseaid=subject.pre)
        assert_rejected("Here is the unknown-operator DAG",
                        bogusOrigin,
                        [bogusChild])

        # An OR group fails when none of its children satisfy the
        # disclosed relation constraints.
        orLeft = acdcmap(israid=issuer.pre,
                         attribute=dict(d="", role="member"),
                         iseaid=subject.pre)
        orRight = acdcmap(israid=issuer.pre,
                          attribute=dict(d="", department="kitchen"),
                          iseaid=subject.pre)
        badOrOrigin = acdcmap(israid=issuer.pre,
                              attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                              edge=dict(d="",
                                        u=Noncer().qb64,
                                        either=dict(d="",
                                                    o="OR",
                                                    member=dict(d="", n=orLeft.said, o="I2I"),
                                                    staff=dict(d="", n=orRight.said, o="I2I"))),
                              iseaid=subject.pre)
        assert_rejected("Here is the unsatisfied grouped-OR DAG",
                        badOrOrigin,
                        [orLeft, orRight])

        # A pinned edge schema must either match the far node's own schema or
        # be a different compatible schema that the far node still satisfies.
        badSchemaChild = acdcmap(israid=issuer.pre,
                                 attribute=dict(d="", role="member"),
                                 iseaid=issuer.pre)
        badSchemaOrigin = acdcmap(israid=issuer.pre,
                                  attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                                  edge=dict(d="",
                                            holder=dict(d="",
                                                        n=badSchemaChild.said,
                                                        o="I2I",
                                                        s=incompatSchemer.said)),
                                  iseaid=subject.pre)
        assert_rejected("Here is the incompatible-schema DAG",
                        badSchemaOrigin,
                        [badSchemaChild])


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
        endorser = hby.makeHab(name="endorser")
        cigarEndorser = hby.makeHab(name="cigar-endorser",
                                    transferable=False)
        registry = regcept(israid=hab.pre)
        acdc = acdcmap(israid=hab.pre,
                       attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                       iseaid=hab.pre)
        schema = acdc.sad["s"]["$id"]

        # Create recorder
        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        # Non-grant IPEX routes reject otherwise valid foreign evidence before
        # any durable exchange rows are written.
        rejectedApply, _ = ipexApply(
            hab=hab,
            recp=hab.pre,
            message="Foreign evidence is not allowed on apply",
            attrs=dict(role="member"),
            modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
        )

        def group(signer, serder):
            return (signer.kever.prefixer,
                    Number(sn=signer.kever.lastEst.s),
                    Diger(qb64=signer.kever.lastEst.d),
                    signer.sign(ser=serder.raw, indexed=True))

        exc.processEvent(rejectedApply,
                         tsgs=[group(hab, rejectedApply),
                               group(endorser, rejectedApply)])
        assert hby.db.exns.get(keys=(rejectedApply.said,)) is None
        assert list(hby.db.esigs.getTopItemIter(
            keys=(rejectedApply.said, ""))) == []
        assert recorder.items == []

        # Foreign last-establishment groups must still reach route policy
        # after the sender's signatures have accumulated in exchange escrow.
        partialSender = hby.makeHab(name="partial-sender", isith="2", icount=3)
        partialApply, _ = ipexApply(
            hab=partialSender, recp=hab.pre,
            message="Foreign evidence remains forbidden after escrow",
            attrs=dict(role="member"),
            modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
        )
        senderGroup = group(partialSender, partialApply)
        endorserGroup = group(endorser, partialApply)
        for index in (0, 1):
            with pytest.raises(MissingSignatureError):
                exc.processEvent(
                    partialApply,
                    tsgs=[(*senderGroup[:3], [senderGroup[3][index]])],
                    lsgs=[(endorser.kever.prefixer, endorserGroup[3])]
                         if index == 0 else [],
                )
        exc.processEscrow()
        assert hby.db.exns.get(keys=(partialApply.said,)) is None
        assert hby.db.epse.get(keys=(partialApply.said,)) is None
        assert recorder.items == []
        exc.cues.clear()

        rejectedCigarApply, _ = ipexApply(
            hab=hab,
            recp=hab.pre,
            message="Foreign cigar is not allowed on apply",
            attrs=dict(role="member"),
            modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
        )
        validForeignCigar = cigarEndorser.sign(
            ser=rejectedCigarApply.raw, indexed=False)
        exc.processEvent(rejectedCigarApply,
                         tsgs=[group(hab, rejectedCigarApply)],
                         cigars=validForeignCigar)
        assert hby.db.exns.get(keys=(rejectedCigarApply.said,)) is None
        assert hby.db.ecigs.get(keys=(rejectedCigarApply.said,)) == []

        invalidCigarApply, _ = ipexApply(
            hab=hab,
            recp=hab.pre,
            message="Invalid foreign cigar is not allowed on apply",
            attrs=dict(role="member"),
            modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
        )
        invalidForeignCigar = cigarEndorser.sign(
            ser=b"different exchange message", indexed=False)
        exc.processEvent(invalidCigarApply,
                         tsgs=[group(hab, invalidCigarApply)],
                         cigars=invalidForeignCigar)
        assert hby.db.exns.get(keys=(invalidCigarApply.said,)) is None
        assert hby.db.ecigs.get(keys=(invalidCigarApply.said,)) == []

        unresolvedApply, _ = ipexApply(
            hab=hab,
            recp=hab.pre,
            message="Unresolved foreign signer is not allowed on apply",
            attrs=dict(role="member"),
            modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
        )
        with pytest.raises(MissingSignatureError):
            exc.processEvent(unresolvedApply,
                             tsgs=[group(hab, unresolvedApply)],
                             ulgs=[endorser.kever.prefixer])
        assert hby.db.exns.get(keys=(unresolvedApply.said,)) is None
        assert list(hby.db.esigs.getTopItemIter(
            keys=(unresolvedApply.said, ""))) == []
        assert exc.cues.popleft() == dict(
            kin="query",
            q=dict(r="logs", pre=endorser.pre),
        )
        assert recorder.items == []

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

        with pytest.raises(ValueError):
            ipexOffer(hab=hab,
                      message="Bare offer without disclosure plan",
                      origin=acdc,
                      recp=hab.pre)

        # Build a bare offer with the committed origin and explicit receiver;
        # the starter generates its own xid once it is also given the explicit
        # disclosure plan that an unsolicited offer now requires.
        offer1, offer1Atc = ipexOffer(hab=hab,
                                      message="Bare offer for spurn path",
                                      origin=acdc,
                                      recp=hab.pre,
                                      modifiers=dict(dp=[[[acdc.sad["s"]["$id"], "/", []]]]))
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
        schema = acdc.sad["s"]["$id"]

        # Build a normal offer first, then remove q.dp to prove the V2 handler
        # fails closed on the required disclosure-plan field.
        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential",
                           modifiers=dict(dp=[[[schema, "/", []]]]))
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
        schema = acdc.sad["s"]["$id"]

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential",
                           modifiers=dict(dp=[[[schema, "/", []]]]))
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
        schema = acdc.sad["s"]["$id"]

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=acdc,
                           message="Here is the offered credential",
                           modifiers=dict(dp=[[[schema, "/", []]]]))
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
        schema = origin.sad["s"]["$id"]

        exn, _ = ipexOffer(hab=hab,
                           recp=hab.pre,
                           origin=origin,
                           message="Here is the offered credential",
                           modifiers=dict(dp=[[[schema, "/", []]]]))

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
                               recp=verifier.pre,
                               modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
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
        with pytest.raises(ValueError):
            ipexOffer(hab=holder,
                      message="Bare offer",
                      origin=acdc,
                      recp=verifier.pre)
        # Supplying the origin plus recipient and explicit dp is enough for an
        # offer-first opener.
        bareOffer, _ = ipexOffer(hab=holder,
                                 message="Bare offer",
                                 origin=acdc,
                                 recp=verifier.pre,
                                 modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]))
        assert bareOffer.ked["p"] == ""
        assert bareOffer.ked["ri"] == verifier.pre
        assert bareOffer.ked["x"] != ""
        assert bareOffer.ked["a"]["o"] == [acdc.said]
        assert bareOffer.ked["q"]["dp"] == [[[schema, "/", ["a/role"]]]]
        # Supplying xid directly is no longer supported at all.
        with pytest.raises(TypeError):
            ipexOffer(hab=holder,
                      message="Bare offer",
                      origin=acdc,
                      recp=verifier.pre,
                      modifiers=dict(dp=[[[schema, "/", ["a/role"]]]]),
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
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Bad disclosure plan prefix",
                      modifiers=dict(dp=[[[schema, "/e/holder", ["a/role"]]]]))
        with pytest.raises(ValueError):
            ipexApply(hab=verifier,
                      recp=holder.pre,
                      message="Bad disclosure plan field entries",
                      modifiers=dict(dp=[[[schema, "/", [1, {}]]]]))


def test_ipex_v2_rejects_inbound_apply_with_malformed_disclosure_path():
    """Inbound apply verification rejects forged dp entries with invalid field paths."""
    with openHby(name="ipex-v2-bad-apply-dp",
                 base="test",
                 version=Vrsn_2_0) as hby:
        holder = hby.makeHab(name="holder")
        verifier = hby.makeHab(name="verifier")
        schema = acdcmap(israid=holder.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                         iseaid=verifier.pre).sad["s"]["$id"]

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        badApply = exchange(sender=verifier.pre,
                            receiver=holder.pre,
                            xid=Noncer().qb64,
                            route="/ipex/apply",
                            modifiers=dict(dp=[[[schema, "/", [1, {}]]]]),
                            attributes=dict(m="Please disclose the forged plan"),
                            pvrsn=Vrsn_2_0,
                            gvrsn=Vrsn_2_0,
                            kind=verifier.kever.serder.kind)
        atc = bytearray(verifier.endorse(serder=badApply, framed=False, gvrsn=Vrsn_2_0))
        del atc[:badApply.size]

        ims = bytearray(badApply.raw)
        ims.extend(atc)
        Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

        assert ims == bytearray()
        assert hby.db.exns.get(keys=(badApply.said,)) is None
        assert recorder.items == []


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


def test_ipex_v2_bound_registry_proof_roundtrip():
    """Grant a bound blind proof through IPEX and keep it as bsss on the node nest."""
    with openHby(name="ipex-v2-bound-blindable",
                 base="test",
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="test")
        rgy = Regery(hby=hby, name="ipex-v2-bound-blindable", temp=True)
        try:
            # Create and anchor a real registry so the later proof has accepted
            # TEL evidence to verify against.
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="bound-blindable", prefix=hab.pre)
            rip = rgy.store.event(registry.regk)
            _anchor(hab, registry, rip, framed=True)

            # Build a registry-backed ACDC that will be disclosed through the grant.
            acdc = acdcmap(israid=hab.pre,
                           regid=registry.regk,
                           attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                           iseaid=hab.pre)

            # Issue a bound blind state so the proof lands in the bsss group
            # rather than the simpler bsqs group.
            boundBlinder, issued = registrar.issue(registry,
                                                   acdc=acdc,
                                                   state="issued",
                                                   bound=True,
                                                   bsn=hab.kever.sn,
                                                   bd=hab.kever.serder.said)
            _anchor(hab, registry, issued, framed=False)

            # Wire the normal IPEX verifier path with access to the local Regery.
            recorder = Recorder()
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, notifier=recorder, rgy=rgy)

            # Grant the ACDC and carry the bound proof on the same node nest.
            grantExn, grantAtc = ipexGrant(hab=hab,
                                           recp=hab.pre,
                                           message="Bound blindable disclosure",
                                           origin=_proofed(acdc, boundBlinder))

            # Parse the inbound grant end to end. Successful acceptance proves
            # the handler can vet bsss-based issuer-auth evidence.
            ims = bytearray(grantExn.raw)
            ims.extend(grantAtc)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)
            assert ims == bytearray()
            assert hby.db.exns.get(keys=(grantExn.said,)) is not None

            # Reload the stored message and confirm the disclosed node still
            # carries one bound proof group, not a plain blind proof group.
            msg = serializeMessage(hby, grantExn.said, framed=True)
            ims = bytearray(msg)
            results = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                     framed=False,
                                                     processive=False)
            assert ims == bytearray()
            assert len(results) == 1
            assert [nest.serder.said for nest in results[0].nests] == [acdc.said]
            assert len(results[0].nests[0].bsqs) == 0
            assert len(results[0].nests[0].bsss) == 1
            proof = results[0].nests[0].bsss[0]

            # These fields are the on-wire bound disclosure tuple:
            # blid, uuid, transaction ACDC said, state, bound sn, bound said.
            assert proof[0].qb64 == boundBlinder.said
            assert proof[1].nonce == boundBlinder.uuid
            assert proof[2].nonce == acdc.said
            assert proof[3].text == "issued"
            assert proof[4].snh == boundBlinder.bnh
            assert proof[5].nonce == boundBlinder.bd
            
            # Unblind from the stored tuple to prove the bsss data round-trips
            # through IPEX storage and serialization without losing meaning.
            unblinder = Blinder.unblind(said=proof[0].qb64,
                                        uuid=proof[1].nonce,
                                        acdc=acdc.said,
                                        states=["issued", "revoked"],
                                        bound=True,
                                        bounds=[(proof[4].sn, proof[5].nonce)])
            assert unblinder is not None
            assert unblinder.state == "issued"
            assert unblinder.bsn == boundBlinder.bsn
            assert unblinder.bd == boundBlinder.bd
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


@pytest.mark.parametrize("senderSeal", [False, True])
@pytest.mark.parametrize("validProof", [False, True])
def test_ipex_v2_escrows_registry_backed_grant_until_tel_evidence_arrives(senderSeal, validProof):
    """Recipient keeps a registry-backed grant retryable until TEL evidence is loaded."""
    with (openHby(name="ipex-v2-proof-escrow-issuer",
                  base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="ipex-v2-proof-escrow-recipient",
                  base="test",
                  version=Vrsn_2_0) as recipientHby):
        issuerHab = issuerHby.makeHab(name="issuer")
        recipientHab = recipientHby.makeHab(name="recipient")
        endorserHab = recipientHby.makeHab(name="endorser", transferable=False)
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

            node = acdc if validProof else acdcmap(
                israid=issuerHab.pre, regid=registry.regk,
                attribute=dict(d="", LEI="different credential"),
                iseaid=recipientHab.pre)
            grantExn, _ = ipexGrant(hab=issuerHab,
                                         recp=recipientHab.pre,
                                         message="Waiting on observer TEL",
                                         origin=_proofed(node, issuedBlinder),
                                         ax=[True] if senderSeal else None)

            anchorHab = issuerHab if senderSeal else recipientHab
            if senderSeal:
                # Truthy ax made the builder create the issuer's grant anchor.
                anchor = issuerHab.msgOwnEvent(sn=issuerHab.kever.sn,
                                               framed=True,
                                               gvrsn=Vrsn_2_0)
                Parser(version=Vrsn_2_0).parse(ims=bytearray(anchor),
                                               kvy=recipientRemoteKvy)
            else:
                # Falsy ax leaves the recipient seal as optional extra evidence.
                anchor = recipientHab.interact(data=[dict(d=grantExn.said)],
                                                framed=True,
                                                gvrsn=Vrsn_2_0)
            seal = SealEvent(i=anchorHab.pre, s=f"{anchorHab.kever.sn:x}",
                             d=anchorHab.kever.serder.said)
            signers = [recipientHab] if senderSeal else [issuerHab, recipientHab]
            tsgs = [(hab.kever.prefixer, Number(num=hab.kever.lastEst.s),
                     Diger(qb64=hab.kever.lastEst.d), hab.sign(ser=grantExn.raw))
                    for hab in signers]
            cigars = endorserHab.sign(ser=grantExn.raw, indexed=False)
            ims = messagize(grantExn, tsgs=tsgs, cigars=cigars, bonds=[seal],
                             nests=[_nest(_proofed(node, issuedBlinder))],
                             framed=False, gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=ims, framed=False, exc=exc)

            assert ims == bytearray()
            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is not None
            assert len(recipientHby.db.ests.get(
                keys=(grantExn.said, anchorHab.pre))) == 1
            assert recorder.items == []
            assert list(exc.cues) == [dict(kin="proof", said=grantExn.said)]

            # Retry twice before the TEL arrives. Each pass must retain every
            # direct authentication factor and the node-local proof.
            for _ in range(2):
                exc.processEscrow()
                assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
                assert recipientHby.db.epse.get(keys=(grantExn.said,)) is not None
                assert list(recipientHby.db.erpy.getTopItemIter()) == []
                assert recorder.items == []
                assert list(exc.cues) == [dict(kin="proof", said=grantExn.said)]
                assert len(list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, "")))) == len(signers)
                assert len(recipientHby.db.ecigs.get(keys=(grantExn.said,))) == 1
                assert len(recipientHby.db.ests.get(
                    keys=(grantExn.said, anchorHab.pre))) == 1
                assert len(recipientHby.db.enst.get(keys=(grantExn.said,))) == 1

            # Simulate the disclosee learning the issuer's TEL later, for
            # example by fetching it from observers after the first grant parse.
            recipientRgy.store.accept(registry.regk, 0, rip)
            recipientRgy.store.accept(registry.regk, 1, issued)

            exc.processEscrow()

            if not validProof:
                # Once TEL evidence is available, the proof for a different
                # credential is a permanent refusal. Remove all escrow rows.
                assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
                assert list(recipientHby.db.erpy.getTopItemIter()) == []
                assert recipientHby.db.epse.get(keys=(grantExn.said,)) is None
                assert recipientHby.db.epsd.get(keys=(grantExn.said,)) is None
                assert list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, ""))) == []
                assert recipientHby.db.ecigs.get(keys=(grantExn.said,)) == []
                assert list(recipientHby.db.ests.getTopItemIter(
                    keys=(grantExn.said, ""))) == []
                assert recipientHby.db.epath.get(keys=(grantExn.said,)) == []
                assert recipientHby.db.enst.get(keys=(grantExn.said,)) == []
                assert recorder.items == []
                assert list(exc.cues) == [dict(kin="proof", said=grantExn.said)]
                return

            assert recipientHby.db.exns.get(keys=(grantExn.said,)) is not None
            assert recipientHby.db.epse.get(keys=(grantExn.said,)) is None
            assert len(recipientHby.db.ests.get(
                keys=(grantExn.said, anchorHab.pre))) == 1
            assert recorder.items == [
                {"r": "/exn/ipex/grant", "d": grantExn.said, "m": "Waiting on observer TEL"},
            ]
            assert list(exc.cues) == [
                dict(kin="proof", said=grantExn.said),
                dict(kin="saved", said=grantExn.said),
            ]
            with reopenDB(db=recipientHby.db, reuse=True):
                wire = serializeMessage(recipientHby, grantExn.said, framed=True)
                replay, = Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(wire), framed=True, processive=False)
                assert {prefixer.qb64 for prefixer, _, _, _ in replay.tsgs} == {
                    hab.pre for hab in signers}
                assert [(cigar.verfer.qb64, cigar.qb64) for cigar in replay.cigars] == [
                    (endorserHab.pre, cigars[0].qb64)]
                assert [(prefixer.qb64, number.sn, diger.qb64)
                        for prefixer, number, diger in replay.ssts] == [
                    (anchorHab.pre, anchorHab.kever.sn, anchorHab.kever.serder.said)]
                assert [nest.serder.said for nest in replay.nests] == [acdc.said]
                assert len(replay.nests[0].bsqs) == 1
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
        endorserHab = issuerHby.makeHab(name="endorser")
        cigarEndorserHab = issuerHby.makeHab(name="cigar-endorser",
                                             transferable=False)
        unknownEndorserHab = issuerHby.makeHab(name="unknown-endorser")
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

            # Establish the single current key used by the offer flow while
            # committing to the 2-of-3 key state used by the later grant.
            issuerRot = issuerHab.rotate(framed=True,
                                         nsith="2",
                                         ncount=3,
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
            endorserIcp = endorserHab.msgOwnEvent(sn=0, framed=True,
                                                  gvrsn=Vrsn_2_0)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(endorserIcp),
                                           kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(ripAnc), kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuedAnc),
                                           framed=False,
                                           kvy=recipientRemoteKvy)
            Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerRot),
                                           kvy=recipientRemoteKvy)

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
                issuerGrantRot = issuerHab.rotate(
                    framed=True,
                    version=Vrsn_2_0,
                    kind=issuerHab.kever.serder.kind,
                    gvrsn=Vrsn_2_0,
                )
                Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(issuerGrantRot), kvy=recipientRemoteKvy)
                grantExn, _ = ipexGrant(hab=issuerHab,
                                        recp=recipientHab.pre,
                                        message="Here is the blind registry disclosure",
                                        origin=_proofed(acdc, issuedBlinder),
                                        agree=storedAgree,
                                        dt=grantStamp)
                grantReceiveMs = helping.fromIso8601(helping.nowIso8601()).timestamp() * 1000

                # A distinct transferable AID endorses the grant with both a
                # signature group and a KEL event that seals the grant SAID.
                endorserAnchor = endorserHab.interact(
                    data=[dict(d=grantExn.said)],
                    framed=True,
                    version=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                )
                Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(endorserAnchor), kvy=recipientRemoteKvy)

                senderSigs = issuerHab.sign(ser=grantExn.raw, indexed=True)
                endorserSigs = endorserHab.sign(ser=grantExn.raw,
                                                indexed=True)
                endorserCigars = cigarEndorserHab.sign(
                    ser=grantExn.raw, indexed=False)
                recipientSigs = recipientHab.sign(ser=grantExn.raw,
                                                  indexed=True)
                unknownEndorserSigs = unknownEndorserHab.sign(
                    ser=grantExn.raw, indexed=True)
                grantEstSn = issuerHab.kever.lastEst.s
                grantEstSaid = issuerHab.kever.lastEst.d

                def sigGroup(hab, sigers):
                    return (hab.kever.prefixer,
                            Number(sn=hab.kever.lastEst.s),
                            Diger(qb64=hab.kever.lastEst.d),
                            sigers)

                validSeal = SealEvent(i=endorserHab.pre,
                                      s=f"{endorserHab.kever.sn:x}",
                                      d=endorserHab.kever.serder.said)
                invalidSeal = SealEvent(i=recipientHab.pre,
                                        s=f"{recipientHab.kever.sn:x}",
                                        d=recipientHab.kever.serder.said)
                nests = [_nest(_proofed(acdc, issuedBlinder))]

                # Deliver a 2-of-3 sender signature threshold in two parser
                # passes. KRAM must pool the bare sigers and rehydrate the
                # optional evidence from the first pass. The recipient's
                # foreign last-establishment group is present only in this
                # partial delivery and must survive escrow in explicit form.
                firstGrant = messagize(
                    grantExn,
                    sigers=[senderSigs[0]],
                    tsgs=[sigGroup(endorserHab, endorserSigs)],
                    lsgs=[(recipientHab.kever.prefixer, recipientSigs),
                          (unknownEndorserHab.kever.prefixer,
                           unknownEndorserSigs)],
                    cigars=endorserCigars,
                    bonds=[validSeal, invalidSeal],
                    nests=nests,
                    framed=False,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(firstGrant)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()
                assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None

                partialKey = (issuerHab.pre, grantExn.said)
                assert len(recipientHby.db.kramPMKS.get(keys=partialKey)) == 1
                assert len(recipientHby.db.kramTSGS.get(keys=partialKey)) == 2
                assert [prefixer.qb64 for prefixer in
                        recipientHby.db.kramULGS.get(keys=partialKey)] == [
                    unknownEndorserHab.pre,
                ]
                assert len(recipientHby.db.kramCIGS.get(keys=partialKey)) == 1
                assert len(recipientHby.db.kramSSTS.get(keys=partialKey)) == 2

                secondGrant = messagize(
                    grantExn,
                    sigers=[senderSigs[2]],
                    nests=nests,
                    framed=False,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(secondGrant)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()
                assert recipientHby.db.exns.get(keys=(grantExn.said,)) is None
                assert any(cue.get("kin") == "query" and
                           cue["q"] == dict(r="logs",
                                            pre=unknownEndorserHab.pre)
                           for cue in recipientExc.cues)
                assert recipientHby.db.kramPMKM.get(keys=partialKey) is None
                assert recipientHby.db.kramPMKS.get(keys=partialKey) == []
                assert recipientHby.db.kramPMSK.get(keys=partialKey) is None
                assert recipientHby.db.kramTSGS.get(keys=partialKey) == []
                assert recipientHby.db.kramULGS.get(keys=partialKey) == []
                assert recipientHby.db.kramCIGS.get(keys=partialKey) == []
                assert recipientHby.db.kramSSTS.get(keys=partialKey) == []

                unknownEndorserIcp = unknownEndorserHab.msgOwnEvent(
                    sn=0, framed=True, gvrsn=Vrsn_2_0)
                Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(unknownEndorserIcp),
                    kvy=recipientRemoteKvy)
                recipientExc.cues.clear()

                # KRAM keeps the accepted SAID in its replay cache, so even a
                # complete same-SAID delivery cannot retry downstream handling.
                sameSaidReplay = messagize(
                    grantExn,
                    sigers=[senderSigs[0], senderSigs[2]],
                    tsgs=[sigGroup(endorserHab, endorserSigs)],
                    lsgs=[(recipientHab.kever.prefixer, recipientSigs),
                          (unknownEndorserHab.kever.prefixer,
                           unknownEndorserSigs)],
                    cigars=endorserCigars,
                    bonds=[validSeal, invalidSeal],
                    nests=nests,
                    framed=False,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(sameSaidReplay)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()
                assert recipientHby.db.exns.get(
                    keys=(grantExn.said,)) is None

                # A protocol retry is a fresh message: the later datetime
                # produces a new SAID and every signer authenticates those bytes.
                clock.advance(milliseconds=1)
                grantStamp = helping.nowIso8601()
                retryGrantExn, _ = ipexGrant(
                    hab=issuerHab,
                    recp=recipientHab.pre,
                    message="Here is the blind registry disclosure",
                    origin=_proofed(acdc, issuedBlinder),
                    agree=storedAgree,
                    dt=grantStamp,
                )
                grantReceiveMs = helping.fromIso8601(
                    helping.nowIso8601()).timestamp() * 1000

                retryEndorserAnchor = endorserHab.interact(
                    data=[dict(d=retryGrantExn.said)],
                    framed=True,
                    version=Vrsn_2_0,
                    gvrsn=Vrsn_2_0,
                )
                Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(retryEndorserAnchor),
                    kvy=recipientRemoteKvy)

                senderSigs = issuerHab.sign(
                    ser=retryGrantExn.raw, indexed=True)
                endorserSigs = endorserHab.sign(
                    ser=retryGrantExn.raw, indexed=True)
                endorserCigars = cigarEndorserHab.sign(
                    ser=retryGrantExn.raw, indexed=False)
                recipientSigs = recipientHab.sign(
                    ser=retryGrantExn.raw, indexed=True)
                unknownEndorserSigs = unknownEndorserHab.sign(
                    ser=retryGrantExn.raw, indexed=True)
                validSeal = SealEvent(
                    i=endorserHab.pre,
                    s=f"{endorserHab.kever.sn:x}",
                    d=endorserHab.kever.serder.said,
                )

                retryGrant = messagize(
                    retryGrantExn,
                    sigers=[senderSigs[0], senderSigs[2]],
                    # An interaction is a valid source seal but cannot supply
                    # establishment keys for an optional signature group.
                    tsgs=[sigGroup(endorserHab, endorserSigs),
                          (endorserHab.kever.prefixer,
                           Number(sn=endorserHab.kever.sn),
                           Diger(qb64=endorserHab.kever.serder.said),
                           endorserSigs)],
                    lsgs=[(recipientHab.kever.prefixer, recipientSigs),
                          (unknownEndorserHab.kever.prefixer,
                           unknownEndorserSigs)],
                    cigars=endorserCigars,
                    bonds=[validSeal, invalidSeal],
                    nests=nests,
                    framed=False,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(retryGrant)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=recipientKvy)
                assert ims == bytearray()

                grantExn = retryGrantExn
                partialKey = (issuerHab.pre, grantExn.said)

                # Preserve the issuer's outbound prior so it can validate the
                # recipient's admit at the end of the real IPEX sequence.
                issuerGrant = messagize(
                    grantExn,
                    tsgs=[sigGroup(issuerHab, senderSigs)],
                    nests=nests,
                    framed=False,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(issuerGrant)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=issuerSelfKvy)
                assert ims == bytearray()

                # The recipient stores this grant locally so the final admit can
                # be built as a real reply to the accepted inbound message.
                storedGrant, _ = cloneMessage(recipientHby, grantExn.said)
                assert storedGrant is not None
                assert storedGrant.ked["x"] == applyExn.ked["x"]

                senderRows = list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, issuerHab.pre, "")))
                endorserRows = list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, endorserHab.pre, "")))
                recipientRows = list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, recipientHab.pre, "")))
                assert len(senderRows) == 2
                assert len(endorserRows) == 1
                assert len(recipientRows) == 1
                assert len(list(recipientHby.db.esigs.getTopItemIter(
                    keys=(grantExn.said, unknownEndorserHab.pre, "")))) == 1
                storedCigars = recipientHby.db.ecigs.get(
                    keys=(grantExn.said,))
                assert [(verfer.qb64, cigar.qb64)
                        for verfer, cigar in storedCigars] == [
                    (cigarEndorserHab.pre, endorserCigars[0].qb64),
                ]

                validSeals = recipientHby.db.ests.get(
                    keys=(grantExn.said, endorserHab.pre))
                invalidSeals = recipientHby.db.ests.get(
                    keys=(grantExn.said, recipientHab.pre))
                assert [(number.sn, diger.qb64)
                        for number, diger in validSeals] == [
                    (endorserHab.kever.sn, endorserHab.kever.serder.said),
                ]
                assert invalidSeals == []
                assert not any(cue.get("kin") == "query"
                               for cue in recipientExc.cues)

                response = recipientHby.db.erpy.get(
                    keys=(grantExn.ked["p"],))
                assert response.qb64 == grantExn.said

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

                # Move the sender to a later establishment event after the
                # grant is accepted. Durable replay must still verify the
                # grant against the historical event that supplied its keys.
                issuerPostGrantRot = issuerHab.rotate(
                    framed=True,
                    version=Vrsn_2_0,
                    kind=issuerHab.kever.serder.kind,
                    gvrsn=Vrsn_2_0,
                )
                Parser(version=Vrsn_2_0).parse(
                    ims=bytearray(issuerPostGrantRot), kvy=recipientRemoteKvy)
                assert recipientHby.kevers[issuerHab.pre].lastEst.s > grantEstSn

                # Run the production prune path after the exchange cache
                # expires. It must remove only KRAM's temporary rows.
                pruneMs = (int(helping.fromIso8601(
                    grantCache.xdt).timestamp() * 1000) + grantCache.pxl + 1)
                assert recipientKvy.kramer._pruneExchanges(rdt_ms=pruneMs)
                assert recipientHby.db.kramTMSC.get(
                    keys=(issuerHab.pre, applyExn.ked["x"], grantExn.said)) is None
                assert recipientHby.db.kramPMKM.get(keys=partialKey) is None
                assert recipientHby.db.kramPMKS.get(keys=partialKey) == []
                assert recipientHby.db.kramTSGS.get(keys=partialKey) == []
                assert recipientHby.db.kramULGS.get(keys=partialKey) == []
                assert recipientHby.db.kramCIGS.get(keys=partialKey) == []
                assert recipientHby.db.kramSSTS.get(keys=partialKey) == []

                # Close and reopen the receiver database before replay. The
                # durable generic evidence and nested streams must survive both
                # KRAM pruning and an LMDB lifecycle boundary.
                with reopenDB(db=recipientHby.db, reuse=True):
                    grantMsg = serializeMessage(recipientHby,
                                                grantExn.said,
                                                framed=True)
                    grantWire = bytearray(grantMsg)
                    grantResults = Parser(version=Vrsn_2_0).parse(
                        ims=grantWire, framed=False, processive=False)
                    assert grantWire == bytearray()
                    assert len(grantResults) == 1

                    replay = grantResults[0]
                    replayGroups = {
                        prefixer.qb64: (number, diger, sigers)
                        for prefixer, number, diger, sigers in replay.tsgs
                    }
                    number, diger, sigers = replayGroups[issuerHab.pre]
                    assert (number.sn, diger.qb64, len(sigers)) == (
                        grantEstSn,
                        grantEstSaid,
                        2,
                    )
                    number, diger, sigers = replayGroups[endorserHab.pre]
                    assert (number.sn, diger.qb64, len(sigers)) == (
                        endorserHab.kever.lastEst.s,
                        endorserHab.kever.lastEst.d,
                        1,
                    )
                    number, diger, sigers = replayGroups[recipientHab.pre]
                    assert (number.sn, diger.qb64, len(sigers)) == (
                        recipientHab.kever.lastEst.s,
                        recipientHab.kever.lastEst.d,
                        1,
                    )
                    assert [(prefixer.qb64, number.sn, diger.qb64)
                            for prefixer, number, diger in replay.ssts] == [
                        (endorserHab.pre,
                         endorserHab.kever.sn,
                         endorserHab.kever.serder.said),
                    ]
                    assert [(cigar.verfer.qb64, cigar.qb64)
                            for cigar in replay.cigars] == [
                        (cigarEndorserHab.pre, endorserCigars[0].qb64),
                    ]
                    assert [nest.serder.said for nest in replay.nests] == [
                        acdc.said,
                    ]
                    assert recipientHby.db.exns.get(
                        keys=(staleOfferExn.said,)) is None
                    assert recipientHby.db.exns.get(
                        keys=(offerExn.said,)) is not None

                    # Process the reconstructed message again after KRAM
                    # pruning. The replay may refresh temporary KRAM state,
                    # but it must not duplicate durable evidence or notify the
                    # route handler a second time.
                    beforeSenderRows = [
                        (keys, siger.qb64)
                        for keys, siger in recipientHby.db.esigs.getTopItemIter(
                            keys=(grantExn.said, issuerHab.pre, ""))
                    ]
                    beforeEndorserRows = [
                        (keys, siger.qb64)
                        for keys, siger in recipientHby.db.esigs.getTopItemIter(
                            keys=(grantExn.said, endorserHab.pre, ""))
                    ]
                    beforeSeals = [
                        (keys, number.qb64, diger.qb64)
                        for keys, (number, diger) in
                        recipientHby.db.ests.getTopItemIter(
                            keys=(grantExn.said, ""))
                    ]
                    beforeItems = list(recipientRecorder.items)

                    replayWire = bytearray(grantMsg)
                    Parser(version=Vrsn_2_0).parse(
                        ims=replayWire, framed=True, kvy=recipientKvy)
                    assert replayWire == bytearray()
                    assert [
                        (keys, siger.qb64)
                        for keys, siger in recipientHby.db.esigs.getTopItemIter(
                            keys=(grantExn.said, issuerHab.pre, ""))
                    ] == beforeSenderRows
                    assert [
                        (keys, siger.qb64)
                        for keys, siger in recipientHby.db.esigs.getTopItemIter(
                            keys=(grantExn.said, endorserHab.pre, ""))
                    ] == beforeEndorserRows
                    assert [
                        (keys, number.qb64, diger.qb64)
                        for keys, (number, diger) in
                        recipientHby.db.ests.getTopItemIter(
                            keys=(grantExn.said, ""))
                    ] == beforeSeals
                    assert recipientRecorder.items == beforeItems

                # Resolve the replayed node's proof against the recipient's
                # accepted TEL. The grant carries the node-local proof, while
                # the recipient's registry store supplies the update history.
                assert len(replay.nests[0].bsqs) == 1
                said, uuid, _, _ = replay.nests[0].bsqs[0]
                assert said.qb64 == issuedBlinder.blid
                carriedBup = recipientRgy.store.seqEvent(registry.regk, 1)
                unblinder = Blinder.unblind(said=carriedBup.sad["b"],
                                            uuid=uuid.nonce,
                                            acdc=replay.nests[0].serder.said,
                                            states=["issued", "revoked"])
                assert unblinder is not None
                assert unblinder.state == "issued"
                assert unblinder.acdc == acdc.said
                assert unblinder.crew == issuedBlinder.crew

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
                             edge=_edge("holder", child, op="E1E"),
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
                                                   [schema, "/e/holder/_/", []],
                                               ]]),
                                               dt=applyStamp)
                
                assert applyExn.ked["q"]["dp"] == [[
                    [schema, "/", []],
                    [schema, "/e/holder/_/", []],
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
            schema = acdc.sad["s"]["$id"]
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
                                               modifiers=dict(dp=[[[schema, "/", []]]]),
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


def test_ipex_v2_nested_signature_does_not_authenticate_outer_grant(
        fakeHelpingClock):
    """A valid nested signature cannot satisfy outer grant KRAM auth."""
    kramConfig = {
        "kram": {
            "enabled": True,
            "denials": [],
            "caches": {
                "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
            },
        },
    }

    with openHby(name="ipex-v2-nested-auth", base="test",
                 version=Vrsn_2_0) as hby:
        sender = hby.makeHab(name="sender")
        recipient = hby.makeHab(name="recipient")

        nested = acdcmap(israid=sender.pre,
                         attribute=dict(d="", role="member"),
                         iseaid=recipient.pre)
        nestedTsgs = [(
            sender.kever.prefixer,
            Number(sn=sender.kever.lastEst.s),
            Diger(qb64=sender.kever.lastEst.d),
            sender.sign(ser=nested.raw, indexed=True),
        )]
        nestedMsg = messagize(
            serder=nested,
            tsgs=nestedTsgs,
            framed=False,
            gvrsn=Vrsn_2_0,
        )

        grantExn, _ = ipexGrant(
            hab=sender,
            recp=recipient.pre,
            message="Nested evidence cannot authenticate this grant",
            origin=nestedMsg,
        )
        invalidOuterTsgs = [(
            sender.kever.prefixer,
            Number(sn=sender.kever.lastEst.s),
            Diger(qb64=sender.kever.lastEst.d),
            sender.sign(ser=b"different outer grant", indexed=True),
        )]
        invalidOuterGrant = messagize(
            serder=grantExn,
            tsgs=invalidOuterTsgs,
            nests=[_nest(nestedMsg)],
            framed=False,
            gvrsn=Vrsn_2_0,
        )

        recorder = Recorder()
        exc = Exchanger(hby=hby, handlers=[])
        loadHandlers(hby=hby, exc=exc, notifier=recorder)

        with openCF(name="ipex-v2-nested-auth-kram", base="test",
                    temp=True) as cf:
            cf.put(kramConfig)
            kvy = Kevery(db=hby.db,
                         lax=False,
                         local=False,
                         kramer=Kramer(db=hby.db, cf=cf),
                         exc=exc)
            ims = bytearray(invalidOuterGrant)
            Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
            assert ims == bytearray()

        assert hby.db.exns.get(keys=(grantExn.said,)) is None
        assert list(hby.db.esigs.getTopItemIter(
            keys=(grantExn.said, ""))) == []
        assert hby.db.enst.get(keys=(grantExn.said,)) == []
        assert hby.db.kramTMSC.get(
            keys=(sender.pre, grantExn.ked["x"], grantExn.said)) is None
        assert recorder.items == []


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
