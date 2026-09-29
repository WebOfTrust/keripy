# -*- coding: utf-8 -*-
"""Worked IPEX presentations for the current SEDI credential design."""

from contextlib import contextmanager

from jsonschema import Draft202012Validator as SchemaValidator

from keri import Kinds, Vrsn_2_0
from keri.acdc import (
    Regery,
    Registrar,
    acdcmap,
    admit as ipexAdmit,
    agree as ipexAgree,
    apply as ipexApply,
    grant as ipexGrant,
    loadHandlers,
    offer as ipexOffer,
)
from keri.app import openCF, openHby
from keri.core import (
    Compactor,
    Diger,
    Kevery,
    Kramer,
    Mapper,
    Noncer,
    Parser,
    Salter,
    SealEvent,
    SerderKERI,
    messagize,
)
from keri.help import helping
from keri.peer import Exchanger, cloneMessage
from keri.peer.exchanging import loadParsedNestedSubstreams

from tests.sedi.test_sedi import (
    CoreSchema,
    CoreSchemaSaid,
    IarSchema,
    IarSchemaSaid,
    ResidenceSchema,
    ResidenceSchemaSaid,
)


_KRAM_CONFIG = {
    "kram": {
        "enabled": True,
        "denials": [],
        "caches": {
            "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
        },
    },
}


class Recorder:
    """Collect accepted IPEX notices for workflow assertions."""

    def __init__(self):
        self.items = []

    def add(self, attrs):
        self.items.append(attrs)


@contextmanager
def _openSediHaberies(name):
    """Open one independent Habery for each SEDI workflow role."""
    with (
        openHby(name=f"{name}-proofer", base="test", version=Vrsn_2_0) as prooferHby,
        openHby(name=f"{name}-issuer", base="test", version=Vrsn_2_0) as issuerHby,
        openHby(name=f"{name}-holder", base="test", version=Vrsn_2_0) as holderHby,
        openHby(name=f"{name}-verifier", base="test", version=Vrsn_2_0) as verifierHby,
    ):
        proofer = prooferHby.makeHab(name="pat-proofer")
        issuer = issuerHby.makeHab(name="sue-state-issuer")
        holder = holderHby.makeHab(name="guy-holder")
        verifier = verifierHby.makeHab(name="vic-verifier")
        yield (
            prooferHby,
            issuerHby,
            holderHby,
            verifierHby,
            proofer,
            issuer,
            holder,
            verifier,
        )


@contextmanager
def _openSediRegistries(name, issuerHby, holderHby, verifierHby):
    """Open and close the registry stores used by the three relying roles."""
    issuerRgy = Regery(hby=issuerHby, name=f"{name}-issuer", temp=True)
    holderRgy = Regery(hby=holderHby, name=f"{name}-holder", temp=True)
    verifierRgy = Regery(hby=verifierHby, name=f"{name}-verifier", temp=True)
    try:
        yield issuerRgy, holderRgy, verifierRgy
    finally:
        issuerRgy.close()
        holderRgy.close()
        verifierRgy.close()


@contextmanager
def _openIpexProcessors(name, holderHby, verifierHby, holderRgy, verifierRgy):
    """Open the independent holder and verifier IPEX/KRAM processors."""
    holderRecorder = Recorder()
    holderExc = Exchanger(hby=holderHby, handlers=[])
    loadHandlers(hby=holderHby, exc=holderExc, notifier=holderRecorder, rgy=holderRgy)
    verifierRecorder = Recorder()
    verifierExc = Exchanger(hby=verifierHby, handlers=[])
    loadHandlers(
        hby=verifierHby, exc=verifierExc, notifier=verifierRecorder, rgy=verifierRgy
    )

    with (
        openCF(name=f"{name}-holder", base="test", temp=True) as holderCf,
        openCF(name=f"{name}-verifier", base="test", temp=True) as verifierCf,
    ):
        holderCf.put(_KRAM_CONFIG)
        verifierCf.put(_KRAM_CONFIG)
        holderKvy = Kevery(
            db=holderHby.db,
            lax=False,
            local=False,
            kramer=Kramer(db=holderHby.db, cf=holderCf),
            exc=holderExc,
        )
        verifierKvy = Kevery(
            db=verifierHby.db,
            lax=False,
            local=False,
            kramer=Kramer(db=verifierHby.db, cf=verifierCf),
            exc=verifierExc,
        )
        yield holderRecorder, verifierRecorder, holderKvy, verifierKvy


def _anchor(hab, registry, event):
    """Anchor one registry event and return its framed KEL stream."""
    seal = dict(i=registry.regk, s=event.sad["n"], d=event.said)
    stream = hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
    assert registry.anchorMsg(event.said) is True
    return stream


def _proofed(acdc, *proofs, source=None):
    """Attach node-local TEL disclosures and an optional KEL source."""
    bonds = [proof.data for proof in proofs]
    if source is not None:
        hab, stream = source
        anchor = SerderKERI(raw=stream)
        bonds.append(SealEvent(i=hab.pre, s=anchor.snh, d=anchor.said))
    return messagize(serder=acdc, bonds=bonds, framed=False, gvrsn=Vrsn_2_0)


def _exchange(exn, atc, senderKvy, receiverKvy):
    """Process one IPEX message in both parties' independent stores."""
    message = bytearray(exn.raw)
    message.extend(atc)
    for kvy in (senderKvy, receiverKvy):
        ims = bytearray(message)
        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
        assert ims == bytearray()


def _buildSediCredentials(
    proofer, issuer, holder, coreRegistry, residenceRegistry, presentationRegistry
):
    """Build IAR, Core, and Residence ACDCs from the current SEDI schemas."""
    salter = Salter(raw=b"sedi-ipex-tests!")
    nonces = [
        Noncer(raw=salter.stretch(size=16, path=f"{index:x}", temp=True)).qb64
        for index in range(32)
    ]

    # The holder proves control of its SMAID challenge during identity proofing.
    challenge = nonces[0]
    challengeEvent = holder.interact(
        data=[dict(nd=challenge)], framed=True, gvrsn=Vrsn_2_0
    )

    # The proofing agent signs this registry-less receipt after checking identity.
    iarAttributes = Mapper(
        mad=dict(
            d="",
            i=holder.pre,
            givenName="Guy",
            middleName="Marty McFly",
            familyName="Brown",
            birthDate="2002-08-22T00:00:00.000000+00:00",
            facialImageProof=Diger(ser=b"Guy facial image").qb64,
            legalPresenceStatus="citizen",
            residence=dict(
                street="157 E 300 N",
                city="Beaver",
                county="Beaver",
                state="Utah",
                postcode="84713",
                country="United States",
            ),
            proofingDatetime="2026-09-01T09:30:00.000000+00:00",
            sediURL="https://example.com/sedi/guy",
        ),
        makify=True,
        saidive=True,
        kind=Kinds.json,
    ).mad

    # Build the IAR ACDC with the proofer's signature
    iar = acdcmap(
        israid=proofer.pre,
        uuid=challenge,
        schema=IarSchemaSaid,
        attribute=iarAttributes,
        kind=Kinds.json,
    )

    # Build the state issuer's authority node referenced by Core SEDI.
    authority = acdcmap(
        israid=proofer.pre,
        uuid=nonces[1],
        attribute=dict(d="", i=issuer.pre, role="Utah SEDI issuer"),
        iseaid=issuer.pre,
        kind=Kinds.json,
    )

    # Core SEDI contains independently saidified identity attribute blocks.
    coreAttributesMad = dict(
        d="",
        u=nonces[3],
        i=holder.pre,
        rd=presentationRegistry.regk,
        givenName=dict(d="", u=nonces[4], value="Guy"),
        middleName=dict(d="", u=nonces[5], value="Marty McFly"),
        familyName=dict(d="", u=nonces[6], value="Brown"),
        nameSuffix=dict(d="", u=nonces[7], value="Jr"),
        birthDate=dict(d="", u=nonces[8], value="2002-08-22T00:00:00.000000+00:00"),
        facialImageProof=dict(
            d="", u=nonces[9], value=Diger(ser=b"Guy facial image").qb64
        ),
        legalPresenceStatus=dict(d="", u=nonces[10], value="citizen"),
        issuedDate=dict(d="", u=nonces[11], value="2026-09-01T00:00:00.000000+00:00"),
        expirationDate=dict(
            d="", u=nonces[12], value="2028-09-01T00:00:00.000000+00:00"
        ),
    )
    coreAttributePaths = [
        ".givenName",
        ".middleName",
        ".familyName",
        ".nameSuffix",
        ".birthDate",
        ".facialImageProof",
        ".legalPresenceStatus",
        ".issuedDate",
        ".expirationDate",
    ]
    coreAttributesCompactor = Compactor(
        mad=coreAttributesMad,
        makify=True,
        compactify=True,
        saidive=True,
        kind=Kinds.json,
    )
    coreAttributes = coreAttributesCompactor.partials[tuple(coreAttributePaths)].mad

    # Create an edge that references the issuer's authority node for the Core SEDI credential
    coreEdgeMad = dict(
        d="",
        u=nonces[13],
        utahAgent=dict(
            d="", u=nonces[14], n=authority.said, s=authority.sad["s"]["$id"], o="I2I"
        ),
    )
    coreEdgePaths = [".utahAgent"]
    coreEdgeCompactor = Compactor(
        mad=coreEdgeMad, makify=True, compactify=True, saidive=True, kind=Kinds.json
    )
    coreEdge = coreEdgeCompactor.partials[tuple(coreEdgePaths)].mad

    ruleMad = dict(d="", l="Use only for identity verification.")
    rulePaths = [""]
    ruleCompactor = Compactor(
        mad=ruleMad, makify=True, compactify=True, saidive=True, kind=Kinds.json
    )
    rule = ruleCompactor.partials[tuple(rulePaths)].mad

    # Build the Core SEDI ACDC with the issuer's authority edge and the holder's identity attributes
    core = acdcmap(
        israid=issuer.pre,
        uuid=nonces[2],
        regid=coreRegistry.regk,
        schema=CoreSchemaSaid,
        attribute=coreAttributes,
        edge=coreEdge,
        rule=rule,
        kind=Kinds.json,
    )

    # Residence SEDI narrows disclosure and links back to the same holder's Core credential
    residenceAttributesMad = dict(
        d="",
        u=nonces[16],
        i=holder.pre,
        rd=presentationRegistry.regk,
        street=dict(d="", u=nonces[17], value="157 E 300 N"),
        city=dict(d="", u=nonces[18], value="Beaver"),
        county=dict(d="", u=nonces[19], value="Beaver"),
        state=dict(d="", u=nonces[20], value="Utah"),
        postcode=dict(d="", u=nonces[21], value="84713"),
        country=dict(d="", u=nonces[22], value="United States"),
        issuedDate=dict(d="", u=nonces[23], value="2026-09-01T00:00:00.000000+00:00"),
    )
    residenceAttributePaths = [
        ".street",
        ".city",
        ".county",
        ".state",
        ".postcode",
        ".country",
        ".issuedDate",
    ]
    residenceAttributesCompactor = Compactor(
        mad=residenceAttributesMad,
        makify=True,
        compactify=True,
        saidive=True,
        kind=Kinds.json,
    )
    residenceAttributes = residenceAttributesCompactor.partials[
        tuple(residenceAttributePaths)
    ].mad

    # Create a nested edge that references the holder's Core SEDI
    residenceEdgeMad = dict(
        d="",
        u=nonces[24],
        coreIdentity=dict(
            d="", u=nonces[25], n=core.said, s=CoreSchemaSaid, o=["E1E", "NI2I"]
        ),
    )
    residenceEdgePaths = [".coreIdentity"]
    residenceEdgeCompactor = Compactor(
        mad=residenceEdgeMad,
        makify=True,
        compactify=True,
        saidive=True,
        kind=Kinds.json,
    )
    residenceEdge = residenceEdgeCompactor.partials[tuple(residenceEdgePaths)].mad

    # Build residence ACDC
    residence = acdcmap(
        israid=issuer.pre,
        uuid=nonces[15],
        regid=residenceRegistry.regk,
        schema=ResidenceSchemaSaid,
        attribute=residenceAttributes,
        edge=residenceEdge,  # nested edge referencing the holder's Core SEDI credential
        rule=rule,
        kind=Kinds.json,
    )

    # Prove each example conforms to the exact schema committed in its s field.
    SchemaValidator(schema=IarSchema).validate(iar.sad)
    SchemaValidator(schema=CoreSchema).validate(core.sad)
    SchemaValidator(schema=ResidenceSchema).validate(residence.sad)
    return iar, authority, core, residence, challengeEvent


def test_signed_iar_through_ipex():
    """Present a registry-less IAR authenticated by its proofer's signature."""
    # Keep the proofer, holder, and verifier in independent stores.
    with (
        openHby(name="ipex-iar-proofer", base="test", version=Vrsn_2_0) as prooferHby,
        openHby(name="ipex-iar-holder", base="test", version=Vrsn_2_0) as holderHby,
        openHby(name="ipex-iar-verifier", base="test", version=Vrsn_2_0) as verifierHby,
    ):
        proofer = prooferHby.makeHab(name="pat-proofer")
        holder = holderHby.makeHab(name="guy-holder")
        verifier = verifierHby.makeHab(name="vic-verifier")

        # Bind Pat's receipt to a nonce Guy publishes from his SMAID.
        challenge = Noncer(
            raw=Salter(raw=b"sedi-iar-test!!!").stretch(
                size=16,
                path="0",
                temp=True,
            )
        ).qb64
        challengeEvent = holder.interact(
            data=[dict(nd=challenge)], framed=True, gvrsn=Vrsn_2_0
        )

        # Guy's identity attributes
        attributes = Mapper(
            mad=dict(
                d="",
                i=holder.pre,
                givenName="Guy",
                middleName="Marty McFly",
                familyName="Brown",
                birthDate="2002-08-22T00:00:00.000000+00:00",
                facialImageProof=Diger(ser=b"Guy facial image").qb64,
                legalPresenceStatus="citizen",
                residence=dict(
                    street="157 E 300 N",
                    city="Beaver",
                    county="Beaver",
                    state="Utah",
                    postcode="84713",
                    country="United States",
                ),
                proofingDatetime="2026-09-01T09:30:00.000000+00:00",
                sediURL="https://example.com/sedi/guy",
            ),
            makify=True,
            saidive=True,
            kind=Kinds.json,
        ).mad

        # Build the IAR ACDC and validate it
        iar = acdcmap(
            israid=proofer.pre,
            uuid=challenge,
            schema=IarSchemaSaid,
            attribute=attributes,
            kind=Kinds.json,
        )
        SchemaValidator(schema=IarSchema).validate(iar.sad)

        # Set up Ipex
        holderRecorder = Recorder()
        holderExc = Exchanger(hby=holderHby, handlers=[])
        loadHandlers(hby=holderHby, exc=holderExc, notifier=holderRecorder)
        verifierRecorder = Recorder()
        verifierExc = Exchanger(hby=verifierHby, handlers=[])
        loadHandlers(hby=verifierHby, exc=verifierExc, notifier=verifierRecorder)

        # Set up Kram and Kevery
        with (
            openCF(name="ipex-iar-holder", base="test", temp=True) as holderCf,
            openCF(name="ipex-iar-verifier", base="test", temp=True) as verifierCf,
        ):
            holderCf.put(_KRAM_CONFIG)
            verifierCf.put(_KRAM_CONFIG)
            holderKvy = Kevery(
                db=holderHby.db,
                lax=False,
                local=False,
                kramer=Kramer(db=holderHby.db, cf=holderCf),
                exc=holderExc,
            )
            verifierKvy = Kevery(
                db=verifierHby.db,
                lax=False,
                local=False,
                kramer=Kramer(db=verifierHby.db, cf=verifierCf),
                exc=verifierExc,
            )

            # Feed Both verifier and holder Pat's keys to verify the nested IAR.
            prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            for kvy in (holderKvy, verifierKvy):
                ims = bytearray(prooferIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                assert ims == bytearray()

            # Vic receives Guy's complete KEL through the challenge event.
            holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            for stream in (holderIcp, challengeEvent):
                ims = bytearray(stream)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

            # Guy needs Vic's inception event to authenticate the Admit.
            verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
            ims = bytearray(verifierIcp)
            Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
            assert ims == bytearray()

            # Pat authenticates the registry-less IAR; Guy presents it.
            signedIar = proofer.endorse(serder=iar, framed=False, gvrsn=Vrsn_2_0)
            grant, grantAtc = ipexGrant(
                hab=holder,
                recp=verifier.pre,
                message="Present signed identity assurance receipt",
                origin=signedIar,
            )

            # Send the Grant to the verifier and assert it is stored
            _exchange(grant, grantAtc, holderKvy, verifierKvy)

            storedGrant, grantPathed = cloneMessage(verifierHby, grant.said)
            assert storedGrant is not None
            assert storedGrant.raw == grant.raw
            assert grantPathed == {}
            assert storedGrant.pre == holder.pre
            assert storedGrant.ked["ri"] == verifier.pre
            assert storedGrant.ked["r"] == "/ipex/grant"
            assert storedGrant.ked["p"] == ""
            assert storedGrant.ked["x"] == grant.ked["x"]
            assert storedGrant.ked["a"]["o"] == [iar.said]
            iarNests = loadParsedNestedSubstreams(verifierHby, grant.said)
            assert len(iarNests) == 1
            assert iarNests[0].serder.said == iar.said

            # Build and send the Admit message
            admit, admitAtc = ipexAdmit(
                hab=verifier,
                message="Identity assurance receipt received",
                grant=storedGrant,
            )
            _exchange(admit, admitAtc, verifierKvy, holderKvy)

        expected = [
            "Present signed identity assurance receipt",
            "Identity assurance receipt received",
        ]
        assert [item["m"] for item in holderRecorder.items] == expected
        assert [item["m"] for item in verifierRecorder.items] == expected
        assert prooferHby.db.exns.get(keys=(grant.said,)) is None


def test_core_sedi_offer_to_admit_flow_with_interleaved_kel_events():
    """Complete IPEX while synchronizing only new KEL suffixes between messages."""
    # Give every production role its own Habery and database.
    with _openSediHaberies("ipex-core") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries("ipex-core", issuerHby, holderHby, verifierHby) as (
            issuerRgy,
            holderRgy,
            verifierRgy,
        ):
            # Set up the issuer registry and anchor its inception event.
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)

            # The shared credential builder also requires a Residence registry.
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="credential-factory-residence-registry",
                prefix=issuer.pre,
            )

            # Set up the holder's presentation registry and anchor its inception.
            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            # Build the credentials.
            _, authority, core, _, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )

            # Pat anchors Sue's authority credential once for perpetual reuse.
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )

            # Rotate afterward to prove the historical anchor remains valid.
            prooferRot = proofer.rotate(
                framed=True, version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0
            )

            # Issue the Core SEDI credential and anchor its issuance event in the issuer's registry
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            # Set up the holder's and verifier's independent IPEX pipelines.
            with _openIpexProcessors(
                "ipex-core", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
            
                # Replicate Pat's and Sue's complete required KEL prefixes.
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)

                # Feed the necessary anchors and events to the Holder and Verifier
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    prooferRot,
                    issuerIcp,
                    coreRipAnchor,
                    coreIssuedAnchor,
                ):
                    for kvy in (holderKvy, verifierKvy):
                        ims = bytearray(stream)
                        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                        assert ims == bytearray()

                # Feed the holder's icp, presentation registry anchor and challenge to the verifier
                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                for stream in (holderIcp, presentationRipAnchor, challengeEvent):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                # Feed the verifier's icp to the holder
                verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Simulate delivery of issuer and presentation TEL evidence.
                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                # Build Apply message from the verifier to the holder
                coreApply, coreApplyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Please present Core SEDI",
                    modifiers=dict(
                        dp=[
                            [
                                [CoreSchemaSaid, "/", []],
                                [authority.sad["s"]["$id"], "/e/utahAgent/_/", []],
                            ]
                        ]
                    ),
                    ax=[True],
                )

                # Send the Apply message to the holder and assert it is stored
                _exchange(coreApply, coreApplyAtc, verifierKvy, holderKvy)
                storedApply, applyPathed = cloneMessage(holderHby, coreApply.said)
                assert storedApply is not None
                assert storedApply.raw == coreApply.raw
                assert applyPathed == {}
                assert storedApply.pre == verifier.pre
                assert storedApply.ked["ri"] == holder.pre
                assert storedApply.ked["r"] == "/ipex/apply"
                assert storedApply.ked["p"] == ""
                assert storedApply.ked["x"] == coreApply.ked["x"]
                assert storedApply.ked["q"] == coreApply.ked["q"]
                assert storedApply.ked["a"]["ax"] == [True]

                # Advance Guy's KEL with an event unrelated to this exchange.
                holderEventBeforeOffer = holder.interact(
                    data=[dict(note="unrelated holder activity before Offer")],
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Offer the Core credential by reference without disclosing it.
                offer, offerAtc = ipexOffer(
                    hab=holder,
                    message="Offer Core SEDI",
                    origin=core,
                    apply=storedApply,
                    ax=[True],
                )
                _exchange(offer, offerAtc, holderKvy, verifierKvy)
                storedOffer, offerPathed = cloneMessage(verifierHby, offer.said)
                assert storedOffer is not None
                assert storedOffer.raw == offer.raw
                assert offerPathed == {}
                assert storedOffer.ked["r"] == "/ipex/offer"
                assert storedOffer.ked["p"] == storedApply.said
                assert storedOffer.ked["a"]["o"] == [core.said]
                assert storedOffer.ked["a"]["ax"] == [True]

                # Offer uses Guy's establishment keys, so Vic does not need the
                # unrelated interaction when no source seal references it.
                remoteHolder = verifierHby.db.kevers.get(holder.pre)
                assert remoteHolder.sn < holder.kever.sn
                assert remoteHolder.lastEst.s == holder.kever.lastEst.s
                assert remoteHolder.lastEst.d == holder.kever.lastEst.d

                # Advance Vic's KEL before Agree creates its source anchor.
                verifierEventBeforeAgree = verifier.interact(
                    data=[dict(note="unrelated verifier activity before Agree")],
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Agree to the offer and publish the new verifier KEL anchor.
                agree, agreeAtc = ipexAgree(
                    hab=verifier,
                    message="Agree to Core SEDI disclosure",
                    offer=storedOffer,
                )
                agreeAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Guy already has Vic's inception, so send only the new
                # contiguous suffix through the source event used by Agree.
                for stream in (verifierEventBeforeAgree, agreeAnchor):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                    assert ims == bytearray()
                remoteVerifier = holderHby.db.kevers.get(verifier.pre)
                assert remoteVerifier.sn == verifier.kever.sn

                # Send the Agree message and assert it is stored
                _exchange(agree, agreeAtc, verifierKvy, holderKvy)
                storedAgree, agreePathed = cloneMessage(holderHby, agree.said)
                assert storedAgree is not None
                assert storedAgree.raw == agree.raw
                assert agreePathed == {}
                assert storedAgree.ked["r"] == "/ipex/agree"
                assert storedAgree.ked["p"] == storedOffer.said
                assert storedAgree.ked["a"]["ax"] == [True]

                # Add another unrelated holder event before the presentation
                # registry update creates the Grant's source event.
                holderEventBeforeGrant = holder.interact(
                    data=[dict(note="unrelated holder activity before Grant")],
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Build a draft Grant first for the presentation registry
                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Core SEDI",
                    origin=core,
                    artifacts=[authority],
                    agree=storedAgree,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )

                # Retrieve the registry proofs and anchor it in the holder's KEL
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(holder, presentationRegistry, presented)

                # Vic was last synchronized through Guy's challenge event.
                # Send only the interactions created since that point.
                for stream in (
                    holderEventBeforeOffer,
                    holderEventBeforeGrant,
                    presentedAnchor,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()
                remoteHolder = verifierHby.db.kevers.get(holder.pre)
                assert remoteHolder.sn == holder.kever.sn

                # Verifier receives the event in their local-store
                verifierRgy.store.accept(presentationRegistry.regk, 1, presented)

                proofedCore = _proofed(
                    core,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )

                # Build the final grant with all the proofs
                grant, grantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Core SEDI",
                    origin=proofedCore,
                    artifacts=[anchoredAuthority],
                    agree=storedAgree,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )

                # Assert that both Grants have the same SAID
                assert grant.said == draftGrant.said

                # Send the exchange and assert it was stored
                _exchange(grant, grantAtc, holderKvy, verifierKvy)
                storedGrant, grantPathed = cloneMessage(verifierHby, grant.said)
                assert storedGrant is not None
                assert storedGrant.raw == grant.raw
                assert grantPathed == {}
                assert storedGrant.pre == holder.pre
                assert storedGrant.ked["ri"] == verifier.pre
                assert storedGrant.ked["r"] == "/ipex/grant"
                assert storedGrant.ked["p"] == storedAgree.said
                assert storedGrant.ked["x"] == storedApply.ked["x"]
                assert storedGrant.ked["a"]["ax"] == [True]
                assert storedGrant.ked["a"]["o"] == [core.said]

                # The authority node carries Pat's seal and no signature.
                coreNests = loadParsedNestedSubstreams(
                    verifierHby,
                    grant.said,
                )
                assert [nest.serder.said for nest in coreNests] == [
                    core.said,
                    authority.said,
                ]
                authorityNest = coreNests[1]
                assert len(authorityNest.ssts) == 1
                assert authorityNest.ssts[0][0].qb64 == proofer.pre
                assert authorityNest.tsgs == []

                # Advance Vic's KEL again before Admit creates its anchor.
                verifierEventBeforeAdmit = verifier.interact(
                    data=[dict(note="unrelated verifier activity before Admit")],
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Build the Admit message
                admit, admitAtc = ipexAdmit(
                    hab=verifier,
                    message="Core SEDI received",
                    grant=storedGrant,
                )
                admitAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Send only Vic's suffix after the already accepted Agree anchor.
                for stream in (verifierEventBeforeAdmit, admitAnchor):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                    assert ims == bytearray()
                remoteVerifier = holderHby.db.kevers.get(verifier.pre)
                assert remoteVerifier.sn == verifier.kever.sn

                # Send the Admit message
                _exchange(admit, admitAtc, verifierKvy, holderKvy)

                # Assert KRAM cache was created
                assert (
                    verifierHby.db.kramTMSC.get(
                        keys=(holder.pre, grant.ked["x"], grant.said)
                    )
                    is not None
                )

            expected = [
                "Please present Core SEDI",
                "Offer Core SEDI",
                "Agree to Core SEDI disclosure",
                "Present Core SEDI",
                "Core SEDI received",
            ]
            assert [item["m"] for item in holderRecorder.items] == expected
            assert [item["m"] for item in verifierRecorder.items] == expected
            assert prooferHby.db.exns.get(keys=(grant.said,)) is None
            assert issuerHby.db.exns.get(keys=(grant.said,)) is None


def test_core_sedi_rejects_missing_authority_node():
    """Reject Core SEDI when its referenced authority node is not disclosed."""
    with _openSediHaberies("ipex-missing-authority") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-missing-authority", issuerHby, holderHby, verifierHby
        ) as (issuerRgy, holderRgy, verifierRgy):
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="credential-factory-residence-registry",
                prefix=issuer.pre,
            )

            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            _, authority, core, _, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            with _openIpexProcessors(
                "ipex-missing-authority", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (holderRecorder, recorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    coreIssuedAnchor,
                    holderIcp,
                    presentationRipAnchor,
                    challengeEvent,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                verifierRgy.store.accept(coreRegistry.regk, 0, coreRip)
                verifierRgy.store.accept(coreRegistry.regk, 1, coreIssued)
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                apply, applyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Request Core SEDI",
                    modifiers=dict(
                        dp=[
                            [
                                [CoreSchemaSaid, "/", []],
                                [authority.sad["s"]["$id"], "/e/utahAgent/_/", []],
                            ]
                        ]
                    ),
                    ax=[True],
                )
                _exchange(apply, applyAtc, verifierKvy, holderKvy)
                storedApply, _ = cloneMessage(holderHby, apply.said)
                assert storedApply is not None

                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present incomplete Core SEDI",
                    origin=core,
                    artifacts=[authority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(holder, presentationRegistry, presented)
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(presentationRegistry.regk, 1, presented)

                proofedCore = _proofed(
                    core,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                incompleteGrant, incompleteGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present incomplete Core SEDI",
                    origin=proofedCore,
                    artifacts=[],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                assert incompleteGrant.said == draftGrant.said

                ims = bytearray(incompleteGrant.raw)
                ims.extend(incompleteGrantAtc)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                assert verifierHby.db.exns.get(keys=(incompleteGrant.said,)) is None
                assert verifierHby.db.epse.get(keys=(incompleteGrant.said,)) is None
                assert all(item["d"] != incompleteGrant.said for item in recorder.items)


def test_sedi_rejects_presentation_proof_for_different_grant():
    """Reject a Grant carrying presentation evidence bound to another Grant."""
    with _openSediHaberies("ipex-wrong-binding") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-wrong-binding", issuerHby, holderHby, verifierHby
        ) as (issuerRgy, holderRgy, verifierRgy):
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="credential-factory-residence-registry",
                prefix=issuer.pre,
            )

            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            _, authority, core, _, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            with _openIpexProcessors(
                "ipex-wrong-binding", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (_holderRecorder, recorder, _holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    coreIssuedAnchor,
                    holderIcp,
                    presentationRipAnchor,
                    challengeEvent,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierRgy.store.accept(coreRegistry.regk, 0, coreRip)
                verifierRgy.store.accept(coreRegistry.regk, 1, coreIssued)
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                boundGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Grant bound by the presentation registry",
                    origin=core,
                    artifacts=[authority],
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=boundGrant,
                )
                presentedAnchor = _anchor(holder, presentationRegistry, presented)
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(presentationRegistry.regk, 1, presented)

                proofedCore = _proofed(
                    core,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                wrongGrant, wrongGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Different unbound Grant",
                    origin=proofedCore,
                    artifacts=[anchoredAuthority],
                    ax=[True],
                    anchorers=[],
                )
                assert wrongGrant.said != boundGrant.said

                ims = bytearray(wrongGrant.raw)
                ims.extend(wrongGrantAtc)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                assert verifierHby.db.exns.get(keys=(wrongGrant.said,)) is None
                assert recorder.items == []


def test_sedi_flow_survives_holder_and_verifier_rotations():
    """Complete graduated Residence disclosures across both parties' rotations."""
    # Keep the proofer, issuer, holder, and verifier in separate stores.
    with _openSediHaberies("ipex-location") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-location", issuerHby, holderHby, verifierHby
        ) as (issuerRgy, holderRgy, verifierRgy):
            # Set up 2 registries for the issuer: Core and Residence
            # Anchor the inception events
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)

            residenceRegistry = issuerRegistrar.makeRegistry(
                name="residence-issuer-registry",
                prefix=issuer.pre,
            )
            residenceRip = issuerRgy.store.event(residenceRegistry.regk)
            residenceRipAnchor = _anchor(issuer, residenceRegistry, residenceRip)

            # Set up presentation registry for the holder and anchor the inception event
            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            # Build the Sedi credentials
            _, authority, core, residence, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )

            # Pat anchors the reusable issuer-authority node in her KEL.
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )

            # Issue core and residence credentials, anchor them in their registries
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)
            residenceProof, residenceIssued = issuerRegistrar.issue(
                residenceRegistry, acdc=residence
            )
            residenceIssuedAnchor = _anchor(issuer, residenceRegistry, residenceIssued)

            # Compact Core so its supporting edge and issuee remain usable
            # without disclosing unrelated identity attributes.
            coreCompactor = Compactor(
                mad=dict(core.sad["a"]), makify=True, kind=Kinds.json
            )
            coreCompactor.compact()
            coreCompactor.expand(greedy=True)
            compactCoreAttributes = dict(coreCompactor.partials[("",)].mad)
            compactCore = acdcmap(
                israid=core.israid,
                uuid=core.sad["u"],
                regid=core.sad["rd"],
                schema=core.sad["s"],
                attribute=compactCoreAttributes,
                edge=core.sad["e"],
                rule=core.sad["r"],
                kind=Kinds.json,
            )
            assert compactCore.said == core.said

            # Start both location variants from the same compact attributes.
            residenceCompactor = Compactor(
                mad=dict(residence.sad["a"]), makify=True, kind=Kinds.json
            )
            residenceCompactor.compact()
            residenceCompactor.expand(greedy=True)
            compactResidenceAttributes = dict(residenceCompactor.partials[("",)].mad)

            # The first level reveals only the state voting jurisdiction.
            stateAttributes = dict(compactResidenceAttributes)
            stateAttributes["state"] = dict(residence.sad["a"]["state"])
            stateCheck = Compactor(
                mad=dict(stateAttributes, d=""), makify=True, kind=Kinds.json
            )
            stateCheck.compact()
            assert stateCheck.said == residence.sad["a"]["d"]
            stateResidence = acdcmap(
                israid=residence.israid,
                uuid=residence.sad["u"],
                regid=residence.sad["rd"],
                schema=residence.sad["s"],
                attribute=stateAttributes,
                edge=residence.sad["e"],
                rule=residence.sad["r"],
                kind=Kinds.json,
            )

            # The second level adds county and postcode but still hides street.
            districtAttributes = dict(compactResidenceAttributes)

            for field in ("state", "county", "postcode"):
                districtAttributes[field] = dict(residence.sad["a"][field])

            districtCheck = Compactor(
                mad=dict(districtAttributes, d=""), makify=True, kind=Kinds.json
            )
            districtCheck.compact()
            assert districtCheck.said == residence.sad["a"]["d"]
            districtResidence = acdcmap(
                israid=residence.israid,
                uuid=residence.sad["u"],
                regid=residence.sad["rd"],
                schema=residence.sad["s"],
                attribute=districtAttributes,
                edge=residence.sad["e"],
                rule=residence.sad["r"],
                kind=Kinds.json,
            )

            # Both compacted forms remain the originally issued credential.
            assert stateResidence.said == residence.said
            assert districtResidence.said == residence.said
            assert stateResidence.sad["a"]["state"]["value"] == "Utah"
            assert isinstance(stateResidence.sad["a"]["county"], str)
            assert districtResidence.sad["a"]["county"]["value"] == "Beaver"
            assert districtResidence.sad["a"]["postcode"]["value"] == "84713"
            assert isinstance(districtResidence.sad["a"]["street"], str)
            assert b"157 E 300 N" not in districtResidence.raw

            with _openIpexProcessors(
                "ipex-location", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                # Replicate the KEL prefixes needed for every nested proof.
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)

                # Feed the inception, registry, and issuance events of proofer
                # and issuer to both Holder and Verifier.
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    residenceRipAnchor,
                    coreIssuedAnchor,
                    residenceIssuedAnchor,
                ):
                    for kvy in (holderKvy, verifierKvy):
                        ims = bytearray(stream)
                        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                        assert ims == bytearray()

                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)

                # Feed Guy's inception, presentation-registry anchor, and
                # challenge event to Vic.
                for stream in (holderIcp, presentationRipAnchor, challengeEvent):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                # Feed the verifier's inception event to the holder
                verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Ingest the registry and issuance events into both stores.
                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                    store.accept(residenceRegistry.regk, 0, residenceRip)
                    store.accept(residenceRegistry.regk, 1, residenceIssued)

                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                # First request and disclose only the state-level jurisdiction.
                stateApply, stateApplyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Prove state residence for voting-rights review",
                    modifiers=dict(
                        dp=[
                            [
                                [ResidenceSchemaSaid, "/", ["a/state/"]],
                                [CoreSchemaSaid, "/e/coreIdentity/_/", []],
                                [
                                    authority.sad["s"]["$id"],
                                    "/e/coreIdentity/_/e/utahAgent/_/",
                                    [],
                                ],
                            ]
                        ]
                    ),
                    ax=[True],
                )

                # Send the Apply message and assert it was stored
                _exchange(stateApply, stateApplyAtc, verifierKvy, holderKvy)
                storedStateApply, stateApplyPathed = cloneMessage(
                    holderHby, stateApply.said
                )
                assert storedStateApply is not None
                assert storedStateApply.raw == stateApply.raw
                assert stateApplyPathed == {}
                assert storedStateApply.pre == verifier.pre
                assert storedStateApply.ked["ri"] == holder.pre
                assert storedStateApply.ked["r"] == "/ipex/apply"
                assert storedStateApply.ked["p"] == ""
                assert storedStateApply.ked["x"] == stateApply.ked["x"]
                assert storedStateApply.ked["a"]["ax"] == [True]

                # Guy rotates before signing and presenting the first Grant.
                holderRotation = holder.rotate(
                    framed=True,
                    version=Vrsn_2_0,
                    kind=Kinds.json,
                    gvrsn=Vrsn_2_0,
                )

                # Feed Guy's rotation event to Vic so it is up to date with Guy's key state
                ims = bytearray(holderRotation)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                holderState = verifierHby.db.kevers.get(holder.pre)
                assert holderState.lastEst.s == holder.kever.lastEst.s
                assert holderState.lastEst.d == holder.kever.lastEst.d

                # Build draft Grant for the presentation registry
                stateStamp = helping.nowIso8601()
                draftStateGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose Utah residence",
                    origin=stateResidence,
                    artifacts=[compactCore, authority],
                    apply=storedStateApply,
                    dt=stateStamp,
                    ax=[True],
                    anchorers=[],
                )
                statePresentationProof, statePresented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftStateGrant,
                )
                statePresentedAnchor = _anchor(
                    holder, presentationRegistry, statePresented
                )
                ims = bytearray(statePresentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(presentationRegistry.regk, 1, statePresented)

                proofedStateResidence = _proofed(
                    stateResidence,
                    residenceProof,
                    statePresentationProof,
                    source=(holder, statePresentedAnchor),
                )
                proofedStateCore = _proofed(
                    compactCore,
                    coreProof,
                    statePresentationProof,
                    source=(holder, statePresentedAnchor),
                )

                # Build the Final Grant with the proofs
                stateGrant, stateGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose Utah residence",
                    origin=proofedStateResidence,
                    artifacts=[proofedStateCore, anchoredAuthority],
                    apply=storedStateApply,
                    dt=stateStamp,
                    ax=[True],
                    anchorers=[],
                )
                assert stateGrant.said == draftStateGrant.said

                # Send the Final Grant and assert it was stored
                _exchange(stateGrant, stateGrantAtc, holderKvy, verifierKvy)
                storedStateGrant, stateGrantPathed = cloneMessage(
                    verifierHby,
                    stateGrant.said,
                )
                assert storedStateGrant is not None
                assert storedStateGrant.raw == stateGrant.raw
                assert stateGrantPathed == {}
                assert storedStateGrant.pre == holder.pre
                assert storedStateGrant.ked["ri"] == verifier.pre
                assert storedStateGrant.ked["r"] == "/ipex/grant"
                assert storedStateGrant.ked["p"] == storedStateApply.said
                assert storedStateGrant.ked["x"] == storedStateApply.ked["x"]
                assert storedStateGrant.ked["a"]["ax"] == [True]
                assert storedStateGrant.ked["a"]["o"] == [residence.said]
                stateNests = loadParsedNestedSubstreams(
                    verifierHby,
                    stateGrant.said,
                )
                assert [nest.serder.said for nest in stateNests] == [
                    residence.said,
                    core.said,
                    authority.said,
                ]
                carriedState = stateNests[0].serder
                assert carriedState.said == residence.said
                assert carriedState.sad["a"]["state"]["value"] == "Utah"
                assert isinstance(carriedState.sad["a"]["county"], str)
                assert isinstance(stateNests[1].serder.sad["a"]["givenName"], str)

                # Vic rotates before anchoring the Admit with the new keys.
                verifierRotation = verifier.rotate(
                    framed=True,
                    version=Vrsn_2_0,
                    kind=Kinds.json,
                    gvrsn=Vrsn_2_0,
                )

                # Feed the rotation event to the holder
                ims = bytearray(verifierRotation)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()
                verifierState = holderHby.db.kevers.get(verifier.pre)
                assert verifierState.lastEst.s == verifier.kever.lastEst.s
                assert verifierState.lastEst.d == verifier.kever.lastEst.d

                stateAdmit, stateAdmitAtc = ipexAdmit(
                    hab=verifier,
                    message="State residence received",
                    grant=storedStateGrant,
                )
                stateAdmitAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(stateAdmitAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Send the Admit message
                _exchange(stateAdmit, stateAdmitAtc, verifierKvy, holderKvy)

                # A new thread graduates disclosure to county and postcode.
                districtApply, districtApplyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Prove local district for voting-rights review",
                    modifiers=dict(
                        dp=[
                            [
                                [
                                    ResidenceSchemaSaid,
                                    "/",
                                    ["a/state/", "a/county/", "a/postcode/"],
                                ],
                                [CoreSchemaSaid, "/e/coreIdentity/_/", []],
                                [
                                    authority.sad["s"]["$id"],
                                    "/e/coreIdentity/_/e/utahAgent/_/",
                                    [],
                                ],
                            ]
                        ]
                    ),
                    ax=[True],
                )
                _exchange(districtApply, districtApplyAtc, verifierKvy, holderKvy)
                storedDistrictApply, districtApplyPathed = cloneMessage(
                    holderHby,
                    districtApply.said,
                )
                assert storedDistrictApply is not None
                assert storedDistrictApply.raw == districtApply.raw
                assert districtApplyPathed == {}
                assert storedDistrictApply.pre == verifier.pre
                assert storedDistrictApply.ked["ri"] == holder.pre
                assert storedDistrictApply.ked["r"] == "/ipex/apply"
                assert storedDistrictApply.ked["p"] == ""
                assert storedDistrictApply.ked["x"] == districtApply.ked["x"]
                assert storedDistrictApply.ked["q"] == districtApply.ked["q"]
                assert storedDistrictApply.ked["a"]["ax"] == [True]

                districtStamp = helping.nowIso8601()
                draftDistrictGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose county and postcode",
                    origin=districtResidence,
                    artifacts=[compactCore, authority],
                    apply=storedDistrictApply,
                    dt=districtStamp,
                    ax=[True],
                    anchorers=[],
                )
                districtPresentationProof, districtPresented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftDistrictGrant,
                )
                districtPresentedAnchor = _anchor(
                    holder,
                    presentationRegistry,
                    districtPresented,
                )
                ims = bytearray(districtPresentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(
                    presentationRegistry.regk, 2, districtPresented
                )

                proofedDistrictResidence = _proofed(
                    districtResidence,
                    residenceProof,
                    districtPresentationProof,
                    source=(holder, districtPresentedAnchor),
                )
                proofedDistrictCore = _proofed(
                    compactCore,
                    coreProof,
                    districtPresentationProof,
                    source=(holder, districtPresentedAnchor),
                )
                districtGrant, districtGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose county and postcode",
                    origin=proofedDistrictResidence,
                    artifacts=[proofedDistrictCore, anchoredAuthority],
                    apply=storedDistrictApply,
                    dt=districtStamp,
                    ax=[True],
                    anchorers=[],
                )
                assert districtGrant.said == draftDistrictGrant.said
                assert districtGrant.said != stateGrant.said
                _exchange(districtGrant, districtGrantAtc, holderKvy, verifierKvy)
                storedDistrictGrant, districtGrantPathed = cloneMessage(
                    verifierHby,
                    districtGrant.said,
                )
                assert storedDistrictGrant is not None
                assert storedDistrictGrant.raw == districtGrant.raw
                assert districtGrantPathed == {}
                assert storedDistrictGrant.pre == holder.pre
                assert storedDistrictGrant.ked["ri"] == verifier.pre
                assert storedDistrictGrant.ked["r"] == "/ipex/grant"
                assert storedDistrictGrant.ked["p"] == storedDistrictApply.said
                assert storedDistrictGrant.ked["x"] == storedDistrictApply.ked["x"]
                assert storedDistrictGrant.ked["a"]["ax"] == [True]
                assert storedDistrictGrant.ked["a"]["o"] == [residence.said]
                districtNests = loadParsedNestedSubstreams(
                    verifierHby,
                    districtGrant.said,
                )
                assert [nest.serder.said for nest in districtNests] == [
                    residence.said,
                    core.said,
                    authority.said,
                ]
                carriedDistrict = districtNests[0].serder
                assert carriedDistrict.said == carriedState.said
                assert carriedDistrict.sad["a"]["state"]["value"] == "Utah"
                assert carriedDistrict.sad["a"]["county"]["value"] == "Beaver"
                assert carriedDistrict.sad["a"]["postcode"]["value"] == "84713"
                assert isinstance(carriedDistrict.sad["a"]["street"], str)
                assert b"157 E 300 N" not in carriedDistrict.raw

                districtAdmit, districtAdmitAtc = ipexAdmit(
                    hab=verifier,
                    message="Local district received",
                    grant=storedDistrictGrant,
                )
                districtAdmitAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(districtAdmitAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()
                _exchange(districtAdmit, districtAdmitAtc, verifierKvy, holderKvy)

                # Each disclosure has its own timely presentation binding.
                assert (
                    verifierHby.db.kramTMSC.get(
                        keys=(holder.pre, stateGrant.ked["x"], stateGrant.said)
                    )
                    is not None
                )
                assert (
                    verifierHby.db.kramTMSC.get(
                        keys=(holder.pre, districtGrant.ked["x"], districtGrant.said)
                    )
                    is not None
                )

            expected = [
                "Prove state residence for voting-rights review",
                "Disclose Utah residence",
                "State residence received",
                "Prove local district for voting-rights review",
                "Disclose county and postcode",
                "Local district received",
            ]
            assert [item["m"] for item in holderRecorder.items] == expected
            assert [item["m"] for item in verifierRecorder.items] == expected


def test_selective_sedi_grant_does_not_leak_hidden_fields():
    """Reveal citizenship without leaking hidden Core values on the wire."""
    # Keep all four roles in independent production-style stores.
    with _openSediHaberies("ipex-citizenship") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-citizenship", issuerHby, holderHby, verifierHby
        ) as (issuerRgy, holderRgy, verifierRgy):
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)
            # The shared credential builder also requires a Residence registry.
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="credential-factory-residence-registry",
                prefix=issuer.pre,
            )

            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            _, authority, core, _, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )

            # Pat anchors Sue's authority credential for reusable verification.
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            # Collapse every independently saidified Core attribute block.
            compactor = Compactor(mad=dict(core.sad["a"]), makify=True, kind=Kinds.json)
            compactor.compact()
            compactor.expand(greedy=True)
            citizenshipAttributes = dict(compactor.partials[("",)].mad)

            # Reveal citizenship while every unrelated identity value stays hidden.
            citizenshipAttributes["legalPresenceStatus"] = dict(
                core.sad["a"]["legalPresenceStatus"]
            )
            check = Compactor(
                mad=dict(citizenshipAttributes, d=""), makify=True, kind=Kinds.json
            )
            check.compact()
            assert check.said == core.sad["a"]["d"]

            selectiveCore = acdcmap(
                israid=core.israid,
                uuid=core.sad["u"],
                regid=core.sad["rd"],
                schema=core.sad["s"],
                attribute=citizenshipAttributes,
                edge=core.sad["e"],
                rule=core.sad["r"],
                kind=Kinds.json,
            )
            assert selectiveCore.said == core.said
            assert selectiveCore.sad["a"]["legalPresenceStatus"]["value"] == "citizen"
            for field in (
                "givenName",
                "middleName",
                "familyName",
                "nameSuffix",
                "birthDate",
                "facialImageProof",
                "issuedDate",
                "expirationDate",
            ):
                assert isinstance(selectiveCore.sad["a"][field], str)
            assert b"Marty McFly" not in selectiveCore.raw
            assert b"2002-08-22" not in selectiveCore.raw

            with _openIpexProcessors(
                "ipex-citizenship", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    coreIssuedAnchor,
                ):
                    for kvy in (holderKvy, verifierKvy):
                        ims = bytearray(stream)
                        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                        assert ims == bytearray()

                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                for stream in (holderIcp, presentationRipAnchor, challengeEvent):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                # Vic asks only for the citizenship factor needed by policy.
                apply, applyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Prove citizenship for voting-rights review",
                    modifiers=dict(
                        dp=[
                            [
                                [CoreSchemaSaid, "/", ["a/legalPresenceStatus/"]],
                                [authority.sad["s"]["$id"], "/e/utahAgent/_/", []],
                            ]
                        ]
                    ),
                    ax=[True],
                )

                # Send the Apply message and assert it was stored
                _exchange(apply, applyAtc, verifierKvy, holderKvy)
                storedApply, applyPathed = cloneMessage(holderHby, apply.said)
                assert storedApply is not None
                assert storedApply.raw == apply.raw
                assert applyPathed == {}
                assert storedApply.pre == verifier.pre
                assert storedApply.ked["ri"] == holder.pre
                assert storedApply.ked["r"] == "/ipex/apply"
                assert storedApply.ked["p"] == ""
                assert storedApply.ked["x"] == apply.ked["x"]
                assert storedApply.ked["q"] == apply.ked["q"]
                assert storedApply.ked["a"]["ax"] == [True]

                # First build the draft Grant for the presentation registry
                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose citizenship status",
                    origin=selectiveCore,
                    artifacts=[authority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(holder, presentationRegistry, presented)
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(presentationRegistry.regk, 1, presented)

                proofedCore = _proofed(
                    selectiveCore,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )

                # Build the final Grant
                grant, grantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Disclose citizenship status",
                    origin=proofedCore,
                    artifacts=[anchoredAuthority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )

                # Assert privacy is preserved while legal status is disclosed
                assert grant.said == draftGrant.said
                grantWire = bytes(grant.raw) + bytes(grantAtc)
                assert b"citizen" in grantWire
                assert b'"value":"Guy"' not in grantWire
                assert b"Marty McFly" not in grantWire
                assert b'"value":"Brown"' not in grantWire
                assert b'"value":"Jr"' not in grantWire
                assert b"2002-08-22" not in grantWire

                # Send the Grant and assert it was stored
                _exchange(grant, grantAtc, holderKvy, verifierKvy)
                storedGrant, grantPathed = cloneMessage(verifierHby, grant.said)
                assert storedGrant is not None
                assert storedGrant.raw == grant.raw
                assert grantPathed == {}
                assert storedGrant.pre == holder.pre
                assert storedGrant.ked["ri"] == verifier.pre
                assert storedGrant.ked["r"] == "/ipex/grant"
                assert storedGrant.ked["p"] == storedApply.said
                assert storedGrant.ked["x"] == storedApply.ked["x"]
                assert storedGrant.ked["a"]["ax"] == [True]
                assert storedGrant.ked["a"]["o"] == [core.said]
                selectiveNests = loadParsedNestedSubstreams(
                    verifierHby,
                    grant.said,
                )
                assert [nest.serder.said for nest in selectiveNests] == [
                    core.said,
                    authority.said,
                ]
                carriedCore = selectiveNests[0].serder
                assert carriedCore.said == core.said
                assert carriedCore.sad["a"]["legalPresenceStatus"]["value"] == "citizen"
                assert isinstance(carriedCore.sad["a"]["nameSuffix"], str)
                assert isinstance(carriedCore.sad["a"]["birthDate"], str)
                assert b"Marty McFly" not in carriedCore.raw
                assert b'"value":"Jr"' not in carriedCore.raw
                assert b"2002-08-22" not in carriedCore.raw

                admit, admitAtc = ipexAdmit(
                    hab=verifier,
                    message="Citizenship evidence received",
                    grant=storedGrant,
                )
                admitAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(admitAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()
                _exchange(admit, admitAtc, verifierKvy, holderKvy)

            expected = [
                "Prove citizenship for voting-rights review",
                "Disclose citizenship status",
                "Citizenship evidence received",
            ]
            assert [item["m"] for item in holderRecorder.items] == expected
            assert [item["m"] for item in verifierRecorder.items] == expected


def test_residence_sedi_requires_every_rd_node_to_bind_grant():
    """Reject a DAG when one rd-bearing node omits presentation evidence."""
    with _openSediHaberies("ipex-missing-node-proof") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-missing-node-proof", issuerHby, holderHby, verifierHby
        ) as (issuerRgy, holderRgy, verifierRgy):
            # Set up issuer's 2 registries: Core and Residence registries
            issuerRegistrar = Registrar(rgy=issuerRgy)

            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)

            residenceRegistry = issuerRegistrar.makeRegistry(
                name="residence-issuer-registry",
                prefix=issuer.pre,
            )
            residenceRip = issuerRgy.store.event(residenceRegistry.regk)
            residenceRipAnchor = _anchor(issuer, residenceRegistry, residenceRip)

            # Set up the Holder's presentation registry
            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            # Build the Sedi Credentials
            _, authority, core, residence, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )
            signedAuthority = proofer.endorse(
                serder=authority,
                framed=False,
                gvrsn=Vrsn_2_0,
            )

            # Issue the core credential and anchor it in the core registry
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            # Issue the residence credential and anchor it in the residence registry
            residenceProof, residenceIssued = issuerRegistrar.issue(
                residenceRegistry,
                acdc=residence,
            )
            residenceIssuedAnchor = _anchor(issuer, residenceRegistry, residenceIssued)

            # Set up the Ipex
            with _openIpexProcessors(
                "ipex-missing-node-proof",
                holderHby,
                verifierHby,
                holderRgy,
                verifierRgy,
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                issuerIcp = issuer.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                holderIcp = holder.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)

                # Feed the issuer and proofer's KEL events to the verifier
                for stream in (
                    prooferIcp,
                    issuerIcp,
                    coreRipAnchor,
                    residenceRipAnchor,
                    coreIssuedAnchor,
                    residenceIssuedAnchor,
                    holderIcp,
                    presentationRipAnchor,
                    challengeEvent,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                # Feed the verifier's icp to the holder
                verifierIcp = verifier.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Feed both parties local registry store with the registry events
                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                    store.accept(residenceRegistry.regk, 0, residenceRip)
                    store.accept(residenceRegistry.regk, 1, residenceIssued)
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                # Build the Apply Ipex message
                apply, applyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Request Residence SEDI",
                    modifiers=dict(
                        dp=[
                            [
                                [ResidenceSchemaSaid, "/", []],
                                [CoreSchemaSaid, "/e/coreIdentity/_/", []],
                                [
                                    authority.sad["s"]["$id"],
                                    "/e/coreIdentity/_/e/utahAgent/_/",
                                    [],
                                ],
                            ]
                        ]
                    ),
                    ax=[True],  # Anchor required for the next messages
                )

                # Send the Apply message to the holder and assert it was stored by the holder
                _exchange(apply, applyAtc, verifierKvy, holderKvy)
                storedApply, _ = cloneMessage(holderHby, apply.said)
                assert storedApply is not None

                # First build the draft Grant to anchor it to the presentation registry
                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present incomplete Residence DAG",
                    origin=residence,
                    artifacts=[core, authority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(holder, presentationRegistry, presented)

                # Feed the KEL event to the verifier db
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                # Feed the registry event to the verifier local registry
                verifierRgy.store.accept(presentationRegistry.regk, 1, presented)

                proofedResidence = _proofed(
                    residence,
                    residenceProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                # Build an incomplete core proof
                # missing presentationProof and source=(holder, presentedAnchor)
                issuerOnlyCore = _proofed(core, coreProof)
                incompleteGrant, incompleteGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present incomplete Residence DAG",
                    origin=proofedResidence,
                    artifacts=[issuerOnlyCore, signedAuthority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                assert incompleteGrant.said == draftGrant.said

                ims = bytearray(incompleteGrant.raw)
                ims.extend(incompleteGrantAtc)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                # Core declares the holder's presentation registry (see _buildSediCredentials())
                # but carries only its issuer proof, not the presentation-registry proof
                # _verifyPresentationAuthGraph() returns a failure
                assert verifierHby.db.exns.get(keys=(incompleteGrant.said,)) is None
                assert verifierHby.db.epse.get(keys=(incompleteGrant.said,)) is None
                assert all(
                    item["d"] != incompleteGrant.said for item in verifierRecorder.items
                )


def test_sedi_grant_escrows_for_presentation_anchor():
    """Accept an escrowed Grant after its presentation-anchor KEL event arrives."""
    with _openSediHaberies("ipex-missing-presentation-anchor") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-missing-presentation-anchor",
            issuerHby,
            holderHby,
            verifierHby,
        ) as (issuerRgy, holderRgy, verifierRgy):
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)

            # The credential builder requires a Residence registry, but this
            # focused Core presentation does not publish a Residence TEL.
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="credential-factory-residence-registry",
                prefix=issuer.pre,
            )

            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder,
                presentationRegistry,
                presentationRip,
            )

            _, authority, core, _, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)

            with _openIpexProcessors(
                "ipex-missing-presentation-anchor",
                holderHby,
                verifierHby,
                holderRgy,
                verifierRgy,
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                issuerIcp = issuer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                holderIcp = holder.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Give Vic every prerequisite except the later presentation anchor.
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    coreIssuedAnchor,
                    holderIcp,
                    presentationRipAnchor,
                    challengeEvent,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierIcp = verifier.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                verifierRgy.store.accept(coreRegistry.regk, 0, coreRip)
                verifierRgy.store.accept(coreRegistry.regk, 1, coreIssued)
                verifierRgy.store.accept(
                    presentationRegistry.regk,
                    0,
                    presentationRip,
                )

                apply, applyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Request Core SEDI before anchor delivery",
                    modifiers=dict(
                        dp=[
                            [
                                [CoreSchemaSaid, "/", []],
                                [authority.sad["s"]["$id"], "/e/utahAgent/_/", []],
                            ]
                        ]
                    ),
                    ax=[True],
                )
                _exchange(apply, applyAtc, verifierKvy, holderKvy)
                storedApply, _ = cloneMessage(holderHby, apply.said)
                assert storedApply is not None

                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Core SEDI after anchor retrieval",
                    origin=core,
                    artifacts=[authority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(
                    holder,
                    presentationRegistry,
                    presented,
                )

                # Vic has the TEL update but not the KEL event that authenticates it.
                verifierRgy.store.accept(
                    presentationRegistry.regk,
                    1,
                    presented,
                )
                proofedCore = _proofed(
                    core,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                grant, grantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Core SEDI after anchor retrieval",
                    origin=proofedCore,
                    artifacts=[anchoredAuthority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                assert grant.said == draftGrant.said

                verifierKvy.exc.cues.clear()
                ims = bytearray(grant.raw)
                ims.extend(grantAtc)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                # Missing KEL evidence keeps the complete Grant in proof escrow.
                assert verifierHby.db.exns.get(keys=(grant.said,)) is None
                assert verifierHby.db.epse.get(keys=(grant.said,)) is not None
                assert all(item["d"] != grant.said for item in verifierRecorder.items)
                assert list(verifierKvy.exc.cues) == [
                    dict(kin="proof", said=grant.said)
                ]

                # Deliver the referenced KEL event and replay the preserved Grant.
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierKvy.exc.processEscrow()

                assert verifierHby.db.exns.get(keys=(grant.said,)) is not None
                assert verifierHby.db.epse.get(keys=(grant.said,)) is None
                assert any(item["d"] == grant.said for item in verifierRecorder.items)
                assert list(verifierKvy.exc.cues) == [
                    dict(kin="proof", said=grant.said),
                    dict(kin="saved", said=grant.said),
                ]
                assert [item["m"] for item in holderRecorder.items] == [
                    "Request Core SEDI before anchor delivery"
                ]


def test_residence_sedi_rejects_invalid_issuee_relationship():
    """Reject authentic SEDI nodes whose declared I2I relationship is false."""
    with _openSediHaberies("ipex-invalid-sedi-edge") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries(
            "ipex-invalid-sedi-edge",
            issuerHby,
            holderHby,
            verifierHby,
        ) as (issuerRgy, holderRgy, verifierRgy):
            issuerRegistrar = Registrar(rgy=issuerRgy)
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)
            residenceRegistry = issuerRegistrar.makeRegistry(
                name="residence-issuer-registry",
                prefix=issuer.pre,
            )
            residenceRip = issuerRgy.store.event(residenceRegistry.regk)
            residenceRipAnchor = _anchor(
                issuer,
                residenceRegistry,
                residenceRip,
            )

            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder,
                presentationRegistry,
                presentationRip,
            )

            _, authority, core, residence, challengeEvent = _buildSediCredentials(
                proofer,
                issuer,
                holder,
                coreRegistry,
                residenceRegistry,
                presentationRegistry,
            )
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )

            # Replace the valid E1E/NI2I relationship with an I2I claim.
            edge = residence.sad["e"]
            relationship = edge["coreIdentity"]
            invalidEdgeMad = dict(
                d="",
                u=edge["u"],
                coreIdentity=dict(
                    d="",
                    u=relationship["u"],
                    n=core.said,
                    s=CoreSchemaSaid,
                    o=["I2I"],
                ),
            )
            invalidEdgeCompactor = Compactor(
                mad=invalidEdgeMad,
                makify=True,
                compactify=True,
                saidive=True,
                kind=Kinds.json,
            )
            invalidEdge = invalidEdgeCompactor.partials[(".coreIdentity",)].mad
            invalidResidence = acdcmap(
                israid=residence.israid,
                uuid=residence.sad["u"],
                regid=residence.sad["rd"],
                schema=ResidenceSchemaSaid,
                attribute=residence.sad["a"],
                edge=invalidEdge,
                rule=residence.sad["r"],
                kind=Kinds.json,
            )
            SchemaValidator(schema=ResidenceSchema).validate(invalidResidence.sad)
            assert invalidResidence.israid == issuer.pre
            assert core.iseaid == holder.pre
            assert invalidResidence.israid != core.iseaid

            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)
            residenceProof, residenceIssued = issuerRegistrar.issue(
                residenceRegistry,
                acdc=invalidResidence,
            )
            residenceIssuedAnchor = _anchor(
                issuer,
                residenceRegistry,
                residenceIssued,
            )

            with _openIpexProcessors(
                "ipex-invalid-sedi-edge",
                holderHby,
                verifierHby,
                holderRgy,
                verifierRgy,
            ) as (_holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                issuerIcp = issuer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                holderIcp = holder.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    residenceRipAnchor,
                    coreIssuedAnchor,
                    residenceIssuedAnchor,
                    holderIcp,
                    presentationRipAnchor,
                    challengeEvent,
                ):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierIcp = verifier.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                    store.accept(residenceRegistry.regk, 0, residenceRip)
                    store.accept(residenceRegistry.regk, 1, residenceIssued)
                verifierRgy.store.accept(
                    presentationRegistry.regk,
                    0,
                    presentationRip,
                )

                apply, applyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Request Residence SEDI with invalid relationship",
                    modifiers=dict(
                        dp=[
                            [
                                [ResidenceSchemaSaid, "/", []],
                                [CoreSchemaSaid, "/e/coreIdentity/_/", []],
                                [
                                    authority.sad["s"]["$id"],
                                    "/e/coreIdentity/_/e/utahAgent/_/",
                                    [],
                                ],
                            ]
                        ]
                    ),
                    ax=[True],
                )
                _exchange(apply, applyAtc, verifierKvy, holderKvy)
                storedApply, _ = cloneMessage(holderHby, apply.said)
                assert storedApply is not None

                stamp = helping.nowIso8601()
                draftGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Residence SEDI with false I2I edge",
                    origin=invalidResidence,
                    artifacts=[core, authority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                presentationProof, presented = holderRegistrar.present(
                    presentationRegistry,
                    grant=draftGrant,
                )
                presentedAnchor = _anchor(
                    holder,
                    presentationRegistry,
                    presented,
                )
                ims = bytearray(presentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(
                    presentationRegistry.regk,
                    1,
                    presented,
                )

                proofedResidence = _proofed(
                    invalidResidence,
                    residenceProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                proofedCore = _proofed(
                    core,
                    coreProof,
                    presentationProof,
                    source=(holder, presentedAnchor),
                )
                grant, grantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Residence SEDI with false I2I edge",
                    origin=proofedResidence,
                    artifacts=[proofedCore, anchoredAuthority],
                    apply=storedApply,
                    dt=stamp,
                    ax=[True],
                    anchorers=[],
                )
                assert grant.said == draftGrant.said

                ims = bytearray(grant.raw)
                ims.extend(grantAtc)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()

                # All evidence is available, so the false edge is a permanent refusal.
                assert verifierHby.db.exns.get(keys=(grant.said,)) is None
                assert verifierHby.db.epse.get(keys=(grant.said,)) is None
                assert all(item["d"] != grant.said for item in verifierRecorder.items)


def test_residence_sedi_supporting_dag_through_ipex():
    """Present Residence, Core, and authority nodes as one verified DAG."""
    # Open 4 independent Haberies for each party
    with _openSediHaberies("ipex-sedi") as (
        prooferHby,
        issuerHby,
        holderHby,
        verifierHby,
        proofer,
        issuer,
        holder,
        verifier,
    ):
        with _openSediRegistries("ipex-sedi", issuerHby, holderHby, verifierHby) as (
            issuerRgy,
            holderRgy,
            verifierRgy,
        ):
            issuerRegistrar = Registrar(rgy=issuerRgy)

            # Sue independently controls both issuing registries (residence and core).
            # Initialize the registries and anchor their inception events in Sue's KEL
            coreRegistry = issuerRegistrar.makeRegistry(
                name="core-issuer-registry",
                prefix=issuer.pre,
            )
            coreRip = issuerRgy.store.event(coreRegistry.regk)
            coreRipAnchor = _anchor(issuer, coreRegistry, coreRip)

            residenceRegistry = issuerRegistrar.makeRegistry(
                name="residence-issuer-registry",
                prefix=issuer.pre,
            )
            residenceRip = issuerRgy.store.event(residenceRegistry.regk)
            residenceRipAnchor = _anchor(issuer, residenceRegistry, residenceRip)

            # Guy independently controls his presentation registry.
            # Initialize the registry and anchor its inception event in Guy's KEL
            holderRegistrar = Registrar(rgy=holderRgy)
            presentationRegistry = holderRegistrar.makeRegistry(
                name="holder-presentation-registry",
                prefix=holder.pre,
            )
            presentationRip = holderRgy.store.event(presentationRegistry.regk)
            presentationRipAnchor = _anchor(
                holder, presentationRegistry, presentationRip
            )

            # Build Guy's 3 SEDI credentials and the SMAID challenge for the IAR
            _, authority, core, residence, challengeEvent = _buildSediCredentials(
                proofer,  # Pat proofing agent signs the IAR
                issuer,  # Sue issues them
                holder,  # Guy holds them
                coreRegistry,  # Sue's 2 registries
                residenceRegistry,
                presentationRegistry,  # Guy's presentation registry
            )

            # Pat anchors the authority node once instead of re-signing it.
            authorityAnchor = proofer.interact(
                data=[dict(d=authority.said)],
                framed=True,
                gvrsn=Vrsn_2_0,
            )
            anchoredAuthority = _proofed(
                authority,
                source=(proofer, authorityAnchor),
            )

            # Sue issues and anchors Guy's two registry-backed credentials.
            coreProof, coreIssued = issuerRegistrar.issue(coreRegistry, acdc=core)
            coreIssuedAnchor = _anchor(issuer, coreRegistry, coreIssued)
            residenceProof, residenceIssued = issuerRegistrar.issue(
                residenceRegistry,
                acdc=residence,
            )
            residenceIssuedAnchor = _anchor(issuer, residenceRegistry, residenceIssued)

            # Set up each exchange party's independent IPEX/KRAM pipeline.
            with _openIpexProcessors(
                "ipex-sedi", holderHby, verifierHby, holderRgy, verifierRgy
            ) as (holderRecorder, verifierRecorder, holderKvy, verifierKvy):
                prooferIcp = proofer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                issuerIcp = issuer.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Both Verifier (Vic) and Holder (Guy) need Pat's and Sue's KEL evidence.
                for stream in (
                    prooferIcp,
                    authorityAnchor,
                    issuerIcp,
                    coreRipAnchor,
                    residenceRipAnchor,
                    coreIssuedAnchor,
                    residenceIssuedAnchor,
                ):
                    for kvy in (holderKvy, verifierKvy):
                        ims = bytearray(stream)
                        Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
                        assert ims == bytearray()

                holderIcp = holder.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Replicate Guy's complete KEL so Vic can authenticate Guy's
                # messages, verify the presentation-registry inception, and receive
                # the SMAID proofing challenge before processing later KEL anchors.
                for stream in (holderIcp, presentationRipAnchor, challengeEvent):
                    ims = bytearray(stream)
                    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                    assert ims == bytearray()

                verifierIcp = verifier.msgOwnEvent(
                    sn=0,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )

                # Guy needs Vic's KEL to authenticate incoming replies.
                ims = bytearray(verifierIcp)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Simulate observer delivery of foreign TEL evidence.
                # Give the holder and verifier Sue's registry and issuance events.
                for store in (holderRgy.store, verifierRgy.store):
                    store.accept(coreRegistry.regk, 0, coreRip)
                    store.accept(coreRegistry.regk, 1, coreIssued)
                    store.accept(residenceRegistry.regk, 0, residenceRip)
                    store.accept(residenceRegistry.regk, 1, residenceIssued)

                # Feed the verifier with Guy's presentation registry inception
                verifierRgy.store.accept(presentationRegistry.regk, 0, presentationRip)

                # Request Residence and every credential in its supporting DAG.
                residenceApply, residenceApplyAtc = ipexApply(
                    hab=verifier,
                    recp=holder.pre,
                    message="Please present Residence SEDI",
                    modifiers=dict(
                        dp=[
                            [
                                [ResidenceSchemaSaid, "/", []],
                                [CoreSchemaSaid, "/e/coreIdentity/_/", []],
                                [
                                    authority.sad["s"]["$id"],
                                    "/e/coreIdentity/_/e/utahAgent/_/",
                                    [],
                                ],
                            ]
                        ]
                    ),
                    ax=[True],
                )

                # Send the Residence Apply message to the holder and verify it is stored
                _exchange(residenceApply, residenceApplyAtc, verifierKvy, holderKvy)
                storedResidenceApply, residenceApplyPathed = cloneMessage(
                    holderHby,
                    residenceApply.said,
                )
                assert storedResidenceApply is not None
                assert storedResidenceApply.raw == residenceApply.raw
                assert residenceApplyPathed == {}
                assert storedResidenceApply.pre == verifier.pre
                assert storedResidenceApply.ked["ri"] == holder.pre
                assert storedResidenceApply.ked["r"] == "/ipex/apply"
                assert storedResidenceApply.ked["p"] == ""
                assert storedResidenceApply.ked["x"] == residenceApply.ked["x"]
                assert storedResidenceApply.ked["q"] == residenceApply.ked["q"]
                assert storedResidenceApply.ked["a"]["ax"] == [True]

                # Build the Residence Grant message
                residenceStamp = helping.nowIso8601()

                # Start with the draft Grant which will be used for anchoring in the presentation registry
                # before the final Grant is built with the proofs
                draftResidenceGrant, _ = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Residence and supporting Core SEDI",
                    origin=residence,
                    artifacts=[core, authority],
                    apply=storedResidenceApply,
                    dt=residenceStamp,
                    ax=[True],
                    anchorers=[],
                )

                # Bind that grant to the presentation registry and anchor it in the holder's KEL
                residencePresentationProof, residencePresented = (
                    holderRegistrar.present(
                        presentationRegistry,
                        grant=draftResidenceGrant,
                    )
                )
                residencePresentedAnchor = _anchor(
                    holder,
                    presentationRegistry,
                    residencePresented,
                )

                # Feed the verifier with the presentation registry event for that Grant
                ims = bytearray(residencePresentedAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=verifierKvy)
                assert ims == bytearray()
                verifierRgy.store.accept(
                    presentationRegistry.regk, 1, residencePresented
                )

                # Each rd-bearing node carries its node-local Grant binding.
                proofedResidence = _proofed(
                    residence,
                    residenceProof,  # proof of issuance from Sue's registry
                    residencePresentationProof,  # proof of presentation from Guy's registry
                    source=(
                        holder,
                        residencePresentedAnchor,
                    ),  # proof of anchoring in Guy's KEL
                )
                proofedSupportingCore = _proofed(
                    core,
                    coreProof,  # proof of issuance from Sue's registry
                    residencePresentationProof,  # proof of presentation from Guy's registry
                    source=(
                        holder,
                        residencePresentedAnchor,
                    ),  # proof of anchoring in Guy's KEL
                )

                # Now Build the final Residence Grant message with the proofs and anchors
                residenceGrant, residenceGrantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present Residence and supporting Core SEDI",
                    origin=proofedResidence,
                    artifacts=[proofedSupportingCore, anchoredAuthority],
                    apply=storedResidenceApply,
                    dt=residenceStamp,
                    ax=[True],
                    anchorers=[],
                )

                # Assert that the final Residence Grant has the same SAID as the draft Residence Grant
                assert residenceGrant.said == draftResidenceGrant.said

                # Send the Residence Grant message to the verifier and verify it is stored
                _exchange(residenceGrant, residenceGrantAtc, holderKvy, verifierKvy)
                storedResidenceGrant, residenceGrantPathed = cloneMessage(
                    verifierHby,
                    residenceGrant.said,
                )
                assert storedResidenceGrant is not None
                assert storedResidenceGrant.raw == residenceGrant.raw
                assert residenceGrantPathed == {}
                assert storedResidenceGrant.pre == holder.pre
                assert storedResidenceGrant.ked["ri"] == verifier.pre
                assert storedResidenceGrant.ked["r"] == "/ipex/grant"
                assert storedResidenceGrant.ked["p"] == storedResidenceApply.said
                assert storedResidenceGrant.ked["x"] == storedResidenceApply.ked["x"]
                assert storedResidenceGrant.ked["a"]["ax"] == [True]
                assert storedResidenceGrant.ked["a"]["o"] == [residence.said]

                # Load nested substreams for assertions
                residenceNests = loadParsedNestedSubstreams(
                    verifierHby,
                    residenceGrant.said,
                )
                assert [nest.serder.said for nest in residenceNests] == [
                    residence.said,
                    core.said,
                    authority.said,
                ]

                # Build Admit message
                residenceAdmit, residenceAdmitAtc = ipexAdmit(
                    hab=verifier,
                    message="Residence SEDI received",
                    grant=storedResidenceGrant,
                )
                residenceAdmitAnchor = verifier.msgOwnEvent(
                    sn=verifier.kever.sn,
                    framed=True,
                    gvrsn=Vrsn_2_0,
                )
                ims = bytearray(residenceAdmitAnchor)
                Parser(version=Vrsn_2_0).parse(ims=ims, kvy=holderKvy)
                assert ims == bytearray()

                # Send the Admit message to the holder and verify it is stored
                _exchange(residenceAdmit, residenceAdmitAtc, verifierKvy, holderKvy)

                # KRAM records when Vic accepted the authenticated Grant.
                assert (
                    verifierHby.db.kramTMSC.get(
                        keys=(holder.pre, residenceGrant.ked["x"], residenceGrant.said)
                    )
                    is not None
                )

            expectedMessages = [
                "Please present Residence SEDI",
                "Present Residence and supporting Core SEDI",
                "Residence SEDI received",
            ]
            assert [item["m"] for item in holderRecorder.items] == expectedMessages
            assert [item["m"] for item in verifierRecorder.items] == expectedMessages

            # Only the two exchange parties store the IPEX messages.
            assert (
                prooferHby.db.exns.get(keys=(residenceGrant.said,)) is None
            )  # Pat is not a party to the IPEX exchange
            assert (
                issuerHby.db.exns.get(keys=(residenceGrant.said,)) is None
            )  # Sue is not a party to the IPEX exchange
            assert holderHby.db.exns.get(keys=(residenceGrant.said,)) is not None
            assert verifierHby.db.exns.get(keys=(residenceGrant.said,)) is not None

            # The final Grant reaches the verifier after all checks pass.
            notice = next(
                item
                for item in verifierRecorder.items
                if item["d"] == residenceGrant.said
            )
            assert notice == dict(
                r="/exn/ipex/grant",
                d=residenceGrant.said,
                m="Present Residence and supporting Core SEDI",
            )
