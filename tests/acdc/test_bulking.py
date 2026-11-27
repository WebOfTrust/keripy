# -*- coding: utf-8 -*-
"""Tests for the experimental shared-registry bulk issuance POC."""

import pytest

from keri import Vrsn_2_0
from keri.acdc import (Regery, Registrar, acdcmap, blindate,
                       grant as ipexGrant, loadHandlers, regcept)
from keri.acdc.bulking import (BulkDeriver,
                               makeCommitment, parseProof, verifyMembership,
                               vetSharedList)
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import (Blinder, Diger, Kevery, MtrDex, Parser, Salter,
                       incept, interact, messagize, rotate)
from keri.kering import (ConfigurationError, InvalidValueError,
                          MisbindingError, MissingAnchorError,
                          UnverifiedBlindError)
from keri.peer import Exchanger


class Recorder:
    """Collect notifications emitted for accepted IPEX messages."""

    def __init__(self):
        self.items = []

    def add(self, attrs):
        self.items.append(attrs)


def _anchor(hab, registry, serder):
    """Anchor one TEL event in the controlling habitat's KEL."""
    seal = dict(i=registry.regk, s=serder.sad["n"], d=serder.said)
    hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
    # Promote the now-anchored TEL event from escrow.
    assert registry.anchorMsg(serder.said) is True


def _publishKel(hab, kevery, start=0):
    """Parse the habitat's KEL from ``start`` into a remote verifier DB."""
    parser = Parser(version=Vrsn_2_0)
    for sn in range(start, hab.kever.sn + 1):
        event = hab.msgOwnEvent(sn=sn, framed=True, gvrsn=Vrsn_2_0)
        parser.parse(ims=bytearray(event), kvy=kevery)


def _proofed(acdc, blinder):
    """Attach one registry-state disclosure to its IPEX ACDC node."""
    return messagize(serder=acdc,
                     bonds=[blinder.data],
                     framed=False,
                     gvrsn=Vrsn_2_0)


def test_shared_list_primitives_cross_hex_boundary():
    """Derivation and membership stay deterministic beyond copy index nine."""
    deriver = BulkDeriver(b"0123456789abcdef", temp=True)

    saids = [Diger(ser=f"copy-{k}".encode()).qb64 for k in range(16)]
    blindings = [deriver.v(k) for k in range(16)]

    # Pin top-level path "a" for hexadecimal index ten.
    assert deriver.u(10) == "aLoIvqLyLhMXXHYp0wM0U_1xXXwptTY9QrzeyKUul9UB"

    # Pin nested path "a/10" for indices ten and sixteen.
    assert deriver.u(10, 16) == "aINrudC-omkMxzldWuyKbyou8bhyY589ihc5biT7oSPj"

    # Pin blinding path "a." for hexadecimal index ten.
    assert deriver.v(10) == "aCzisOax8K6NHY5op8ToguCG59MRyFl1dQ6ohwzJsflX"

    # The same salt and paths deterministically regenerate every UUID.
    assert [BulkDeriver(b"0123456789abcdef", temp=True).u(k)
            for k in range(16)] == [deriver.u(k) for k in range(16)]

    # Keep UUID and blinding derivation spaces disjoint.
    assert all(deriver.u(k) != deriver.v(k) for k in range(16))

    # Require every generated top-level UUID to be unique.
    assert len({deriver.u(k) for k in range(16)}) == 16

    members, aggregate = makeCommitment(blindings, saids)

    # Pin the complete set's aggregate commitment.
    assert aggregate == "EPZhFtng743xAPc7cNXfwhlI1gaivJ63Pr3TOkEkr9xX"

    # Pin index ten's blinded member commitment.
    assert members[10] == "EDRtDq5ceQqoBEtd7_0piaFA1_wGAP_97q-y4P3NWrhI"

    assert all(verifyMembership(saids[k], blindings[k], members, aggregate)
               for k in range(16))

    outsider = Diger(ser=b"outsider").qb64
    tampered = (Diger(ser=b"tampered").qb64,) + members[1:]
    wrong = Diger(ser=b"wrong aggregate").qb64

    # Reject a member paired with another member's blinding factor.
    assert not verifyMembership(saids[0], blindings[1], members, aggregate)

    # Reject a SAID absent from the committed list.
    assert not verifyMembership(outsider, blindings[0], members, aggregate)

    # Reject a list that no longer reproduces B.
    assert not verifyMembership(saids[0], blindings[0], tampered, aggregate)

    # Reject a reordered list against the original B.
    assert not verifyMembership(saids[0], blindings[0], reversed(members), aggregate)

    # Reject a commitment unrelated to the supplied list.
    assert not verifyMembership(saids[0], blindings[0], members, wrong)

    # Reject malformed blinding material without raising.
    assert not verifyMembership(saids[0], "not-a-nonce", members, aggregate)


def test_shared_list_rejects_invalid_inputs():
    """The API refuses invalid indices and malformed commitment inputs."""
    deriver = BulkDeriver(b"0123456789abcdef", temp=True)

    # Reject salts that Salter would otherwise truncate or cannot use as raw bytes.
    for salt in (b"0123456789abcde", b"0123456789abcdef0", "0123456789abcdef"):
        with pytest.raises(InvalidValueError):
            BulkDeriver(salt, temp=True)

    for index in (-1, True, 1.5, "a"):
        with pytest.raises(InvalidValueError):
            deriver.u(index)

    # Reject a negative nested index.
    with pytest.raises(InvalidValueError):
        deriver.u(0, -1)

    # Reject an empty bulk set.
    with pytest.raises(InvalidValueError):
        makeCommitment([], [])

    # Reject unequal blinding and SAID counts.
    with pytest.raises(InvalidValueError):
        makeCommitment([deriver.v(0)], [])

    # Reject non-iterable commitment inputs.
    with pytest.raises(InvalidValueError):
        makeCommitment(None, None)

    # Reject malformed blinding-factor text.
    with pytest.raises(InvalidValueError):
        makeCommitment(["not-a-nonce"], [Diger(ser=b"copy").qb64])

    # Reject malformed SAID text.
    with pytest.raises(InvalidValueError):
        makeCommitment([deriver.v(0)], ["not-a-said"])

    # Reject binary SAIDs because the draft hashes qb64 text.
    with pytest.raises(InvalidValueError):
        makeCommitment([deriver.v(0)], [Diger(ser=b"copy").qb64b])

    proof = dict(blinding=deriver.v(0),
                 members=[Diger(ser=b"member").qb64])
    assert set(proof) == {"blinding", "members"}
    proof["members"] = ["not-a-digest"]
    with pytest.raises(InvalidValueError):
        parseProof(proof)

    # Reject unexpected proof fields.
    proof = dict(blinding=deriver.v(0),
                 members=[Diger(ser=b"member").qb64],
                 extra="unsupported")
    with pytest.raises(InvalidValueError):
        parseProof(proof)

    # Reject incomplete membership material.
    proof = dict(blinding=deriver.v(0),
                 members=[Diger(ser=b"member").qb64])
    del proof["members"]
    with pytest.raises(InvalidValueError):
        parseProof(proof)


def test_shared_list_issuer_grants_bulk_copy_to_holder():
    """Issue a bulk set and deliver one copy to its holder through IPEX."""
    with (openHby(name="bulk-poc-ipex-issuance-issuer", base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="bulk-poc-ipex-issuance-holder", base="test",
                  version=Vrsn_2_0) as holderHby):

        issuer = issuerHby.makeHab(name="issuer")
        holder = holderHby.makeHab(name="holder")

        issuerRgy = Regery(hby=issuerHby, name="bulk-issuance-issuer", temp=True)
        holderRgy = Regery(hby=holderHby, name="bulk-issuance-holder", temp=True)
        try:
            # Create and anchor the shared registry inception.
            registrar = Registrar(rgy=issuerRgy)
            registry = registrar.makeRegistry(name="bulk", prefix=issuer.pre)
            rip = issuerRgy.store.event(registry.regk)
            _anchor(issuer, registry, rip)

            deriver = BulkDeriver(b"bulk-ipex-issue0", temp=True)
            copies = [acdcmap(israid=issuer.pre,
                              uuid=deriver.u(k),
                              regid=registry.regk,
                              attribute=dict(d="", u=deriver.u(k, 0),
                                             role="member"),
                              iseaid=holder.pre)
                      for k in range(2)]
            blindings = [deriver.v(k) for k in range(2)]

            members, aggregate = makeCommitment(blindings, [copy.said for copy in copies])
            issuedBlinder, issued = registrar.issueBulk(registry, aggregate=aggregate)
            _anchor(issuer, registry, issued)

            # Load the issuer KEL and registry TEL into the holder's stores.
            remoteKvy = Kevery(db=holderHby.db, lax=False, local=False)
            _publishKel(issuer, remoteKvy)
            holderRgy.store.accept(registry.regk, 0, rip)
            holderRgy.store.accept(registry.regk, 1, issued)

            recorder = Recorder()
            exchanger = Exchanger(hby=holderHby, handlers=[])
            loadHandlers(hby=holderHby,
                         exc=exchanger,
                         notifier=recorder,
                         rgy=holderRgy)

            # Grant one selected copy with its bulk membership proof.
            proof = dict(blinding=blindings[0], members=list(members))
            grant, grantAtc = ipexGrant(
                hab=issuer,
                recp=holder.pre,
                message="Issue one bulk credential copy.",
                origin=_proofed(copies[0], issuedBlinder),
                attrs=dict(bulkMembershipProof=proof),
            )

            # Parse and authenticate the Grant against the local TEL head.
            stream = bytearray(grant.raw + bytes(grantAtc))
            Parser(version=Vrsn_2_0).parse(
                ims=stream, framed=False, exc=exchanger)
            assert stream == bytearray()
            assert holderHby.db.exns.get(keys=(grant.said,)) is not None
            assert holderHby.db.epse.get(keys=(grant.said,)) is None
            assert len(recorder.items) == 1

            # Confirm IPEX recorded the real bulk registry state.
            record = holderHby.db.exrs.get(
                keys=(grant.said, copies[0].said))
            assert record.regid == registry.regk
            assert record.said == issued.said
            assert record.sn == 1
            assert record.state == "issued"

            blinding, disclosed = parseProof(
                grant.ked["a"]["bulkMembershipProof"])
            assert verifyMembership(copies[0].said, blinding,
                                    disclosed, aggregate)
        finally:
            issuerRgy.close()
            holderRgy.close()


def test_shared_list_two_ipex_presentations_two_verifiers():
    """Have two independent IPEX verifiers authenticate separate bulk copies."""
    with (openHby(name="bulk-poc-ipex-issuer", base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="bulk-poc-ipex-holder", base="test",
                  version=Vrsn_2_0) as holderHby,
          openHby(name="bulk-poc-ipex-verifier-1", base="test",
                  version=Vrsn_2_0) as verifier1Hby,
          openHby(name="bulk-poc-ipex-verifier-2", base="test",
                  version=Vrsn_2_0) as verifier2Hby):

        issuer = issuerHby.makeHab(name="issuer")
        # Give one holder two AIDs for separate presentations.
        holders = [holderHby.makeHab(name=f"holder-{k}") for k in range(2)]
        verifiers = [verifier1Hby.makeHab(name="verifier-1"),
                     verifier2Hby.makeHab(name="verifier-2")]
        issuerRgy = Regery(hby=issuerHby, name="bulk-ipex-issuer", temp=True)
        verifierRgys = [Regery(hby=verifier1Hby,
                               name="bulk-ipex-verifier-1", temp=True),
                        Regery(hby=verifier2Hby,
                               name="bulk-ipex-verifier-2", temp=True)]
        try:
            # Create and anchor one issuer-controlled shared registry.
            registrar = Registrar(rgy=issuerRgy)
            registry = registrar.makeRegistry(name="bulk", prefix=issuer.pre)
            rip = issuerRgy.store.event(registry.regk)
            _anchor(issuer, registry, rip)

            deriver = BulkDeriver(b"bulk-ipex-salt-0", temp=True)
            copies = [acdcmap(israid=issuer.pre,
                              uuid=deriver.u(k),
                              regid=registry.regk,
                              attribute=dict(d="", u=deriver.u(k, 0),
                                             role="member"),
                              iseaid=holders[k].pre)
                      for k in range(2)]
            blindings = [deriver.v(k) for k in range(2)]
            members, aggregate = makeCommitment(
                blindings, [copy.said for copy in copies])

            # Issue and anchor the aggregate once for the complete set.
            issuedBlinder, issued = registrar.issueBulk(
                registry, aggregate=aggregate)
            _anchor(issuer, registry, issued)

            # Give each verifier an independent copy of the issuer KEL and TEL.
            verifierHbys = [verifier1Hby, verifier2Hby]
            for verifierHby, verifierRgy in zip(verifierHbys, verifierRgys):
                remoteKvy = Kevery(db=verifierHby.db, lax=False, local=False)
                _publishKel(issuer, remoteKvy)
                for holder in holders:
                    _publishKel(holder, remoteKvy)
                verifierRgy.store.accept(registry.regk, 0, rip)
                verifierRgy.store.accept(registry.regk, 1, issued)

            grants = []
            grantStreams = []

            # Present a different copy to each verifier through its real handler.
            for k, (holder, verifier, verifierHby, verifierRgy) in enumerate(
                    zip(holders, verifiers, verifierHbys, verifierRgys)):
                recorder = Recorder()
                exchanger = Exchanger(hby=verifierHby, handlers=[])
                loadHandlers(hby=verifierHby,
                             exc=exchanger,
                             notifier=recorder,
                             rgy=verifierRgy)

                proof = dict(blinding=blindings[k], members=list(members))

                # The handler must refuse malformed membership material.
                if k == 0:
                    malformed = dict(proof)
                    malformed["members"] = ["not-a-digest"]
                    refused, refusedAtc = ipexGrant(
                        hab=holder,
                        recp=verifier.pre,
                        message="Present malformed bulk proof.",
                        origin=_proofed(copies[k], issuedBlinder),
                        attrs=dict(bulkMembershipProof=malformed),
                    )
                    refusedStream = bytearray(refused.raw + bytes(refusedAtc))
                    Parser(version=Vrsn_2_0).parse(
                        ims=refusedStream, framed=False, exc=exchanger)
                    assert refusedStream == bytearray()
                    assert verifierHby.db.exns.get(keys=(refused.said,)) is None
                    assert recorder.items == []

                grant, grantAtc = ipexGrant(
                    hab=holder,
                    recp=verifier.pre,
                    message="Present one bulk-issued credential copy.",
                    origin=_proofed(copies[k], issuedBlinder),
                    attrs=dict(bulkMembershipProof=proof),
                )

                # Parse, authenticate, and persist the Grant as this verifier.
                stream = bytearray(grant.raw + bytes(grantAtc))
                Parser(version=Vrsn_2_0).parse(
                    ims=stream, framed=False, exc=exchanger)
                assert stream == bytearray()
                assert verifierHby.db.exns.get(keys=(grant.said,)) is not None
                assert len(recorder.items) == 1

                record = verifierHby.db.exrs.get(
                    keys=(grant.said, copies[k].said))
                assert record.regid == registry.regk
                assert record.said == issued.said
                assert record.state == "issued"

                blinding, disclosed = parseProof(
                    grant.ked["a"]["bulkMembershipProof"])
                assert verifyMembership(copies[k].said, blinding,
                                        disclosed, aggregate)
                grants.append(grant)
                grantStreams.append(grant.raw + bytes(grantAtc))

            # Each context uses a distinct holder AID, ACDC SAID, and blinding.
            assert holders[0].pre != holders[1].pre
            assert copies[0].said != copies[1].said
            assert blindings[0] != blindings[1]

            # Neither presentation discloses the other copy's raw SAID.
            assert copies[1].said.encode() not in grantStreams[0]
            assert copies[0].said.encode() not in grantStreams[1]

            # The signed grants are distinct and target different verifiers.
            assert grants[0].said != grants[1].said
            assert grants[0].ked["ri"] != grants[1].ked["ri"]

            # Shared-list proofs remain correlatable after full disclosure.
            proof0 = grants[0].ked["a"]["bulkMembershipProof"]
            proof1 = grants[1].ked["a"]["bulkMembershipProof"]
            assert copies[0].sad["rd"] == copies[1].sad["rd"] == registry.regk
            assert proof0["members"] == proof1["members"] == list(members)
        finally:
            issuerRgy.close()
            for verifierRgy in verifierRgys:
                verifierRgy.close()


def test_shared_list_real_tel_kel_persistence_and_revocation(tmp_path):
    """Issue, persist, remotely verify, and revoke one shared bulk set."""

    with (openHby(name="bulk-poc-issuer", base="test",
                  version=Vrsn_2_0) as issuerHby,
          openHby(name="bulk-poc-verifier", base="test",
                  version=Vrsn_2_0) as verifierHby,
          openHby(name="bulk-poc-empty-verifier", base="test",
                  version=Vrsn_2_0) as emptyVerifierHby,
          openHby(name="bulk-poc-foreign-verifier", base="test",
                  version=Vrsn_2_0) as foreignVerifierHby):

        issuer = issuerHby.makeHab(name="issuer")
        holder = issuerHby.makeHab(name="holder")
        storeName = "shared-list-poc"

        # Persist the registry so the test can close and recover it.
        baser = RegBaser(name=storeName,
                         headDirPath=str(tmp_path),
                         temp=False)
        rgy = Regery(hby=issuerHby, baser=baser)

        reopened = None
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="bulk", prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)

            # Anchor the inception event in the issuer KEL.
            _anchor(issuer, registry, rip)

            deriver = BulkDeriver(b"bulk-poc-salt-00", temp=True)
            copies = [acdcmap(israid=issuer.pre,
                              uuid=deriver.u(k),
                              regid=registry.regk,
                              attribute=dict(d="", u=deriver.u(k, 0), role="member"),
                              iseaid=holder.pre)
                      for k in range(16)]

            regenerated = BulkDeriver(b"bulk-poc-salt-00", temp=True)
            regeneratedCopy = acdcmap(
                israid=issuer.pre,
                uuid=regenerated.u(10),
                regid=registry.regk,
                attribute=dict(d="", u=regenerated.u(10, 0), role="member"),
                iseaid=holder.pre,
            )

            assert regeneratedCopy.said == copies[10].said
            assert len({copy.said for copy in copies}) == 16

            blindings = [deriver.v(k) for k in range(16)]
            members, aggregate = makeCommitment(blindings, [copy.said for copy in copies])

            # Bulk issuance accepts only Blake3-256 aggregate digests.
            with pytest.raises(ConfigurationError):
                registrar.issueBulk(registry, aggregate="not-a-digest")

            # Reject a valid digest using the wrong algorithm.
            with pytest.raises(ConfigurationError):
                registrar.issueBulk(
                    registry,
                    aggregate=Diger(ser=b"wrong code",
                                    code=MtrDex.SHA2_256).qb64,
                )

            # Reject caller-controlled blinded state material.
            with pytest.raises(ConfigurationError):
                registrar.issueBulk(registry, aggregate=aggregate, blinder=object())

            # Keep individual issuance strict about ACDC inputs.
            with pytest.raises(ConfigurationError):
                registrar.issue(registry, acdc=aggregate)

            issuedProof, issued = registrar.issueBulk(registry, aggregate=aggregate)

            _anchor(issuer, registry, issued)

            regk = registry.regk
            rgy.close()

            # Reopen the registry from disk and recover its current TEL head.
            reopened = Regery(
                hby=issuerHby,
                baser=RegBaser(name=storeName,
                               headDirPath=str(tmp_path),
                               temp=False),
            )

            registry = reopened.registryByName("bulk")

            assert registry is not None
            assert registry.regk == regk
            assert reopened.store.headEvent(regk).said == issued.said

            # Verify with an independently replicated issuer KEL.
            remoteKvy = Kevery(db=verifierHby.db, lax=False, local=False)
            _publishKel(issuer, remoteKvy)

            # Verify copy ten against the issued shared-list state.
            record = vetSharedList(rip=rip,
                                   updates=[issued],
                                   db=verifierHby.db,
                                   blinders=[issuedProof],
                                   acdc=copies[10],
                                   blinding=blindings[10],
                                   members=members)
            assert record.regid == regk
            assert record.acdc == aggregate
            assert record.state == "issued"
            assert record.binding == "bulk"

            # Reject valid TEL evidence when no issuer KEL is available.
            with pytest.raises(MissingAnchorError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=emptyVerifierHby.db,
                              blinders=[issuedProof],
                              acdc=copies[10],
                              blinding=blindings[10],
                              members=members)

            # Matching seals in the holder's KEL cannot replace issuer anchors.
            foreignSeals = [dict(i=registry.regk, s=event.sad["n"],
                                 d=event.said)
                            for event in (rip, issued)]
            holder.interact(data=foreignSeals, framed=True, gvrsn=Vrsn_2_0)
            foreignKvy = Kevery(db=foreignVerifierHby.db, lax=False, local=False)
            _publishKel(holder, foreignKvy)

            # Reject foreign anchors even when their seals match.
            with pytest.raises(MissingAnchorError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=foreignVerifierHby.db,
                              blinders=[issuedProof],
                              acdc=copies[10],
                              blinding=blindings[10],
                              members=members)
            # Reject copy ten with copy eleven's blinding factor.
            with pytest.raises(MisbindingError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=verifierHby.db,
                              blinders=[issuedProof],
                              acdc=copies[10],
                              blinding=blindings[11],
                              members=members)
            # Reject a reordered list because it targets another aggregate.
            with pytest.raises(MisbindingError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=verifierHby.db,
                              blinders=[issuedProof],
                              acdc=copies[10],
                              blinding=blindings[10],
                              members=reversed(members))

            wrongRegistry = acdcmap(israid=issuer.pre,
                                    uuid=deriver.u(0),
                                    regid=Diger(ser=b"wrong registry").qb64,
                                    attribute=dict(d="", u=deriver.u(0, 0),
                                                   role="member"),
                                    iseaid=holder.pre)
            # Reject a credential whose rd differs from the shared registry.
            with pytest.raises(MisbindingError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=verifierHby.db,
                              blinders=[issuedProof],
                              acdc=wrongRegistry,
                              blinding=blindings[0],
                              members=members)

            wrongIssuer = acdcmap(israid=holder.pre,
                                  uuid=deriver.u(0),
                                  regid=regk,
                                  attribute=dict(d="", u=deriver.u(0, 0),
                                                 role="member"),
                                  iseaid=holder.pre)
            # Reject a credential whose issuer differs from the registry issuer.
            with pytest.raises(MisbindingError):
                vetSharedList(rip=rip,
                              updates=[issued],
                              db=verifierHby.db,
                              blinders=[issuedProof],
                              acdc=wrongIssuer,
                              blinding=blindings[0],
                              members=members)

            registrar = Registrar(rgy=reopened)

            # Stage whole-set revocation against the same aggregate B.
            revokedProof, revoked = registrar.issueBulk(registry,
                                                        aggregate=aggregate,
                                                        state="revoked")

            priorKelSn = issuer.kever.sn
            _anchor(issuer, registry, revoked)
            _publishKel(issuer, remoteKvy, start=priorKelSn + 1)
            assert reopened.store.headEvent(regk).said == revoked.said

            # Verification reports the state in the chain supplied by the caller.
            stale = vetSharedList(rip=rip,
                                  updates=[issued],
                                  db=verifierHby.db,
                                  blinders=[issuedProof],
                                  acdc=copies[10],
                                  blinding=blindings[10],
                                  members=members)
            # Applications must synchronize and supply the current TEL chain.
            assert stale.state == "issued"

            # Reject stale issuance disclosure after anchored revocation.
            with pytest.raises(UnverifiedBlindError):
                vetSharedList(rip=rip,
                              updates=[issued, revoked],
                              db=verifierHby.db,
                              blinders=[issuedProof],
                              acdc=copies[10],
                              blinding=blindings[10],
                              members=members)

            # Verify membership against the latest revoked state.
            record = vetSharedList(
                rip=rip,
                updates=[issued, revoked],
                db=verifierHby.db,
                blinders=[revokedProof],
                acdc=copies[10],
                blinding=blindings[10],
                members=members,
            )
            assert record.said == revoked.said
            # Confirm rip, issuance, then revocation sequencing.
            # n=0  rip
            # n=1  bup(B, issued)
            # n=2  bup(B, revoked)
            assert record.sn == 2
            # Preserve membership while reporting whole-set revocation.
            assert record.state == "revoked"
            assert record.binding == "bulk"
        finally:
            if reopened is not None and reopened.baser.opened:
                reopened.baser.close(clear=True)
            elif rgy.baser.opened:
                rgy.baser.close(clear=True)
            else:
                cleaner = RegBaser(name=storeName,
                                   headDirPath=str(tmp_path),
                                   temp=False)
                cleaner.close(clear=True)


def test_shared_list_accepts_recovered_kel_branch():
    """A recovered KEL replaces a malicious TEL anchoring branch."""
    # Use an independent verifier database for the issuer's reconciled KEL.
    with openHby(name="bulk-recovery-verifier", base="test",
                 version=Vrsn_2_0) as verifierHby:
        # Derive the current, recovery, and next signing keys deterministically.
        signers = Salter(raw=b"0123456789abcdef").signers(
            count=3, path="bulk-recovery", temp=True)
        # Commit the recovery key in the issuer inception event.
        inception = incept(
            keys=[signers[0].verfer.qb64],
            ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64],
            version=Vrsn_2_0,
        )
        # Create the verifier-side KEL processor.
        kevery = Kevery(db=verifierHby.db, lax=False, local=False)
        # Accept the signed issuer inception.
        kevery.processEvent(
            serder=inception,
            sigers=[signers[0].sign(inception.raw, index=0)],
        )

        # Create one shared registry controlled by the manual issuer AID.
        rip = regcept(israid=inception.pre)
        # Derive one reproducible bulk credential copy.
        deriver = BulkDeriver(b"recover-poc-salt", temp=True)
        copy = acdcmap(
            israid=inception.pre,
            uuid=deriver.u(0),
            regid=rip.said,
            attribute=dict(d="", u=deriver.u(0, 0), role="member"),
        )
        # Commit the copy into its blinded-list aggregate.
        members, aggregate = makeCommitment([deriver.v(0)], [copy.said])

        # Build the original issued state at TEL sequence one.
        issuedProof = Blinder.blind(
            sn=1,
            acdc=aggregate,
            state="issued",
            salt=Salter(raw=b"issue-state-salt").qb64,
        )
        issued = blindate(regid=rip.said,
                          prior=rip.said,
                          blid=issuedProof.said,
                          sn=1)
        # Anchor registry inception and issuance in the first interaction.
        issuedAnchor = interact(
            pre=inception.pre,
            dig=inception.said,
            sn=1,
            data=[dict(i=rip.said, s=rip.sad["n"], d=rip.said),
                  dict(i=rip.said, s=issued.sad["n"], d=issued.said)],
            version=Vrsn_2_0,
        )
        # Accept the signed issuance anchor on the initial KEL branch.
        kevery.processEvent(
            serder=issuedAnchor,
            sigers=[signers[0].sign(issuedAnchor.raw, index=0)],
        )

        # Build a malicious revocation at TEL sequence two.
        maliciousProof = Blinder.blind(
            sn=2,
            acdc=aggregate,
            state="revoked",
            salt=Salter(raw=b"malic-state-salt").qb64,
        )
        malicious = blindate(regid=rip.said,
                             prior=issued.said,
                             blid=maliciousProof.said,
                             sn=2)
        # Anchor the malicious update in a compromised interaction event.
        maliciousAnchor = interact(
            pre=inception.pre,
            dig=issuedAnchor.said,
            sn=2,
            data=[dict(i=rip.said, s=malicious.sad["n"],
                       d=malicious.said)],
            version=Vrsn_2_0,
        )
        # Accept the malicious interaction before recovery is observed.
        kevery.processEvent(
            serder=maliciousAnchor,
            sigers=[signers[0].sign(maliciousAnchor.raw, index=0)],
        )

        # Confirm the malicious state verified before KEL recovery.
        record = vetSharedList(
            rip=rip,
            updates=[issued, malicious],
            db=verifierHby.db,
            blinders=[maliciousProof],
            acdc=copy,
            blinding=deriver.v(0),
            members=members,
        )
        assert record.state == "revoked"

        # Supersede the compromised interaction with a recovery rotation.
        recovery = rotate(
            pre=inception.pre,
            keys=[signers[1].verfer.qb64],
            dig=issuedAnchor.said,
            ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
            sn=2,
            version=Vrsn_2_0,
        )
        # Accept the recovery event signed by the pre-rotated key.
        kevery.processEvent(
            serder=recovery,
            sigers=[signers[1].sign(recovery.raw, index=0)],
        )
        # Confirm the recovery rotation is now authoritative at KEL sequence two.
        assert verifierHby.db.kels.getLast(keys=inception.pre, on=2) == recovery.said

        # Build the issuer's corrected state at the same TEL sequence number.
        correctedProof = Blinder.blind(
            sn=2,
            acdc=aggregate,
            state="issued",
            salt=Salter(raw=b"corre-state-salt").qb64,
        )
        corrected = blindate(regid=rip.said,
                             prior=issued.said,
                             blid=correctedProof.said,
                             sn=2)
        # Anchor the correction on the recovered authoritative KEL branch.
        correctedAnchor = interact(
            pre=inception.pre,
            dig=recovery.said,
            sn=3,
            data=[dict(i=rip.said, s=corrected.sad["n"],
                       d=corrected.said)],
            version=Vrsn_2_0,
        )
        # Accept the correction under the recovered signing key.
        kevery.processEvent(
            serder=correctedAnchor,
            sigers=[signers[1].sign(correctedAnchor.raw, index=0)],
        )

        # The superseded malicious anchor no longer proves registry state.
        with pytest.raises(MissingAnchorError):
            vetSharedList(rip=rip,
                          updates=[issued, malicious],
                          db=verifierHby.db,
                          blinders=[maliciousProof],
                          acdc=copy,
                          blinding=deriver.v(0),
                          members=members)

        # Accept the correction anchored on the recovered authoritative KEL.
        record = vetSharedList(
            rip=rip,
            updates=[issued, corrected],
            db=verifierHby.db,
            blinders=[correctedProof],
            acdc=copy,
            blinding=deriver.v(0),
            members=members,
        )
        # Report the recovered current state instead of false duplicity.
        assert record.said == corrected.said
        assert record.sn == 2
        assert record.state == "issued"
