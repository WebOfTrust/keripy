# -*- encoding: utf-8 -*-
"""Test support for externally controlled Signify habitats."""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from keri import core
from keri.app import habbing, keeping
from keri.core import coring, eventing


@dataclass(frozen=True)
class SignifyMemberFixture:
    """One externally controlled Signify member and its signing state."""

    hab: habbing.SignifyHab
    signer: core.Signer
    next_diger: core.Diger

    def sign(self, signing_index: int, raw: bytes) -> core.Siger:
        """Sign raw bytes at this member's position in the group key list."""
        return self.signer.sign(ser=raw, index=signing_index)


@dataclass(frozen=True)
class SignifyGroupFixture:
    """A real Signify group backed by externally held member signers."""

    hby: habbing.Habery
    group: habbing.SignifyGroupHab
    members: tuple[SignifyMemberFixture, ...]

    def sign(self, signing_index: int, raw: bytes) -> core.Siger:
        """Sign with the member occupying signing_index in the group."""
        member = self.members[signing_index]
        return member.sign(signing_index=signing_index, raw=raw)


def makeSignifyMember(
    *,
    hby: habbing.Habery,
    creator: keeping.SaltyCreator,
    name: str,
    member_index: int,
) -> SignifyMemberFixture:
    """Create one externally signed Signify member habitat.

    member_index selects a distinct salty key derivation path. The caller later
    places the returned fixture into the group member tuple, whose order defines
    group signing indexes.
    """
    signer = creator.create(pidx=member_index, ridx=0, kidx=0, temp=True).pop()
    next_signer = creator.create(pidx=member_index, ridx=1, kidx=1, temp=True).pop()
    next_diger = coring.Diger(ser=next_signer.verfer.qb64b)
    inception = eventing.incept(
        keys=[signer.verfer.qb64],
        isith="1",
        nsith="1",
        ndigs=[next_diger.qb64],
        code=coring.MtrDex.Blake3_256,
        toad=0,
    )
    hab = hby.makeSignifyHab(
        name=name,
        serder=inception,
        sigers=[signer.sign(ser=inception.raw, index=0)],
    )
    return SignifyMemberFixture(hab=hab, signer=signer, next_diger=next_diger)


def makeSignifyGroupHab(
    *,
    hby: habbing.Habery,
    name: str,
    members: tuple[SignifyMemberFixture, ...],
    mhabIdx: int,
) -> habbing.SignifyGroupHab:
    """Create one 2-of-3 Signify group from prepared members.

    members defines the group key and signing-index order. mhabIdx selects which
    member habitat becomes group.mhab, representing the local member whose
    leadership is evaluated.
    """
    group_keys = [member.signer.verfer.qb64 for member in members]
    next_digests = [member.next_diger.qb64 for member in members]
    member_ids = [member.hab.pre for member in members]
    local_member = members[mhabIdx]

    inception = eventing.incept(
        keys=group_keys,
        isith="2",
        nsith="2",
        ndigs=next_digests,
        code=coring.MtrDex.Blake3_256,
        toad=0,
    )
    sigers = [
        member.sign(signing_index=signing_index, raw=inception.raw)
        for signing_index, member in enumerate(members)
    ]
    return hby.makeSignifyGroupHab(
        name=name,
        mhab=local_member.hab,
        smids=member_ids,
        rmids=member_ids,
        serder=inception,
        sigers=sigers,
    )


@contextmanager
def openSignifyGroup(
    *,
    name: str = "signify-group",
    mhabIdx: int = 0,
    salt: bytes = b"0123456789abcdef",
) -> Iterator[SignifyGroupFixture]:
    """Open a real three-member Signify group for tests.

    Members are created in group signing-index order. mhabIdx selects
    the member represented locally by the returned group's mhab.
    """
    salter = core.Salter(raw=salt)
    creator = keeping.SaltyCreator(salt=salter.qb64, tier=coring.Tiers.low)

    with habbing.openHby(name=name, temp=True) as hby:
        # Tuple position becomes the member's group signing index.
        members = tuple(
            makeSignifyMember(
                hby=hby,
                creator=creator,
                name=f"{name}-member-{member_index}",
                member_index=member_index,
            )
            for member_index in range(3)
        )
        group = makeSignifyGroupHab(
            hby=hby,
            name=f"{name}-group",
            members=members,
            mhabIdx=mhabIdx,
        )
        yield SignifyGroupFixture(hby=hby, group=group, members=members)
