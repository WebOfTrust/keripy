"""Kever.locallyContributedIndices for a member that is absent from, or has moved within, a
group event's signing list."""

from keri.app import habbing
from keri.core.signing import Signer


def _group(hby):
    hab1 = hby.makeHab(name="member1")
    hab2 = hby.makeHab(name="member2")
    # A threshold of one, so the local member's own signature puts the group in key state.
    ghab = hby.makeGroupHab(group="group", mhab=hab1, smids=[hab1.pre, hab2.pre],
                            rmids=[hab1.pre, hab2.pre], isith="1", nsith="1", toad=0, wits=[])
    return hab1, ghab


def test_a_member_absent_from_the_list_contributed_nothing():
    """A member the others removed is absent from the removing rotation's signing list. Before
    the fix this raised ValueError, so the removed member could never process its removal."""
    with habbing.openHby(name="contrib-absent", temp=True) as hby:
        _, ghab = _group(hby)
        stranger = Signer(transferable=True).verfer
        assert hby.kevers[ghab.pre].locallyContributedIndices([stranger]) == []


def test_a_member_that_rotated_its_own_aid_is_still_found_by_its_older_key():
    """The key a member contributed to the group's event stops being its current key once it
    rotates its own AID. Indexing the current key alone raised ValueError here too, and where it
    did not, it would have missed the contributed key."""
    with habbing.openHby(name="contrib-rotated", temp=True) as hby:
        hab1, ghab = _group(hby)
        kever = hby.kevers[ghab.pre]
        contributed = list(kever.verfers)
        old = hab1.kever.verfers[0].qb64
        hab1.rotate()
        assert hab1.kever.verfers[0].qb64 != old
        index = [verfer.qb64 for verfer in contributed].index(old)
        assert kever.locallyContributedIndices(contributed) == [index]
