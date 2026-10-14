"""Group records retain membership and local ownership across database reopen."""
from contextlib import contextmanager

import pytest

from keri import core
from keri.app import configing, habbing, keeping
from keri.core import coring, eventing
from tests.app.signifying import makeSignifyMember


@contextmanager
def openPersistentHabery(path):
    """Keep files under pytest's temporary path while closing every live handle."""
    # temp=False retains the files for the next open; all three stores are isolated.
    with configing.openCF(name="groups", headDirPath=str(path), temp=False) as cf:
        with habbing.openHby(name="groups", headDirPath=str(path), temp=False, cf=cf) as hby:
            yield hby


def signifyMembers(hby):
    """Create two real Signify habitats using externally held test signers."""
    creator = keeping.SaltyCreator(salt=core.Salter(raw=b"0123456789abcdef").qb64)
    return tuple(makeSignifyMember(hby=hby, creator=creator, name=f"member-{index}",
                                  member_index=index) for index in range(2))


@pytest.mark.parametrize("rotation", ["default", "extra_rotator", "empty"])
def test_group_membership_survives_reopen(tmp_path, rotation):
    """Ordinary groups retain distinct rotation membership, including no next keys."""
    with openPersistentHabery(tmp_path) as hby:
        member = hby.makeHab(name="member")
        other = hby.makeHab(name="other")
        smids = [member.pre]
        choices = {"default": None, "extra_rotator": [other.pre, member.pre], "empty": []}
        rmids = choices[rotation]
        expected = smids if rmids is None else rmids
        group = hby.makeGroupHab(group="group", mhab=member, smids=smids, rmids=rmids,
                                isith="1", nsith="1" if expected else "0")
        pre = group.pre
        assert group.accepted and group.rmids == expected
        assert hby.db.habs.get(keys=(pre,)).rmids == expected
        nextKeys = [diger.qb64 for diger in group.kever.ndigers]

    # A new Habery reloads records and KEL state from closed databases, not cached Habs.
    with openPersistentHabery(tmp_path) as reopened:
        loaded = reopened.habByName("group")
        assert isinstance(loaded, habbing.GroupHab) and loaded.pre == pre
        assert loaded.mhab is reopened.habs[member.pre]
        assert loaded.smids == smids and loaded.rmids == expected
        assert [diger.qb64 for diger in loaded.kever.ndigers] == nextKeys


@pytest.mark.parametrize("rotation", ["default", "extra_rotator", "empty"])
def test_signify_group_membership_survives_reopen(tmp_path, rotation):
    """Externally signed groups preserve the same membership contract on restart."""
    with openPersistentHabery(tmp_path) as hby:
        member, other = signifyMembers(hby)
        smids = [member.hab.pre]
        choices = {"default": None, "extra_rotator": [other.hab.pre, member.hab.pre], "empty": []}
        rmids = choices[rotation]
        expected = smids if rmids is None else rmids
        nextDigests = {item.hab.pre: item.next_diger.qb64 for item in (member, other)}
        inception = eventing.incept(keys=[member.signer.verfer.qb64], isith="1",
                                   ndigs=[nextDigests[mid] for mid in expected],
                                   nsith="1" if expected else "0", code=coring.MtrDex.Blake3_256)
        group = hby.makeSignifyGroupHab(name="group", mhab=member.hab, smids=smids, rmids=rmids,
                                       serder=inception, sigers=[member.sign(0, inception.raw)])
        pre = group.pre
        assert group.accepted and group.rmids == expected
        assert hby.db.habs.get(keys=(pre,)).rmids == expected

    with openPersistentHabery(tmp_path) as reopened:
        loaded = reopened.habByName("group")
        assert isinstance(loaded, habbing.SignifyGroupHab) and loaded.pre == pre
        assert loaded.mhab is reopened.habs[member.hab.pre]
        assert loaded.smids == smids and loaded.rmids == expected
        assert [diger.qb64 for diger in loaded.kever.ndigers] == [nextDigests[mid] for mid in expected]


def test_signify_group_join_record_survives_reopen(tmp_path):
    """The join API persists group identity and local-member linkage across reopen."""
    with openPersistentHabery(tmp_path) as hby:
        member, other = signifyMembers(hby)
        smids = [member.hab.pre]
        rmids = [other.hab.pre, member.hab.pre]
        inception = eventing.incept(keys=[member.signer.verfer.qb64], isith="1", nsith="1",
                                   ndigs=[other.next_diger.qb64, member.next_diger.qb64],
                                   code=coring.MtrDex.Blake3_256)
        # Receive the externally signed group event before joining it locally.
        hby.kvy.processEvent(serder=inception, sigers=[member.sign(0, inception.raw)])
        group = hby.joinSignifyGroupHab(pre=inception.pre, name="joined", mhab=member.hab,
                                       smids=smids, rmids=rmids)
        record = hby.db.habs.get(keys=(group.pre,))
        assert record.hid == record.sid == group.pre
        assert record.mid == member.hab.pre

    with openPersistentHabery(tmp_path) as reopened:
        loaded = reopened.habByName("joined")
        assert isinstance(loaded, habbing.SignifyGroupHab) and loaded.pre == inception.pre
        assert loaded.accepted and loaded.mhab is reopened.habs[member.hab.pre]
        assert loaded.smids == smids and loaded.rmids == rmids
        assert reopened.habByName("member-0") is loaded.mhab
