# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import os
import shutil

from keri.app import habbing, keeping
from keri.db import basing


def test_habitat():
    """
    Test Habitat class
    """
    hab = habbing.Habitat(temp=True)
    assert hab.name == "test"

    hab.db.close(clear=True)
    hab.ks.close(clear=True)

    """End Test"""


def test_habitat_rotate_with_witness():
    if os.path.exists('/usr/local/var/keri/db/phil-test'):
        shutil.rmtree('/usr/local/var/keri/db/phil-test')
    if os.path.exists('/usr/local/var/keri/ks/phil-test'):
        shutil.rmtree('/usr/local/var/keri/ks/phil-test')

    name = "phil-test"
    with basing.openDB(name=name, temp=False) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False,
                              wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])
        oidig = hab.iserder.dig
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.dig

    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False,
                              wits=["B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M"])

        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.dig == oidig

        hab.rotate(count=3)

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.dig


def test_habitat_reinitialization():
    """
    Test Reinitializing Habitat class
    """
    if os.path.exists('/usr/local/var/keri/db/bob-test'):
        shutil.rmtree('/usr/local/var/keri/db/bob-test')
    if os.path.exists('/usr/local/var/keri/ks/bob-test'):
        shutil.rmtree('/usr/local/var/keri/ks/bob-test')

    name = "bob-test"

    with basing.openDB(name=name, clear=True, temp=False) as db, \
            keeping.openKS(name=name, clear=True, temp=False) as ks:

        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        oidig = hab.iserder.dig
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.dig
        assert hab.ridx == 0

    with basing.openDB(name=name, temp=False) as db, \
            keeping.openKS(name=name, temp=False) as ks:

        assert opre not in db.prefixes
        assert opre in db.kevers  # write through cache

        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.dig == oidig

        hab.rotate()

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.dig

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.dig

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.ridx == 1

        assert hab.kever.serder.dig != odig
        assert hab.kever.serder.dig == ndig

        hab.ks.close(clear=True)
        hab.db.close(clear=True)

    assert not os.path.exists(hab.ks.path)
    assert not os.path.exists(hab.db.path)
    """End Test"""


def test_habitat_reinitialization_reload():
    if os.path.exists('/usr/local/var/keri/db/bob-test'):
        shutil.rmtree('/usr/local/var/keri/db/bob-test')
    if os.path.exists('/usr/local/var/keri/ks/bob-test'):
        shutil.rmtree('/usr/local/var/keri/ks/bob-test')

    name = "bob-test"

    with basing.openDB(name=name, clear=True, temp=False) as db, \
            keeping.openKS(name=name, clear=True, temp=False) as ks:
        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        oidig = hab.iserder.dig
        opre = hab.pre
        opub = hab.kever.verfers[0].qb64
        odig = hab.kever.serder.dig
        assert hab.ridx == 0

    # openDB with reload=True which should reload .habs into db.kevers and db.prefixes
    with basing.openDB(name=name, temp=False, reload=True) as db, \
            keeping.openKS(name=name, temp=False) as ks:
        assert opre in db.prefixes
        assert opre in db.kevers

        hab = habbing.Habitat(name=name, ks=ks, db=db, icount=1, temp=False)
        assert hab.pre == opre
        assert hab.prefixes is db.prefixes
        assert hab.kevers is db.kevers
        assert hab.pre in hab.prefixes
        assert hab.pre in hab.kevers
        assert hab.iserder.dig == oidig

        hab.rotate()

        assert hab.ridx == 1
        assert opub != hab.kever.verfers[0].qb64
        assert odig != hab.kever.serder.dig

        npub = hab.kever.verfers[0].qb64
        ndig = hab.kever.serder.dig

        assert opre == hab.pre
        assert hab.kever.verfers[0].qb64 == npub
        assert hab.ridx == 1

        assert hab.kever.serder.dig != odig
        assert hab.kever.serder.dig == ndig

        hab.ks.close(clear=True)
        hab.db.close(clear=True)

    assert not os.path.exists(hab.ks.path)
    assert not os.path.exists(hab.db.path)
    """End Test"""


def test_habitat_with_delegation():
    """
    Test Habitat class
    """
    delhab = habbing.Habitat(name="del", temp=True)
    delpre = delhab.pre
    assert delpre == "E5R24em6RjYzygDkAqM2Sr3cYkFJIObwxc7bvJ68w0rU"

    bobhab = habbing.Habitat(name="bob", temp=True, delpre=delpre)
    assert bobhab.pre == "EP5Mtq4GUNpSerefl7gyFzEth1IHslD8yPUd5TqxCIDk"

    assert bobhab.delserder.pre == "EP5Mtq4GUNpSerefl7gyFzEth1IHslD8yPUd5TqxCIDk"
    assert bobhab.delserder.ked["s"] == '0'
    assert bobhab.delserder.dig == "EInoiW2u40h0bgm3gu2C4xFXW-QVrDeJ3VG97QjbCKFQ"

    assert bobhab.accepted is False

    bobhab.db.close(clear=True)
    bobhab.ks.close(clear=True)
    delhab.db.close(clear=True)
    delhab.ks.close(clear=True)

    """End Test"""


if __name__ == "__main__":
    test_habitat_rotate_with_witness()
