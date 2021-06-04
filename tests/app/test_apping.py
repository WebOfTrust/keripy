# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""

import json
import os
from dataclasses import dataclass, asdict

import pytest

from keri.app import apping, habbing, keeping
from keri.core import coring, eventing
from keri.core.coring import Serials
from keri.db import dbing, koming


def test_clean():
    """
    Test Baser db clean clone function
    """
    with dbing.openDB(name="nat") as natDB, keeping.openKS(name="nat") as natKS:
        # setup Nat's habitat using default salt multisig already incepts
        natHab = habbing.Habitat(name='nat', ks=natKS, db=natDB,
                                isith=2, icount=3, temp=True)
        assert natHab.name == 'nat'
        assert natHab.ks == natKS
        assert natHab.db == natDB
        assert natHab.kever.prefixer.transferable
        assert natHab.db.opened
        assert natHab.pre in natHab.kevers
        assert natHab.db.path.endswith("/keri/db/nat")
        path = natHab.db.path  # save for later

        # Create series of events for Nat
        natHab.interact()
        natHab.rotate()
        natHab.interact()
        natHab.interact()
        natHab.interact()
        natHab.interact()

        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.dig == 'En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI'
        ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
        assert ldig == natHab.kever.serder.digb
        serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
        assert serder.dig == natHab.kever.serder.dig
        assert natHab.db.env.stat()['entries'] == 19

        # test reopenDB with reuse  (because temp)
        with dbing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.digb
            serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.dig == natHab.kever.serder.dig
            assert natHab.db.env.stat()['entries'] == 19

            # verify name pre kom in db
            # kdb = koming.Komer(db=natHab.db, schema=habbing.HabitatRecord, subdb='habs.')
            data = natHab.db.habs.get(keys=(natHab.name, ))
            assert data.prefix == natHab.pre
            assert data.name == natHab.name

            # add garbage event to corrupt database
            badsrdr = eventing.rotate(pre=natHab.pre,
                                       keys=[verfer.qb64 for verfer in natHab.kever.verfers],
                                       dig=natHab.kever.serder.dig,
                                       sn=natHab.kever.sn+1,
                                       sith=2,
                                       nxt=natHab.kever.nexter.qb64)
            fn = natHab.kever.logEvent(serder=badsrdr, first=True)
            assert fn == 7
            # verify garbage event in database
            assert natHab.db.getEvt(dbing.dgKey(natHab.pre,badsrdr.dig))
            assert natHab.db.getFe(dbing.fnKey(natHab.pre, 7))


        # test openDB copy db with clean
        with dbing.openDB(name=natHab.db.name,
                          temp=natHab.db.temp,
                          headDirPath=natHab.db.headDirPath,
                          dirMode=natHab.db.dirMode,
                          clean=True) as copy:
            assert copy.path.endswith("/keri/clean/db/nat")
            assert copy.env.stat()['entries'] >= 18

        # now clean it
        natHab.kevers.clear()  # clear kevers dict in place
        assert not natHab.kevers
        kvy = eventing.Kevery(kevers=natHab.kevers)  # use inplace kevers & promiscuous mode
        apping.clean(orig=natHab.db, kvy=kvy)

        # see if kevers dict is back to what it was before
        assert natHab.kever.sn == 6
        assert natHab.kever.fn == 6
        assert natHab.kever.serder.dig == 'En0iLDgaeD9Dydf4Tkd0ilgOW-clbhwMdGW3_t4xHsXI'

        # see if database is back where it belongs
        with dbing.reopenDB(db=natHab.db, reuse=True):
            assert natHab.db.path == path
            ldig = bytes(natHab.db.getKeLast(dbing.snKey(natHab.pre, natHab.kever.sn)))
            assert ldig == natHab.kever.serder.digb
            serder = coring.Serder(raw=bytes(natHab.db.getEvt(dbing.dgKey(natHab.pre,ldig))))
            assert serder.dig == natHab.kever.serder.dig
            assert natHab.db.env.stat()['entries'] >= 18

            # confirm bad event missing from database
            assert not natHab.db.getEvt(dbing.dgKey(natHab.pre,badsrdr.dig))
            assert not natHab.db.getFe(dbing.fnKey(natHab.pre, 7))

            # verify name pre kom in db
            # kdb = koming.Komer(db=natHab.db, schema=habbing.HabitatRecord, subdb='habs.')
            data = natHab.db.habs.get(keys=(natHab.name, ))
            assert data.prefix == natHab.pre
            assert data.name == natHab.name


    assert not os.path.exists(natKS.path)
    assert not os.path.exists(natDB.path)

    """End Test"""


if __name__ == "__main__":
    test_clean()
