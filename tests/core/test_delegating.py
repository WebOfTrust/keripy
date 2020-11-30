# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import kering
from keri.help import ogling
from keri.db import dbing
from keri.base import keeping
from keri.core import coring
from keri.core import eventing

blogger, flogger = ogling.ogler.getLoggers()


def test_delegation():
    """
    Test creation and validation of delegated identifer prefixes and events

    """
    # bob, del, and pam are remote parties  del is delegated identifier
    # bob is the delegator del is bob's delegate

    bobSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    delSalt = coring.Salter(raw=b'abcdef0123456789').qb64
    pamSalt = coring.Salter(raw=b'56789abcdef01234').qb64


    with dbing.openDB(name="bob") as bobDB, \
          keeping.openKeep(name="bob") as bobKp, \
          dbing.openDB(name="del") as delDB, \
          keeping.openKeep(name="del") as delKp, \
          dbing.openDB(name="pam") as pamDB, \
          keeping.openKeep(name="pam") as pamKp:

        # Init key pair managers
        bobMgr = keeping.Manager(keeper=bobKp, salt=bobSalt)
        delMgr = keeping.Manager(keeper=delKp, salt=delSalt)
        pamMgr = keeping.Manager(keeper=pamKp, salt=pamSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(baser=bobDB)
        delKvy = eventing.Kevery(baser=delDB)
        pamKvy = eventing.Kevery(baser=pamDB)


        #  init sequence numbers for all identifiers
        bsn = besn = 0  # sn and last establishment sn = esn
        dsn = desn = 0  # sn and last establishment sn = esn
        psn = pesn = 0  # sn and last establishment sn = esn

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.CryOneDex.Blake3_256)

        bobPre = bobSrdr.ked["pre"]
        assert bobPre == 'EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U'

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"vs":"KERI10JSON0000fb_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2c'
                                 b'uYWEQPp0mEu1U","sn":"0","ilk":"icp","sith":"1","keys":["DqI2cOZ0'
                                 b'6RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nxt":"E7FuL3Z_KBgt_QAwuZ'
                                 b'i1lUFNC69wvyHSxnMFUsKjZHss","toad":"0","wits":[],"cnfg":[]}-AABA'
                                 b'A_-vC5z6_KnT2iWrA8-twdgh-BfjrWTlq8VN0sj6uQEyoE4zgoCive3x6GGvr1Hj'
                                 b'KHwpFRoXnsDsXanQV3QB0BQ')

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bobPre]
        assert bobK.prefixer.qb64 == bobPre

        bobPriorDig = bobSrdr.dig
        assert bobPriorDig == 'Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ'

        # Setup Del by creating inception event assuming that Bob's next event
        # will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True) # algo default salty and rooted

        seal = eventing.SealLocation(pre=bobPre,
                                     sn="{:x}".format(bsn+1),
                                     ilk=coring.Ilks.ixn,
                                     dig=bobPriorDig)

        assert seal._asdict() == dict(pre='EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U',
                                      sn='1',
                                      ilk='ixn',
                                      dig='Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ')

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   seal=seal,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["pre"]
        assert delPre == 'Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE'
        assert delSrdr.dig == 'EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw'


        # Now create delegating event
        seal = eventing.SealEvent(pre=delPre, dig=delSrdr.dig)
        bsn += 1
        bobSrdr = eventing.interact(pre=bobPre,
                                    dig=bobPriorDig,
                                    sn=bsn,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"vs":"KERI10JSON00010e_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2c'
                                b'uYWEQPp0mEu1U","sn":"1","ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dla'
                                b'dxUQyXv4JaPg-gaKuXLfceQ","data":[{"pre":"Ek7M173EvQZ6kLjyorCwZK4'
                                b'XWwyNcSi6u7lz5-M6MyFE","dig":"EeBPcw30IVCylYANEGOg3V8f4nBYMspEpq'
                                b'Naq2Y8_knw"}]}-AABAA8_fyED6L-y6d8GUg1nKCMtfhyChd_6_bpfAXv1nMC76l'
                                b'zpyaPBTm0O6geoO9kBuaaBCz3ojPUDAtktikVRFlCA')

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.sn == bsn  # key state updated so event was validated
        assert bobK.diger.qb64 == bobSrdr.dig  # likewise

        # now create msg with Del's delegated inception event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg ==bytearray(b'{"vs":"KERI10JSON000183_","pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi'
                               b'6u7lz5-M6MyFE","sn":"0","ilk":"dip","sith":"1","keys":["DuK1x8yd'
                               b'pucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"nxt":"EWWkjZkZDXF74O2bOQ'
                               b'4H5hu4nXDlKg2m4CBEBkUxibiU","toad":"0","wits":[],"cnfg":[],"seal'
                               b'":{"pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"1"'
                               b',"ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ'
                               b'"}}-AABAAMSF33ZiOLYH7Pg74MnMQjbfT_oq9wDeFy4ztfEWP0VagIKPqgYW_zrA'
                               b'kyJrZnQ-7-bfpekNtyRh3sN4doFseAg')


        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated



    assert not os.path.exists(pamKp.path)
    assert not os.path.exists(pamDB.path)
    assert not os.path.exists(delKp.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKp.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()
