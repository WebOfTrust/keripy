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
    # bob is the delegator del is bob's delegate

    bobSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    delSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with dbing.openDB(name="bob") as bobDB, \
          keeping.openKeep(name="bob") as bobKp, \
          dbing.openDB(name="del") as delDB, \
          keeping.openKeep(name="del") as delKp:

        # Init key pair managers
        bobMgr = keeping.Manager(keeper=bobKp, salt=bobSalt)
        delMgr = keeping.Manager(keeper=delKp, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(baser=bobDB)
        delKvy = eventing.Kevery(baser=delDB)

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.CryOneDex.Blake3_256)

        bobPre = bobSrdr.ked["pre"]
        assert bobPre == 'EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U'

        bobMgr.move(old=verfers[0].qb64, new=bobPre)  # move key pair label to prefix

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
        assert bobK.serder.diger.qb64 == bobSrdr.dig
        assert bobK.serder.diger.qb64 == 'Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert bobPre in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True) # algo default salty and rooted

        seal = eventing.SealLocation(pre=bobK.prefixer.qb64,
                                     sn="{:x}".format(bobK.sn+1),
                                     ilk=coring.Ilks.ixn,
                                     dig=bobK.serder.diger.qb64)

        assert seal._asdict() == dict(pre='EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U',
                                      sn='1',
                                      ilk='ixn',
                                      dig='Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ')

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   seal=seal,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["pre"]
        assert delPre == 'Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.dig == 'EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw'

        # Now create delegating event
        seal = eventing.SealEvent(pre=delPre,
                                  sn=delSrdr.ked["sn"],
                                  dig=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"vs":"KERI10JSON000117_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2c'
                                b'uYWEQPp0mEu1U","sn":"1","ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dla'
                                b'dxUQyXv4JaPg-gaKuXLfceQ","data":[{"pre":"Ek7M173EvQZ6kLjyorCwZK4'
                                b'XWwyNcSi6u7lz5-M6MyFE","sn":"0","dig":"EeBPcw30IVCylYANEGOg3V8f4'
                                b'nBYMspEpqNaq2Y8_knw"}]}-AABAAD-OA6t17UiGoNivDiCBtkmIuDnjhuuYSLae'
                                b'tbf8_iVktJtD38Ix6LvFI1n6EIqBqyaTdeSqt2s7hT5i8jmlxBg')


        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated
        assert bobK.serder.diger.qb64 == 'EbJxDKQqvYtZ3y8pL_kHNumERg8_OSb28XweHsS1yNHo'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bobPre].serder.diger.qb64 == bobSrdr.dig

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
        delK = bobKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        seal = eventing.SealLocation(pre=bobK.prefixer.qb64,
                                     sn="{:x}".format(bobK.sn+1),
                                     ilk=coring.Ilks.ixn,
                                     dig=bobK.serder.diger.qb64)

        assert seal._asdict() == dict(pre='EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U',
                                      sn='2',
                                      ilk='ixn',
                                      dig='EbJxDKQqvYtZ3y8pL_kHNumERg8_OSb28XweHsS1yNHo')

        delSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.diger.qb64,
                                   seal=seal,
                                   sn=delK.sn+1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.dig == 'E5_Qnd78eKwf7AFCHjraVNpvxu6pnwqgdWi3HdCNyN44'

        # Now create delegating rotation event
        seal = eventing.SealEvent(pre=delK.prefixer.qb64,
                                  sn=delSrdr.ked["sn"],
                                  dig=delSrdr.dig)
        bobSrdr = eventing.interact(pre=bobK.prefixer.qb64,
                                    dig=bobK.serder.diger.qb64,
                                    sn=bobK.sn+1,
                                    data=[seal._asdict()])

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=bobK.verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"vs":"KERI10JSON000117_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2c'
                                b'uYWEQPp0mEu1U","sn":"2","ilk":"ixn","dig":"EbJxDKQqvYtZ3y8pL_kHN'
                                b'umERg8_OSb28XweHsS1yNHo","data":[{"pre":"Ek7M173EvQZ6kLjyorCwZK4'
                                b'XWwyNcSi6u7lz5-M6MyFE","sn":"1","dig":"E5_Qnd78eKwf7AFCHjraVNpvx'
                                b'u6pnwqgdWi3HdCNyN44"}]}-AABAAi0gU5t6NYcK07DwDedgw5cHawG4CCUcXpHO'
                                b'-raWpMlu_GRYEGHSlCQwZIakFE_TWfykCU5d9hf9-a1jjc-18Dw')

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bobPre].serder.diger.qb64 == bobSrdr.dig

        # now create msg from Del's delegated rotation event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"vs":"KERI10JSON0001c2_","pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi'
                                b'6u7lz5-M6MyFE","sn":"1","ilk":"drt","dig":"EeBPcw30IVCylYANEGOg3'
                                b'V8f4nBYMspEpqNaq2Y8_knw","sith":"1","keys":["DTf6QZWoet154o9wvze'
                                b'MuNhLQRr8JaAUeiC6wjB_4_08"],"nxt":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd'
                                b'_yIMH0miptIFFPo","toad":"0","cuts":[],"adds":[],"data":[],"seal"'
                                b':{"pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"2",'
                                b'"ilk":"ixn","dig":"EbJxDKQqvYtZ3y8pL_kHNumERg8_OSb28XweHsS1yNHo"'
                                b'}}-AABAAKnITCZt0mvZ9Ewts2DeT-_C_wpcujGTs7Elbg6NlH_yOwL_ENEHTxaqS'
                                b'lPGjwcGnMv53OipTIDrrPUs3P456BA')

        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'E5_Qnd78eKwf7AFCHjraVNpvxu6pnwqgdWi3HdCNyN44'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

    assert not os.path.exists(delKp.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKp.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()
