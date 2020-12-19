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

        bobPre = bobSrdr.ked["i"]
        assert bobPre == 'EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0cDcS0qC3ZK0'

        bobMgr.move(old=verfers[0].qb64, new=bobPre)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.SigCounter(count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0c'
                                b'DcS0qC3ZK0","s":"0","t":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYU'
                                b'WExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyH'
                                b'SxnMFUsKjZHss","wt":"0","w":[],"c":[]}-AABAAEQJs05lKxSa8wWfV4hYf'
                                b'd8j47ATEtnaps_WKM0wHhDnNrgCin4m6NP9cYQ5UCfKXHhe4mTF6-dfnuQxtBq7CBA')

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bobPre]
        assert bobK.prefixer.qb64 == bobPre
        assert bobK.serder.diger.qb64 == bobSrdr.dig
        assert bobK.serder.diger.qb64 == 'EmEY_w4RrCIIKvJ2gFA3cS7EUvVldX2DKUz-xIwxw5mc'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert bobPre in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True) # algo default salty and rooted

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        assert seal._asdict() == dict(i='EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0cDcS0qC3ZK0',
                                      s='1',
                                      t='ixn',
                                      p='EmEY_w4RrCIIKvJ2gFA3cS7EUvVldX2DKUz-xIwxw5mc')

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   seal=seal,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["i"]
        assert delPre == 'EYWTA7WoB0Cdu4Dq6WnAVodn-xklLI0vltf34S_XK2zg'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.dig == 'ElEt2RtdiyJoImqGO2krlF2Y4rnPnqI-BXy1KGywC2HA'

        # Now create delegating event
        seal = eventing.SealEvent(i=delPre,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
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

        assert msg == bytearray(b'{"v":"KERI10JSON000107_","i":"EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0c'
                                b'DcS0qC3ZK0","s":"1","t":"ixn","p":"EmEY_w4RrCIIKvJ2gFA3cS7EUvVld'
                                b'X2DKUz-xIwxw5mc","a":[{"i":"EYWTA7WoB0Cdu4Dq6WnAVodn-xklLI0vltf3'
                                b'4S_XK2zg","s":"0","d":"ElEt2RtdiyJoImqGO2krlF2Y4rnPnqI-BXy1KGywC'
                                b'2HA"}]}-AABAAS_Fnq8_FIPTBV6Vz-jjdaok7gh32q9gxaRWEGbBnA42z0-YqRAp'
                                b'2iAmJlkYK18HvWVTuzZTYCmR66TUJMsTODw')

        # apply msg to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated
        assert bobK.serder.diger.qb64 == 'E1RjNsNVehiVsvuvQQL0N3Xok0y9OupLV6JIW64GGd6M'

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

        assert msg == bytearray(b'{"v":"KERI10JSON000165_","i":"EYWTA7WoB0Cdu4Dq6WnAVodn-xklLI0vlt'
                                b'f34S_XK2zg","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd'
                                b'1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2'
                                b'm4CBEBkUxibiU","wt":"0","w":[],"c":[],"da":{"i":"EjR6PFb7KSo8dIC'
                                b'njD6dQ5kYJR07R3-T0cDcS0qC3ZK0","s":"1","t":"ixn","p":"EmEY_w4RrC'
                                b'IIKvJ2gFA3cS7EUvVldX2DKUz-xIwxw5mc"}}-AABAA5K8RggXcquGksdVrXWNgo'
                                b'K9LHvkTx-8gxW7G-1gCudS5jWLWAUyAf8piSlDsmKdTQ0HpUC2TuxRl7Qwl6oj_DQ')


        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        delK = bobKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'ElEt2RtdiyJoImqGO2krlF2Y4rnPnqI-BXy1KGywC2HA'

        # apply msg to del's Kevery
        delKvy.processAll(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        assert seal._asdict() == dict(i='EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0cDcS0qC3ZK0',
                                      s='2',
                                      t='ixn',
                                      p='E1RjNsNVehiVsvuvQQL0N3Xok0y9OupLV6JIW64GGd6M')

        delSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.diger.qb64,
                                   seal=seal,
                                   sn=delK.sn+1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.dig == 'EOiyqfqvKcQHy8_7txhp_Iz5g5ynV25L6l6D7sWVVQA0'

        # Now create delegating rotation event
        seal = eventing.SealEvent(i=delK.prefixer.qb64,
                                  s=delSrdr.ked["s"],
                                  d=delSrdr.dig)
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

        assert msg == bytearray(b'{"v":"KERI10JSON000107_","i":"EjR6PFb7KSo8dICnjD6dQ5kYJR07R3-T0c'
                                b'DcS0qC3ZK0","s":"2","t":"ixn","p":"E1RjNsNVehiVsvuvQQL0N3Xok0y9O'
                                b'upLV6JIW64GGd6M","a":[{"i":"EYWTA7WoB0Cdu4Dq6WnAVodn-xklLI0vltf3'
                                b'4S_XK2zg","s":"1","d":"EOiyqfqvKcQHy8_7txhp_Iz5g5ynV25L6l6D7sWVV'
                                b'QA0"}]}-AABAAtsDvEdBhF9WfVJzdhHJ1srBBoYAow6OkX11SEyDnjW2TktWv-gc'
                                b'qLFoWW7PxStVcjRhgee6YtR-K-V6VtzjNCw')

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

        assert msg == bytearray(b'{"v":"KERI10JSON0001a1_","i":"EYWTA7WoB0Cdu4Dq6WnAVodn-xklLI0vlt'
                                b'f34S_XK2zg","s":"1","t":"drt","p":"ElEt2RtdiyJoImqGO2krlF2Y4rnPn'
                                b'qI-BXy1KGywC2HA","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAU'
                                b'eiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo'
                                b'","wt":"0","wr":[],"wa":[],"a":[],"da":{"i":"EjR6PFb7KSo8dICnjD6'
                                b'dQ5kYJR07R3-T0cDcS0qC3ZK0","s":"2","t":"ixn","p":"E1RjNsNVehiVsv'
                                b'uvQQL0N3Xok0y9OupLV6JIW64GGd6M"}}-AABAAPVu6DmWiYtEWOLDzULJR7M5j_'
                                b'YT7V3uWTot5Y4I7XXQHiwDwDhpUP14LOohokbjV-KLJQ_BBHsjVxXLuywEvCw')

        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.processAll(ims=bytearray(msg))  # process local copy of msg
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'EOiyqfqvKcQHy8_7txhp_Iz5g5ynV25L6l6D7sWVVQA0'

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
