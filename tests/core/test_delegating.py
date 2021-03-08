# -*- encoding: utf-8 -*-
"""
tests delegation primaily from keri.core.eventing

"""
import os

import pytest

from keri import kering
from keri import help
from keri.db import dbing
from keri.base import keeping
from keri.core import coring
from keri.core import eventing

logger = help.ogler.getLogger()


def test_delegation():
    """
    Test creation and validation of delegated identifer prefixes and events

    """
    # bob is the delegator del is bob's delegate

    bobSalt = coring.Salter(raw=b'0123456789abcdef').qb64
    delSalt = coring.Salter(raw=b'abcdef0123456789').qb64

    with dbing.openDB(name="bob") as bobDB, \
          keeping.openKS(name="bob") as bobKS, \
          dbing.openDB(name="del") as delDB, \
          keeping.openKS(name="del") as delKS:

        # Init key pair managers
        bobMgr = keeping.Manager(keeper=bobKS, salt=bobSalt)
        delMgr = keeping.Manager(keeper=delKS, salt=delSalt)

        # Init Keverys
        bobKvy = eventing.Kevery(db=bobDB)
        delKvy = eventing.Kevery(db=delDB)

        # Setup Bob by creating inception event
        verfers, digers = bobMgr.incept(stem='bob', temp=True) # algo default salty and rooted
        bobSrdr = eventing.incept(keys=[verfer.qb64 for verfer in verfers],
                                 nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64,
                                 code=coring.MtrDex.Blake3_256)

        bobPre = bobSrdr.ked["i"]
        assert bobPre == 'EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE'

        bobMgr.move(old=verfers[0].qb64, new=bobPre)  # move key pair label to prefix

        sigers = bobMgr.sign(ser=bobSrdr.raw, verfers=verfers)

        msg = bytearray(bobSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs, count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0000e6_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-U'
                                b'j92Ri7XnFE","s":"0","t":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYU'
                                b'WExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyH'
                                b'SxnMFUsKjZHss","wt":"0","w":[],"c":[]}-AABAAQPFdtnncXLz6dE6A-tXG'
                                b'YYK0BHu3I3Pj-G8DxlbzC3yx5MV8yucZILqAA5toZNODnHVHZtPIMkDknqldL4utBQ')

        # apply msg to bob's Kevery
        bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        bobK = bobKvy.kevers[bobPre]
        assert bobK.prefixer.qb64 == bobPre
        assert bobK.serder.diger.qb64 == bobSrdr.dig
        assert bobK.serder.diger.qb64 == 'EvP2kWxEjTMI3auc6x64EpU-nMQZHiBeKeuavcGdRB24'

        # apply msg to del's Kevery
        delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert bobPre in delKvy.kevers

        # Setup Del's inception event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.incept(stem='del', temp=True) # algo default salty and rooted

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        assert seal._asdict() == dict(i='EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE',
                                      s='1',
                                      t='ixn',
                                      p='EvP2kWxEjTMI3auc6x64EpU-nMQZHiBeKeuavcGdRB24')

        delSrdr = eventing.delcept(keys=[verfer.qb64 for verfer in verfers],
                                   seal=seal,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        delPre = delSrdr.ked["i"]
        assert delPre == 'ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs'

        delMgr.move(old=verfers[0].qb64, new=delPre)  # move key pair label to prefix
        assert delSrdr.dig == 'ESDuaqpoI8-HLD8-eLijUMZpXqYFkNArJFDvt3ABYr9I'

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
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000107_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-U'
                                b'j92Ri7XnFE","s":"1","t":"ixn","p":"EvP2kWxEjTMI3auc6x64EpU-nMQZH'
                                b'iBeKeuavcGdRB24","a":[{"i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcg'
                                b'YtPRhqPs","s":"0","d":"ESDuaqpoI8-HLD8-eLijUMZpXqYFkNArJFDvt3ABY'
                                b'r9I"}]}-AABAAZ4V2cSIXYEPg5BtkJSHVBj-A0dGI6rH2XGaVt1kewqGeJjpy4uz'
                                b'ObPWnoBpaEojFa5AnrUJEgMytORoWMqEhCw')

        # apply msg to bob's Kevery
        bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated
        assert bobK.serder.diger.qb64 == 'EtzXPztLsGC5DGyooSdHdBGIOHjhblBWtZ_AOhGS-hDE'

        # apply msg to del's Kevery
        delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bobPre].serder.diger.qb64 == bobSrdr.dig

        # now create msg with Del's delegated inception event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000165_","i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VG'
                                b'cgYtPRhqPs","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd'
                                b'1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2'
                                b'm4CBEBkUxibiU","wt":"0","w":[],"c":[],"da":{"i":"EiBlVttjqvySMbA'
                                b'4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"1","t":"ixn","p":"EvP2kWxEjT'
                                b'MI3auc6x64EpU-nMQZHiBeKeuavcGdRB24"}}-AABAADv-a3LeXEStuY1LHknepu'
                                b'J7mBcTByugqQ1TNRMrIa0rctfjKsh-hkkkpwDj6M_OLLaFtLqBpmdNTUgBPANLzCQ')

        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delPre in bobKvy.kevers  # successfully validated
        delK = bobKvy.kevers[delPre]
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'ESDuaqpoI8-HLD8-eLijUMZpXqYFkNArJFDvt3ABYr9I'

        # apply msg to del's Kevery
        delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

        # Setup Del rotation event assuming that Bob's next event will be an ixn delegating event
        verfers, digers = delMgr.rotate(pre=delPre, temp=True)

        seal = eventing.SealLocation(i=bobK.prefixer.qb64,
                                     s="{:x}".format(bobK.sn+1),
                                     t=coring.Ilks.ixn,
                                     p=bobK.serder.diger.qb64)

        assert seal._asdict() == {'i': 'EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE',
                                  's': '2',
                                  't': 'ixn',
                                  'p': 'EtzXPztLsGC5DGyooSdHdBGIOHjhblBWtZ_AOhGS-hDE'}


        delSrdr = eventing.deltate(pre=delK.prefixer.qb64,
                                   keys=[verfer.qb64 for verfer in verfers],
                                   dig=delK.serder.diger.qb64,
                                   seal=seal,
                                   sn=delK.sn+1,
                                   nxt=coring.Nexter(digs=[diger.qb64 for diger in digers]).qb64)

        assert delSrdr.dig == 'E-dZsWLp2IIPVDbGdGS-yvuw4HeV_w_w76FHsofmuiq0'

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
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON000107_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-U'
                                b'j92Ri7XnFE","s":"2","t":"ixn","p":"EtzXPztLsGC5DGyooSdHdBGIOHjhb'
                                b'lBWtZ_AOhGS-hDE","a":[{"i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcg'
                                b'YtPRhqPs","s":"1","d":"E-dZsWLp2IIPVDbGdGS-yvuw4HeV_w_w76FHsofmu'
                                b'iq0"}]}-AABAAmloDxOwz6ztvRR_4N8Hn-6ZJk6_0nQhfNE7bzX6NpJRfYDwmUw3'
                                b'rXod0g46iFOLqEWw12oaFVzVH85NYAh67Ag')

        # apply msg to bob's Kevery
        bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert bobK.serder.diger.qb64 == bobSrdr.dig  # key state updated so event was validated

        # apply msg to del's Kevery
        delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[bobPre].serder.diger.qb64 == bobSrdr.dig

        # now create msg from Del's delegated rotation event
        sigers = delMgr.sign(ser=delSrdr.raw, verfers=verfers)

        msg = bytearray(delSrdr.raw)
        counter = coring.Counter(code=coring.CtrDex.ControllerIdxSigs,
                                 count=len(sigers))
        msg.extend(counter.qb64b)
        for siger in sigers:
            msg.extend(siger.qb64b)

        assert msg == bytearray(b'{"v":"KERI10JSON0001a1_","i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VG'
                                b'cgYtPRhqPs","s":"1","t":"drt","p":"ESDuaqpoI8-HLD8-eLijUMZpXqYFk'
                                b'NArJFDvt3ABYr9I","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAU'
                                b'eiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo'
                                b'","wt":"0","wr":[],"wa":[],"a":[],"da":{"i":"EiBlVttjqvySMbA4ShN'
                                b'19rSrz3D0ioNW-Uj92Ri7XnFE","s":"2","t":"ixn","p":"EtzXPztLsGC5DG'
                                b'yooSdHdBGIOHjhblBWtZ_AOhGS-hDE"}}-AABAAXcUl6KlY4VOx8ZumFMc0uR4iH'
                                b'BGmPQo4IAx0nIiiEDB_u2ewkvgIDIp1ELDGxfc2VVUkl38Z7PqwydBdpIK0DA')


        # apply Del's delegated inception event message to bob's Kevery
        bobKvy.process(ims=bytearray(msg))  # process local copy of msg
        assert delK.delegated
        assert delK.serder.diger.qb64 == delSrdr.dig  # key state updated so event was validated
        assert delK.serder.diger.qb64 == 'E-dZsWLp2IIPVDbGdGS-yvuw4HeV_w_w76FHsofmuiq0'

        # apply msg to del's Kevery
        delKvy.process(ims=bytearray(msg))  # process remote copy of msg
        assert delKvy.kevers[delPre].serder.diger.qb64 == delSrdr.dig

    assert not os.path.exists(delKS.path)
    assert not os.path.exists(delDB.path)
    assert not os.path.exists(bobKS.path)
    assert not os.path.exists(bobDB.path)

    """End Test"""


if __name__ == "__main__":
    test_delegation()
