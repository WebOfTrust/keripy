# -*- encoding: utf-8 -*-
"""
tests.core.test_reply module

Test endpoint and location reply messages
routes: /end/role and /loc/scheme

"""
import os

import pytest

from hio.help.hicting import Mict

from keri import kering

from keri import help

from keri import core
from keri.core import eventing, parsing, routing
from keri.core.coring import MtrDex

from keri.db import basing
from keri.app import habbing, keeping



logger = help.ogler.getLogger()


def test_reply(mockHelpingNowUTC):
    """
    Test reply message 'rpy' for both endpoint /end/role auth records and
    endpoint /loc/scheme url records.

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/end/role/add",
      "a" :
      {
         "cid":  "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
         "role": "watcher",  # one of kering.Roles
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
      }
    }

    {
      "v" : "KERI10JSON00011c_",
      "t" : "rep",
      "d": "EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM",
      "dt": "2020-08-22T17:50:12.988921+00:00",
      "r" : "/loc/scheme",
      "a" :
      {
         "eid": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
         "scheme": "http",  # one of keirng.Schemes
         "url":  "http://localhost:8080/watcher/wilma",
      }
    }


    """
    # use same salter for all but different path
    # salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    raw = b'\x05\xaa\x8f-S\x9a\xe9\xfaU\x9c\x02\x9c\x9b\x08Hu'
    salt =  core.Salter(raw=raw).qb64
    assert salt == '0AAFqo8tU5rp-lWcApybCEh1'
    # makHab uses stem=name to make different names have differnt AID pre
    with (habbing.openHby(name="wes", base="test", salt=salt) as wesHby,
         habbing.openHby(name="wok", base="test", salt=salt) as wokHby,
         habbing.openHby(name="wam", base="test", salt=salt) as wamHby,
         habbing.openHby(name="tam", base="test", salt=salt) as tamHby,
         habbing.openHby(name="wat", base="test", salt=salt) as watHby,
         habbing.openHby(name="wel", base="test", salt=salt) as welHby,
         habbing.openHby(name="nel", base="test", salt=salt) as nelHby):

        # witnesses first so can setup inception event for tam
        wsith = '1'

        # setup Wes's habitat nontrans
        wesHab = wesHby.makeHab(name='wes', isith=wsith, icount=1, transferable=False)
        assert not wesHab.kever.prefixer.transferable
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        wesPrs = parsing.Parser(kvy=wesKvy)

        # setup Wok's habitat nontrans
        wokHab = wokHby.makeHab(name='wok', isith=wsith, icount=1, transferable=False)
        #assert wokHab.ks == wokKS
        #assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)
        wokPrs = parsing.Parser(kvy=wokKvy)

        # setup Wam's habitat nontrans
        wamHab = wamHby.makeHab(name='wam', isith=wsith, icount=1, transferable=False)
        #assert wamHab.ks == wamKS
        #assert wamHab.db == wamDB
        assert not wamHab.kever.prefixer.transferable
        wamKvy = eventing.Kevery(db=wamHab.db, lax=False, local=False)
        wamPrs = parsing.Parser(kvy=wamKvy)

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        tsith = '2'  # hex str of threshold int
        #tamHab = habbing.Habitat(name='cam', ks=tamKS, db=tamDB,
                                 #isith=tsith, icount=3,
                                 #toad=2, wits=wits,
                                 #salt=salt, temp=True)  # stem is .name
        tamHab = tamHby.makeHab(name='cam', isith=tsith, icount=3, toad=2, wits=wits,)
        #assert tamHab.ks == tamKS
        #assert tamHab.db == tamDB
        assert tamHab.kever.prefixer.transferable
        assert len(tamHab.iserder.berfers) == len(wits)
        for werfer in tamHab.iserder.berfers:
            assert werfer.qb64 in wits
        assert tamHab.kever.wits == wits
        assert tamHab.kever.toader.num == 2
        assert tamHab.kever.sn == 0
        assert tamHab.kever.tholder.thold == 2 == int(tsith, 16)
        # create non-local kevery for Tam to process non-local msgs
        tamKvy = eventing.Kevery(db=tamHab.db, lax=False, local=False)
        # create non-local parer for Tam to process non-local msgs
        rtr = routing.Router()
        rvy = routing.Revery(db=tamHby.db, rtr=rtr)
        kvy = eventing.Kevery(db=tamHby.db, lax=False, local=True, rvy=rvy)
        kvy.registerReplyRoutes(router=rtr)
        tamPrs = parsing.Parser(kvy=tamKvy, rvy=rvy)

        # setup Wat's habitat nontrans
        #watHab = habbing.Habitat(name='wat', ks=watKS, db=watDB,
                                 #isith=wsith, icount=1,
                                 #salt=salt, transferable=False, temp=True)  # stem is .name
        watHab = watHby.makeHab(name='wat', isith=wsith, icount=1, transferable=False)
        #assert watHab.ks == watKS
        #assert watHab.db == watDB
        assert not watHab.kever.prefixer.transferable
        watKvy = eventing.Kevery(db=watHab.db, lax=False, local=False)

        # setup Wel's habitat nontrans
        #welHab = habbing.Habitat(name='wel', ks=welKS, db=welDB,
                                 #isith=wsith, icount=1,
                                 #salt=salt, transferable=False, temp=True)  # stem is .name
        welHab = welHby.makeHab(name='wel', isith=wsith, icount=1, transferable=False)
        #assert welHab.ks == welKS
        #assert welHab.db == welDB
        assert not welHab.kever.prefixer.transferable
        welKvy = eventing.Kevery(db=welHab.db, lax=False, local=False)

        # setup Nel's habitat nontrans
        #nelHab = habbing.Habitat(name='nel', ks=nelKS, db=nelDB,
                                 #isith=wsith, icount=1,
                                 #salt=salt, transferable=False, temp=True)  # stem is .name
        nelHab = nelHby.makeHab(name='nel', isith=wsith, icount=1, transferable=False)
        #assert nelHab.ks == nelKS
        #assert nelHab.db == nelDB
        assert not nelHab.kever.prefixer.transferable
        nelRtr = routing.Router()
        nelRvy = routing.Revery(db=nelHab.db, rtr=nelRtr)
        nelKvy = eventing.Kevery(db=nelHab.db, lax=False, local=False, rvy=nelRvy)
        nelKvy.registerReplyRoutes(router=nelRtr)
        # create non-local parer for Nel to process non-local msgs
        nelPrs = parsing.Parser(kvy=nelKvy, rvy=nelRvy)

        assert nelHab.pre == 'BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y'
        assert nelHab.kever.prefixer.code == MtrDex.Ed25519N
        assert nelHab.kever.verfers[0].qb64 == nelHab.pre

        # add watcher for wat for Nel to auth in Tam's kel fo Nel
        # add endpoint with reply route add
        route = "/end/role/add"

        # watcher role
        role = kering.Roles.watcher

        # with trans cid for nel and eid for wat
        data = dict(cid=nelHab.pre,
                    role=role,
                    eid=watHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.stamp == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpL'
                            b'ZAkcoMkk","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"'
                            b'cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y","role":"watcher","eid":"'
                            b'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"}}')

        assert serderR.said == 'EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpLZAkcoMkk'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EFlkeg-NociMRXHSGBSqARxV'
                    b'5y7zuT5z-ZpLZAkcoMkk","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/end/role/add","a":{"cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuP'
                    b'r_xUwKcj7y","role":"watcher","eid":"BF6YSJGAtVNmq3b7dpBi04Q0Ydqv'
                    b'Tfsk9PFkkZaR8LRr"}}-VAi-CABBLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_x'
                    b'UwKcj7y0BDa3HMDHpdGb9rQ1wsYmQdGMoeFrO2OguTUBXU6kvJjqb2ucmAka59hU'
                    b'9SC-z3YbRGuJchnBIA2N5Q9ja843OkG')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = tamHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # use Nels's parser and kevery to process its own watcher
        nelHab.psr.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # cut endpoint with reply route
        route = "/end/role/cut"

        # stale datetime
        serderR = eventing.reply(route=route, data=data, )
        assert serderR.stamp == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EM_AD-vVfhW-paUryMAZJKasyBuz_GoYIU_k'
                            b'fp7hmqHY","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/cut","a":{"'
                            b'cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y","role":"watcher","eid":"'
                            b'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"}}')

        assert serderR.said == 'EM_AD-vVfhW-paUryMAZJKasyBuz_GoYIU_kfp7hmqHY'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EM_AD-vVfhW-paUryMAZJKas'
                    b'yBuz_GoYIU_kfp7hmqHY","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/end/role/cut","a":{"cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuP'
                    b'r_xUwKcj7y","role":"watcher","eid":"BF6YSJGAtVNmq3b7dpBi04Q0Ydqv'
                    b'Tfsk9PFkkZaR8LRr"}}-VAi-CABBLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_x'
                    b'UwKcj7y0BBegucvx6h-fQGlrdqLmzYKa02eKYmngDvUgc_4DJa5_t5AmnDmTe6n7'
                    b'ky2bbOZn9qWpSUgSNtnivpNB9NeTIcG')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        # Verify no change because stale update
        dater = tamHab.db.sdts.get(keys=saidkeys)  # old saidkeys
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said != serderR.said  # old serderR
        couples = tamHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # use Nels's parser and kevery to process own wat cut
        nelHab.psr.parse(ims=bytearray(msg))

        # Verify no change because stale update
        dater = nelHab.db.sdts.get(keys=saidkeys)  # old saidkeys
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said != serderR.said  # old serderR
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # Redo with Updated not stale datetime
        serderR = eventing.reply(route=route, data=data, stamp=help.helping.DTS_BASE_1)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_1

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"ELGR7LbL2Ik4gd9Odc_BfmetxQKrnZawMwEP'
                            b'NR5vBWrI","dt":"2021-01-01T00:00:01.000000+00:00","r":"/end/role/cut","a":{"'
                            b'cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y","role":"watcher","eid":"'
                            b'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"}}')

        assert serderR.said == 'ELGR7LbL2Ik4gd9Odc_BfmetxQKrnZawMwEPNR5vBWrI'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"ELGR7LbL2Ik4gd9Odc_Bfmet'
                    b'xQKrnZawMwEPNR5vBWrI","dt":"2021-01-01T00:00:01.000000+00:00","r'
                    b'":"/end/role/cut","a":{"cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuP'
                    b'r_xUwKcj7y","role":"watcher","eid":"BF6YSJGAtVNmq3b7dpBi04Q0Ydqv'
                    b'Tfsk9PFkkZaR8LRr"}}-VAi-CABBLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_x'
                    b'UwKcj7y0BAuuOGujYKbo-4bbL3tSA2cXExHtTjqbJqXeoRRchn6CBttw5Poxm7sz'
                    b'kPUiilPHqHPqV4PUZpmN7sxL1quhMsG')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        # verify old reply artifacts at old said removed
        assert not tamHab.db.sdts.get(keys=saidkeys)  # old old saidkeys
        assert not tamHab.db.rpys.get(keys=saidkeys)
        assert tamHab.db.scgs.cnt(keys=saidkeys) == 0
        assert tamHab.db.ssgs.cnt(keys=saidkeys) == 0
        osaidkeys = saidkeys

        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = tamHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == False
        assert ender.name == ""

        # use Nels's parser and kevery to process for Nel's own KEL
        nelHab.psr.parse(ims=bytearray(msg))

        # verify old reply artifacts at old said removed
        assert not nelHab.db.sdts.get(keys=osaidkeys)  # old old saidkeys
        assert not nelHab.db.rpys.get(keys=osaidkeys)
        assert nelHab.db.scgs.cnt(keys=osaidkeys) == 0
        assert nelHab.db.ssgs.cnt(keys=osaidkeys) == 0

        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, watHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == False
        assert ender.name == ""

        # add watcher for wel
        # endpoint with reply route add
        route = "/end/role/add"

        # watcher role
        role = kering.Roles.watcher

        # with trans cid and eid
        data = dict(cid=nelHab.pre,
                    role=role,
                    eid=welHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0  # independent datetimes for each eid
        msg = nelHab.endorse(serder=serderR)

        # tam process for nel watcher wel
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = tamHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, welHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # nel process own watcher wel
        nelHab.psr.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == nelHab.pre

        endkeys = (nelHab.pre, role, welHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # get all watchers in ends
        items = [(keys, ender.allowed) for keys, ender
                 in tamHab.db.ends.getItemIter(keys=(nelHab.pre, role))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                           False)]


        # get all watchers in ends
        items = [(keys, ender.allowed) for keys, ender
                 in nelHab.db.ends.getItemIter(keys=(nelHab.pre, role))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                           False)]

        # restore wat as watcher
        data = dict(cid=nelHab.pre,
                    role=role,
                    eid=watHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data, stamp=help.helping.DTS_BASE_2)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_2
        msg = nelHab.endorse(serder=serderR)
        # Tam process
        tamPrs.parse(ims=bytearray(msg))

        endkeys = (nelHab.pre, role, watHab.pre)
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # Nel process
        nelHab.psr.parse(ims=bytearray(msg))

        endkeys = (nelHab.pre, role, watHab.pre)
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # Provide wat location
        # add endpoint with reply route add
        route = "/loc/scheme"

        # watcher role
        role = kering.Roles.watcher

        scheme = kering.Schemes.http
        url = "http://localhost:8080/watcher/wat"

        # with trans cid for nel and eid for wat
        data = dict(
            eid=watHab.pre,
            scheme=scheme,
            url=url,
        )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"ECvGf7-4WSGJgpm1KvzD5_r5MDD6tcDvJ3JT'
                            b'nmd8CRPp","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                            b'd":"BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr","scheme":"http","url":"htt'
                            b'p://localhost:8080/watcher/wat"}}')


        assert serderR.said == 'ECvGf7-4WSGJgpm1KvzD5_r5MDD6tcDvJ3JTnmd8CRPp'

        # Sign Reply
        msg = watHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"ECvGf7-4WSGJgpm1KvzD5_r5'
                    b'MDD6tcDvJ3JTnmd8CRPp","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFk'
                    b'kZaR8LRr","scheme":"http","url":"http://localhost:8080/watcher/w'
                    b'at"}}-VAi-CABBF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr0BAPHOj'
                    b'hO9Ctpq7BAICbWfAFHCLt6ya5cAafLXtLWJUrUtJUWlT--OVjl659ZA1FBf6uWqJ'
                    b'A-Ex8S0jpC1bAFYYJ')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = tamHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == watHab.pre

        lockeys = (watHab.pre, scheme)
        saider = tamHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = tamHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # use Nel's parser and kevery to process for own location
        nelHab.psr.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == watHab.pre

        lockeys = (watHab.pre, scheme)
        saider = nelHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = nelHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # Tam as trans authZ for witnesses
        # add endpoint with reply route add
        route = "/end/role/add"

        # witness role
        role = kering.Roles.witness

        # with trans cid for tam and eid for wes
        data = dict(cid=tamHab.pre,
                    role=role,
                    eid=wesHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EHC0gHTxQ16xL9vT9n7OBu5sZlO96AX0Jh-d'
                        b'UD42QLDA","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"'
                        b'cid":"ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e","role":"witness","eid":"'
                        b'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom"}}')


        assert serderR.said == 'EHC0gHTxQ16xL9vT9n7OBu5sZlO96AX0Jh-dUD42QLDA'

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EHC0gHTxQ16xL9vT9n7OBu5s'
                    b'ZlO96AX0Jh-dUD42QLDA","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/end/role/add","a":{"cid":"ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CK'
                    b'HG4-mHua6e","role":"witness","eid":"BBVDlgWic_rAf-m_v7vz_VvIYAUP'
                    b'ErvZgLTfXGNrFRom"}}-VBg-FABED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4'
                    b'-mHua6e0AAAAAAAAAAAAAAAAAAAAAAAED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-C'
                    b'KHG4-mHua6e-AADAABAppmVvSGqtmE4Esa87Etz1nEFpyxGSqVaOCOJ-yvNs_EqH'
                    b'NRXwBmIgTHb9J36eKuUh2IyiTPGFsJcfKbIo5QNABBWpvKJtVJvSt575kmW9PVl8'
                    b'UoojGp3AnFnFjmgxwZhvbBTrp9iSFZ5XeeR-vRV3BztCBKSlw3eQWOLhbFUydIFA'
                    b'CD9cNMh0xdMIf_YEpjyg9I0hIC1kO6CktzTLURCBjJNAuzOxp1NRn-8ujWYmXrNN'
                    b'73t4gdsnZwIFn8z57XeKW0G')

        # use Nel's parser and kevery to authZ wes as tam end witness
        nelPrs.parse(ims=bytearray(msg))  # no kel for tam so escrow
        # check escrow
        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role",)  # escrow route base not full route
        [saider] = nelHab.db.rpes.get(keys=escrowkeys)
        assert saider.qb64 == serder.said

        serder0 = serderR

        # use Nel's parser and kevery for tam to provide its url as controller role
        # for itself at its own location
        # add endpoint with reply route add
        route = "/loc/scheme"

        scheme = kering.Schemes.http
        url = "http://localhost:8080/controller/tam"

        # with trans cid for nel and eid for wat
        data = dict(
            eid=tamHab.pre,
            scheme=scheme,
            url=url,
        )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000108_","t":"rpy","d":"ELoGi_w2FKTRR2FU6UjclHJuCgtDOHKXL8Gx'
                            b'dIt5ZGtf","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                            b'd":"ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e","scheme":"http","url":"htt'
                            b'p://localhost:8080/controller/tam"}}')

        assert serderR.said == 'ELoGi_w2FKTRR2FU6UjclHJuCgtDOHKXL8GxdIt5ZGtf'

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000108_","t":"rpy","d":"ELoGi_w2FKTRR2FU6UjclHJu'
                    b'CgtDOHKXL8GxdIt5ZGtf","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG'
                    b'4-mHua6e","scheme":"http","url":"http://localhost:8080/controlle'
                    b'r/tam"}}-VBg-FABED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e0AAA'
                    b'AAAAAAAAAAAAAAAAAAAAED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e'
                    b'-AADAAAE-R2roSYmjUEkk44DwNh26bYZvacAsLaOIzgAC47coa0bOk4KdLYyfy-t'
                    b'AmUMQ7QY0Dp87Ks7tFnW-8SWjMQJABCPas0sa6FAQre8TEbvavW5ip00DnifkeRU'
                    b'9wQOsjomEIsccSeoDYEeIEKPiAO2zRCsxqlPfgsgPFH1jeaWUFQAACD9pt3Ijcc0'
                    b'_7fcemVbCID_n8DOWTHhwWZ6K_xRQ_9bb6RHGzVJNWtxO-gI_A7eBt1yE76uLVCA'
                    b'dXTHHDvmhH4A')

        # use Tam's parser and kevery to process
        nelPrs.parse(ims=bytearray(msg))  # no kel for tam so escrow
        # check escrow
        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/loc/scheme",)  # escrow route base not full route
        [saider] = nelHab.db.rpes.get(keys=escrowkeys)
        assert saider.qb64 == serder.said

        serder1 = serderR

        # add tam kel to nel and process escrows
        tamicp = tamHab.makeOwnInception()
        nelPrs.parse(bytearray(tamicp), local=True)
        assert tamHab.pre not in nelKvy.kevers
        wesPrs.parse(bytearray(tamicp), local=True)
        assert tamHab.pre in wesKvy.kevers
        wokPrs.parse(bytearray(tamicp), local=True)
        assert tamHab.pre in wokKvy.kevers
        wamPrs.parse(bytearray(tamicp), local=True)
        assert tamHab.pre in wamKvy.kevers
        wittamicp = wesHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp), local=True)
        wittamicp = wokHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp), local=True)
        wittamicp = wamHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp), local=True)
        nelKvy.processEscrows()
        assert tamHab.pre in nelHab.kevers

        # process escrow reply
        nelRvy.processEscrowReply()

        # verify /end/role escrow removed
        saidkeys = (serder0.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serder0.said
        quadkeys = (serder0.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role",)  # escrow route base not full route
        assert not nelHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, wesHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # verify /loc/scheme escrow removed
        saidkeys = (serder1.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serder1.said
        quadkeys = (serder1.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/loc/scheme",)  # escrow route base not full route
        assert not nelHab.db.rpes.get(keys=escrowkeys)

        lockeys = (tamHab.pre, scheme)
        saider = nelHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = nelHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # do wok as witness for tam
        # with trans cid for tam and eid for wok
        role = kering.Roles.witness  # witness role
        route = "/end/role/add"  # add authZ
        data = dict(cid=tamHab.pre,
                    role=role,
                    eid=wokHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)

        # use Nel's parser and kevery to authZ wok as tam end witness
        nelPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)

        endkeys = (tamHab.pre, role, wokHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # add test to deauthorize wok

        # use Nel's parser and kevery for wok to provide its url as witness for tam
        # Provide wok location
        # add endpoint with reply route add
        route = "/loc/scheme"
        scheme = kering.Schemes.http
        url = "http://localhost:8080/witness/wok"
        # with trans cid for nel and eid for wat
        data = dict(
            eid=wokHab.pre,
            scheme=scheme,
            url=url,
        )

        serderR = eventing.reply(route=route, data=data, )
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"EN0OizQsqguCvvhE4mkxn4anHCEBvEaRRjNv'
                            b'fsffVzLv","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                            b'd":"BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX","scheme":"http","url":"htt'
                            b'p://localhost:8080/witness/wok"}}')

        assert serderR.said == 'EN0OizQsqguCvvhE4mkxn4anHCEBvEaRRjNvfsffVzLv'

        # Sign Reply
        msg = wokHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"EN0OizQsqguCvvhE4mkxn4an'
                    b'HCEBvEaRRjNvfsffVzLv","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXR'
                    b'PoYIOErX","scheme":"http","url":"http://localhost:8080/witness/w'
                    b'ok"}}-VAi-CABBKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX0BA16jD'
                    b'CM_oWzDGfl8bYOm5ad6Ej-kWejwj7SVkH7QnGrNqeM1_BzUMzgFHgN85DM7Lkoh_'
                    b'IMWtUPnii6hC_oWcL')

        # use Nels's parser and kevery to process
        nelPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        couples = nelHab.db.scgs.get(keys=saidkeys)
        assert len(couples) == 1
        verfer, cigar = couples[0]
        cigar.verfer = verfer
        assert verfer.qb64 == wokHab.pre

        lockeys = (wokHab.pre, scheme)
        saider = nelHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = nelHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # use Nel's parser and kevery for tam to update its url as controller role
        # for itself at its own location
        # add endpoint with reply route add
        route = "/loc/scheme"

        # controller role
        role = kering.Roles.controller

        scheme = kering.Schemes.http
        url = "http://localhost:8088/controller/tam"

        # with trans cid for nel and eid for wat
        data = dict(
            eid=tamHab.pre,
            scheme=scheme,
            url=url,
        )

        serderR = eventing.reply(route=route, data=data, stamp=help.helping.DTS_BASE_1)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_1
        # Sign Reply
        msg = tamHab.endorse(serder=serderR)

        # use Nels's parser and kevery to process
        nelPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)

        lockeys = (tamHab.pre, scheme)
        saider = nelHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = nelHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # use Tam's parser and kevery for tam to update its own url as own
        # controller role for itself at its own location
        # add endpoint with reply route add
        # use Tams's parser and kevery to process
        tamHab.psr.parse(ims=bytearray(msg))

        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = tamHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)

        lockeys = (tamHab.pre, scheme)
        saider = tamHab.db.lans.get(keys=lockeys)
        assert saider.qb64 == serder.said
        locer = tamHab.db.locs.get(keys=lockeys)
        assert locer.url == url
        # assert locer.cids == []

        # Tam as trans authZ its own controller role for Nel
        role = kering.Roles.controller  # controller role
        route = "/end/role/add"  # add endpoint with reply route add
        # with trans cid for tam and eid for wes
        data = dict(cid=tamHab.pre,
                    role=role,
                    eid=tamHab.pre,
                    )

        serderR = eventing.reply(route=route, data=data)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)

        # use Nel's parser and kevery to authZ tam as tam end controller
        nelPrs.parse(ims=bytearray(msg))

        # verify /end/role escrow removed
        saidkeys = (serderR.said,)
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role",)  # escrow route base not full route
        assert not nelHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, tamHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # use Tam's parser and kevery to authZ tam as tam end controller in tam's kel
        tamHab.psr.parse(ims=bytearray(msg))

        # verify /end/role escrow removed
        saidkeys = (serderR.said,)
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.said == serderR.said
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = tamHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role",)  # escrow route base not full route
        assert not tamHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, tamHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # get all roles in ends
        items = [(keys, ender.allowed) for keys, ender
                 in nelHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'controller',
                            'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX'),
                           True)]


        items = [(keys, ender.allowed) for keys, ender
                 in nelHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                           True)]

        items = [(keys, ender.allowed) for keys, ender
                 in tamHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                        'controller',
                        'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e'),
                         True)]

        items = [(keys, ender.allowed) for keys, ender
                 in tamHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                           True)]

        # get all schemes in locs
        # nel locs
        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e', 'http'),
                          'http://localhost:8088/controller/tam')]


        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert not items

        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == []

        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert items == [(('BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX', 'http'),
                          'http://localhost:8080/witness/wok')]

        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr', 'http'),
                          'http://localhost:8080/watcher/wat')]

        items = [(keys, locer.url) for keys, locer
                 in nelHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert not items

        # tam locs
        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e', 'http'),
                          'http://localhost:8088/controller/tam')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert not items

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == []

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert not items

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wamHab.pre, ""))]
        assert not items

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr', 'http'),
                          'http://localhost:8080/watcher/wat')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert not items

        # test Habitat methods to fetch urls ends and locs
        rurls = nelHab.fetchRoleUrls(cid=tamHab.pre)
        assert len(rurls.getall("controller")) == 1
        assert rurls["controller"][tamHab.pre]['http'] == 'http://localhost:8088/controller/tam'
        assert len(rurls.getall("witness")) == 1
        assert rurls.getall("witness")[0][wokHab.pre]["http"] == 'http://localhost:8080/witness/wok'

        rurls = nelHab.fetchRoleUrls(cid=nelHab.pre)
        assert rurls == {'watcher': {'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr':
                                        {'http': 'http://localhost:8080/watcher/wat'}}}

        rurls = tamHab.fetchRoleUrls(cid=tamHab.pre)
        assert rurls == {'controller': {'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e':
                                           {'http': 'http://localhost:8088/controller/tam'}}}

        rurls = tamHab.fetchRoleUrls(cid=nelHab.pre)
        assert len(rurls.getall("watcher")) == 1

        assert tamHab.fetchLoc(eid=watHab.pre) == basing.LocationRecord(
            url='http://localhost:8080/watcher/wat')

        assert tamHab.fetchUrl(eid=watHab.pre) == 'http://localhost:8080/watcher/wat'

        end = tamHab.fetchEnd(cid=tamHab.pre,
                              role='controller',
                              eid=tamHab.pre)
        assert end == basing.EndpointRecord(allowed=True, name='')

        assert tamHab.fetchEndAllowed(cid=tamHab.pre, role='controller', eid=tamHab.pre)

        # test fetchWitnessUrls
        rurls = nelHab.fetchWitnessUrls(cid=tamHab.pre)
        assert len(rurls) == 2
        assert rurls["witness"][wokHab.pre]['http'] == 'http://localhost:8080/witness/wok'

        msgs = bytearray()
        msgs.extend(tamHab.makeEndRole(eid=wesHab.pre, role=kering.Roles.witness))
        msgs.extend(tamHab.makeEndRole(eid=wokHab.pre, role=kering.Roles.witness))
        msgs.extend(tamHab.makeEndRole(eid=wamHab.pre, role=kering.Roles.witness))
        msgs.extend(wesHab.makeLocScheme(url='http://localhost:8080/witness/wes'))
        msgs.extend(wokHab.makeLocScheme(url='http://localhost:8080/witness/wok'))
        msgs.extend(wamHab.makeLocScheme(url='http://localhost:8080/witness/wam'))

        tamHab.psr.parse(bytearray(msgs))
        wesHab.psr.parse(bytearray(msgs))
        wokHab.psr.parse(bytearray(msgs))
        wamHab.psr.parse(bytearray(msgs))

        nelHab.psr.parse(bytearray(msgs))
        watHab.psr.parse(bytearray(msgs))
        welHab.psr.parse(bytearray(msgs))

        msgs = bytearray()
        msgs.extend(nelHab.makeEndRole(eid=nelHab.pre, role=kering.Roles.controller))
        msgs.extend(nelHab.makeEndRole(eid=watHab.pre, role=kering.Roles.watcher))
        msgs.extend(nelHab.makeEndRole(eid=welHab.pre, role=kering.Roles.watcher))
        msgs.extend(nelHab.makeLocScheme(url='http://localhost:8080/controller/nel'))
        msgs.extend(watHab.makeLocScheme(url='http://localhost:8080/watcher/wat'))
        msgs.extend(welHab.makeLocScheme(url='http://localhost:8080/watcher/wel'))

        tamHab.psr.parse(bytearray(msgs))
        wesHab.psr.parse(bytearray(msgs))
        wokHab.psr.parse(bytearray(msgs))
        wamHab.psr.parse(bytearray(msgs))

        nelHab.psr.parse(bytearray(msgs))
        watHab.psr.parse(bytearray(msgs))
        welHab.psr.parse(bytearray(msgs))

        # get all roles in ends
        items = [(keys, ender.allowed) for keys, ender
                 in nelHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'controller',
                            'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BByq5Nfi0KgohEaJ8h9JrLqbhX_waySFSXKsgumxEYQp'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX'),
                           True)]

        items = [(keys, ender.allowed) for keys, ender
                 in nelHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                        'controller',
                        'BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y'),
                       True),
                      (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                        'watcher',
                        'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                       True),
                      (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                        'watcher',
                        'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                       True)]

        items = [(keys, ender.allowed) for keys, ender
                 in tamHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'controller',
                            'ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BByq5Nfi0KgohEaJ8h9JrLqbhX_waySFSXKsgumxEYQp'),
                           True),
                          (('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e',
                            'witness',
                            'BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX'),
                           True)]

        items = [(keys, ender.allowed) for keys, ender
                 in tamHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'controller',
                            'BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC'),
                           True),
                          (('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y',
                            'watcher',
                            'BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr'),
                           True)]

        # tam locs
        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('ED7ek7qhzr9SzqmV8IBxgHHWfsNcbWd-CKHG4-mHua6e', 'http'),
                          'http://localhost:8088/controller/tam')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y', 'http'),
                          'http://localhost:8080/controller/nel')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == [(('BBVDlgWic_rAf-m_v7vz_VvIYAUPErvZgLTfXGNrFRom', 'http'),
                          'http://localhost:8080/witness/wes')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert items == [(('BKVb58uITf48YoMPz8SBOTVwLgTO9BY4oEXRPoYIOErX', 'http'),
                          'http://localhost:8080/witness/wok')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(wamHab.pre, ""))]
        assert items == [(('BByq5Nfi0KgohEaJ8h9JrLqbhX_waySFSXKsgumxEYQp', 'http'),
                         'http://localhost:8080/witness/wam')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr', 'http'),
                          'http://localhost:8080/watcher/wat')]

        items = [(keys, locer.url) for keys, locer
                 in tamHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert items == [(('BD0enuaak8Gk_sDSWrHy7H-RwqM7KNfiCj6k5JKz1oEC', 'http'),
                          'http://localhost:8080/watcher/wel')]


    assert not os.path.exists(nelHby.ks.path)
    assert not os.path.exists(nelHby.db.path)
    assert not os.path.exists(watHby.ks.path)
    assert not os.path.exists(watHby.db.path)
    assert not os.path.exists(welHby.ks.path)
    assert not os.path.exists(welHby.db.path)
    assert not os.path.exists(wamHby.ks.path)
    assert not os.path.exists(wamHby.db.path)
    assert not os.path.exists(wokHby.ks.path)
    assert not os.path.exists(wokHby.db.path)
    assert not os.path.exists(wesHby.ks.path)
    assert not os.path.exists(wesHby.db.path)
    assert not os.path.exists(tamHby.ks.path)
    assert not os.path.exists(tamHby.db.path)
    """Done Test"""


if __name__ == "__main__":
    pytest.main(['-vv', 'test_reply.py::test_reply'])
