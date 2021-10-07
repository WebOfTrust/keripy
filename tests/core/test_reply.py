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

from keri.core import eventing, parsing
from keri.core.coring import MtrDex, Salter

from keri.db import basing
from keri.app import habbing, keeping

from keri import help

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
    salter = Salter(raw=raw)
    salt = salter.qb64
    assert salt == '0ABaqPLVOa6fpVnAKcmwhIdQ'

    with basing.openDB(name="wes") as wesDB, keeping.openKS(name="wes") as wesKS, \
         basing.openDB(name="wok") as wokDB, keeping.openKS(name="wok") as wokKS, \
         basing.openDB(name="wam") as wamDB, keeping.openKS(name="wam") as wamKS, \
         basing.openDB(name="tam") as tamDB, keeping.openKS(name="tam") as tamKS, \
         basing.openDB(name="wat") as watDB, keeping.openKS(name="wat") as watKS, \
         basing.openDB(name="wel") as welDB, keeping.openKS(name="wel") as welKS, \
         basing.openDB(name="nel") as nelDB, keeping.openKS(name="nel") as nelKS:

        # witnesses first so can setup inception event for tam
        wsith = 1

        # setup Wes's habitat nontrans
        wesHab = habbing.Habitat(name='wes', ks=wesKS, db=wesDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wesHab.ks == wesKS
        assert wesHab.db == wesDB
        assert not wesHab.kever.prefixer.transferable
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        wesPrs = parsing.Parser(kvy=wesKvy)

        # setup Wok's habitat nontrans
        wokHab = habbing.Habitat(name='wok',ks=wokKS, db=wokDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wokHab.ks == wokKS
        assert wokHab.db == wokDB
        assert not wokHab.kever.prefixer.transferable
        wokKvy = eventing.Kevery(db=wokHab.db, lax=False, local=False)
        wokPrs = parsing.Parser(kvy=wokKvy)

        # setup Wam's habitat nontrans
        wamHab = habbing.Habitat(name='wam', ks=wamKS, db=wamDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert wamHab.ks == wamKS
        assert wamHab.db == wamDB
        assert not wamHab.kever.prefixer.transferable
        wamKvy = eventing.Kevery(db=wamHab.db, lax=False, local=False)
        wamPrs = parsing.Parser(kvy=wamKvy)

        # setup Tam's habitat trans multisig
        wits = [wesHab.pre, wokHab.pre, wamHab.pre]
        tsith = 2  # hex str of threshold int
        tamHab = habbing.Habitat(name='cam', ks=tamKS, db=tamDB,
                                   isith=tsith, icount=3,
                                   toad=2, wits=wits,
                                   salt=salt, temp=True)  # stem is .name
        assert tamHab.ks == tamKS
        assert tamHab.db == tamDB
        assert tamHab.kever.prefixer.transferable
        assert len(tamHab.iserder.werfers) == len(wits)
        for werfer in tamHab.iserder.werfers:
            assert werfer.qb64 in wits
        assert tamHab.kever.wits == wits
        assert tamHab.kever.toad == 2
        assert tamHab.kever.sn == 0
        assert tamHab.kever.tholder.thold == tsith == 2
        # create non-local kevery for Tam to process non-local msgs
        tamKvy = eventing.Kevery(db=tamHab.db, lax=False, local=False)
        # create non-local parer for Tam to process non-local msgs
        tamPrs = parsing.Parser(kvy=tamKvy)

        # setup Wat's habitat nontrans
        watHab = habbing.Habitat(name='wat', ks=watKS, db=watDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert watHab.ks == watKS
        assert watHab.db == watDB
        assert not watHab.kever.prefixer.transferable
        watKvy = eventing.Kevery(db=watHab.db, lax=False, local=False)

        # setup Wel's habitat nontrans
        welHab = habbing.Habitat(name='wel', ks=welKS, db=welDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert welHab.ks == welKS
        assert welHab.db == welDB
        assert not welHab.kever.prefixer.transferable
        welKvy = eventing.Kevery(db=welHab.db, lax=False, local=False)

        # setup Nel's habitat nontrans
        nelHab = habbing.Habitat(name='nel', ks=nelKS, db=nelDB,
                                   isith=wsith, icount=1,
                                   salt=salt, transferable=False, temp=True)  # stem is .name
        assert nelHab.ks == nelKS
        assert nelHab.db == nelDB
        assert not nelHab.kever.prefixer.transferable
        nelKvy = eventing.Kevery(db=nelHab.db, lax=False, local=False)
        # create non-local parer for Nel to process non-local msgs
        nelPrs = parsing.Parser(kvy=nelKvy)

        assert nelHab.pre == 'Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI'
        assert nelHab.kever.prefixer.code == MtrDex.Ed25519N
        assert nelHab.kever.verfers[0].qb64 == nelHab.pre

        # add watcher for wat for Nel to auth in Tam's kel fo Nel
        # add endpoint with reply route add
        route = "/end/role/add"

        # watcher role
        role = kering.Roles.watcher

        # with trans cid for nel and eid for wat
        data = dict( cid=nelHab.pre,
                     role=role,
                     eid=watHab.pre,
                   )

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"El8evbsys_Z2gIEluLw6pr31EYpH6Cu52fjn'
                            b'RN8X8mKc","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"'
                            b'cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI","role":"watcher","eid":"'
                            b'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs"}}')

        assert serderR.said == 'El8evbsys_Z2gIEluLw6pr31EYpH6Cu52fjnRN8X8mKc'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"El8evbsys_Z2gIEluLw6pr31'
                       b'EYpH6Cu52fjnRN8X8mKc","dt":"2021-01-01T00:00:00.000000+00:00","r'
                       b'":"/end/role/add","a":{"cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-'
                       b'v_FTApyPvI","role":"watcher","eid":"BXphIkYC1U2ardvt2kGLThDRh2q9'
                       b'N-yT08WSRlpHwtGs"}}-VAi-CABBsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_F'
                       b'TApyPvI0BaLjdO2H6j7Z8g3UpGGRwKQJ0Lz_sngwxLLPM72bGajVeIVXiqRAB0Eo'
                       b'yweFc3wzUfgECAksyvsB9wyqdeXGJAA')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EKrW_70GQTYiBMjZYQGDE68eDMLaOOuBlY78'
                               b'pW1HRPbg","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/cut","a":{"'
                               b'cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI","role":"watcher","eid":"'
                               b'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs"}}')

        assert serderR.said == 'EKrW_70GQTYiBMjZYQGDE68eDMLaOOuBlY78pW1HRPbg'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EKrW_70GQTYiBMjZYQGDE68e'
                    b'DMLaOOuBlY78pW1HRPbg","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/end/role/cut","a":{"cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-'
                    b'v_FTApyPvI","role":"watcher","eid":"BXphIkYC1U2ardvt2kGLThDRh2q9'
                    b'N-yT08WSRlpHwtGs"}}-VAi-CABBsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_F'
                    b'TApyPvI0Bgq_j5W7FeoD3JeSEUjgNlF3iwKMNeX2244CPp0hmWYl8roNvC0vSeyt'
                    b'84rm5l_OwA63X5sR_y_S_zgfEtJF_Cw')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        # Verify no change because stale update
        dater = tamHab.db.sdts.get(keys=saidkeys)  # old saidkeys
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig != serderR.dig  # old serderR
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
        assert serder.dig != serderR.dig  # old serderR
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

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EwZH6wJVwwqb2tmhYKYa-GyiO75k4MqkuMKy'
                               b'G2XWpP7Y","dt":"2021-01-01T00:00:01.000000+00:00","r":"/end/role/cut","a":{"'
                               b'cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI","role":"watcher","eid":"'
                               b'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs"}}')

        assert serderR.said == 'EwZH6wJVwwqb2tmhYKYa-GyiO75k4MqkuMKyG2XWpP7Y'

        # Sign Reply
        msg = nelHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"EwZH6wJVwwqb2tmhYKYa-Gyi'
                    b'O75k4MqkuMKyG2XWpP7Y","dt":"2021-01-01T00:00:01.000000+00:00","r'
                    b'":"/end/role/cut","a":{"cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-'
                    b'v_FTApyPvI","role":"watcher","eid":"BXphIkYC1U2ardvt2kGLThDRh2q9'
                    b'N-yT08WSRlpHwtGs"}}-VAi-CABBsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_F'
                    b'TApyPvI0BUrzk2jcq5YtdMuW4s4U6FuGrfHNZZAn4pzfzzsEcfIsgfMbhJ1ozpWl'
                    b'YPYdR3wbryWUkxfWqtbNwDWlBdTblAQ')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        # verify old reply artifacts at old said removed
        assert not tamHab.db.sdts.get(keys=saidkeys)  # old old saidkeys
        assert not tamHab.db.rpys.get(keys=saidkeys)
        assert tamHab.db.scgs.cnt(keys=saidkeys) == 0
        assert tamHab.db.ssgs.cnt(keys=saidkeys) == 0
        osaidkeys = saidkeys

        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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
        assert serder.dig == serderR.dig
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
        data = dict( cid=nelHab.pre,
                     role=role,
                     eid=welHab.pre,
                   )

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0  # independent datetimes for each eid
        msg = nelHab.endorse(serder=serderR)

        # tam process for nel watcher wel
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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
        items = [ (keys, ender.allowed) for keys,  ender
                  in tamHab.db.ends.getItemIter(keys=(nelHab.pre, role))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                           False)]

        # get all watchers in ends
        items = [ (keys, ender.allowed) for keys,  ender
                      in nelHab.db.ends.getItemIter(keys=(nelHab.pre, role))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                               'watcher',
                                'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                              True),
                             (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                                'watcher',
                                'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                               False)]

        # restore wat as watcher
        data = dict( cid=nelHab.pre,
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

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"EuAfTbTUnkflpg3jRS6UZ4_KoSCVQ6_hpOjo'
                                b'sEpeiXWU","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                                b'd":"BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs","scheme":"http","url":"htt'
                                b'p://localhost:8080/watcher/wat"}}')

        assert serderR.said == 'EuAfTbTUnkflpg3jRS6UZ4_KoSCVQ6_hpOjosEpeiXWU'

        # Sign Reply
        msg = watHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"EuAfTbTUnkflpg3jRS6UZ4_K'
                    b'oSCVQ6_hpOjosEpeiXWU","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WS'
                    b'RlpHwtGs","scheme":"http","url":"http://localhost:8080/watcher/w'
                    b'at"}}-VAi-CABBXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs0BwAeTU'
                    b'CYDXu4RYWGcOWeRvcUrIeM2XL4z2Uvzl16A4RZ60xKuis92kTaMxRYcwg-qbZuya'
                    b'FNgzthKfSY03VomDg')

        # use Tam's parser and kevery to process
        tamPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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
        data = dict( cid=tamHab.pre,
                     role=role,
                     eid=wesHab.pre,
                   )

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"ErMaG30t2WhCS7VbMEtN6uTjfztlkbESh1vM'
                            b'HrGyjY0Q","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"'
                            b'cid":"EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M","role":"witness","eid":"'
                            b'BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY"}}')

        assert serderR.said == 'ErMaG30t2WhCS7VbMEtN6uTjfztlkbESh1vMHrGyjY0Q'

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000113_","t":"rpy","d":"ErMaG30t2WhCS7VbMEtN6uTj'
                    b'fztlkbESh1vMHrGyjY0Q","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/end/role/add","a":{"cid":"EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BL'
                    b'aRMirZ4I8M","role":"witness","eid":"BFUOWBaJz-sB_6b-_u_P9W8hgBQ8'
                    b'Su9mAtN9cY2sVGiY"}}-VBg-FABEQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRM'
                    b'irZ4I8M0AAAAAAAAAAAAAAAAAAAAAAAETbIi40gakUBXSBVi55Vnadttn4A-GKsH'
                    b'IAeZxnfn_zg-AADAAffDL_OJLC_At3P-U9SQJmejYjgU-q7TwsiWln4_hDNoMNv_'
                    b'-clEHl1A1UAzFIi2WiPU9SGu6b3dMnEW4cwcoAwAB81_Nph4W2ru0dYOPKMyGTvI'
                    b'Fhcl_xIPZYQXkIEz2Y1OHr6_mXkqRDvkexxf8iag8VsuyadvS_FlJq8wthDCgAQA'
                    b'CmJDe4G2PCrsn9x2hZoPFGtHPw1qWaWSyItKNZyeoqQqAFbJ_HWzHz28pyDunxYH'
                    b'lQxVTjq5UqIthmi2vH-aWDg')

        # use Nel's parser and kevery to authZ wes as tam end witness
        nelPrs.parse(ims=bytearray(msg))  # no kel for tam so escrow
        # check escrow
        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
        quadkeys = (serderR.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role", )  # escrow route base not full route
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

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000108_","t":"rpy","d":"ECdQJkLqcnjoH_yXlb-wTLFARLmtWQ07v8IQ'
                            b'8uQlsrNA","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                            b'd":"EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M","scheme":"http","url":"htt'
                            b'p://localhost:8080/controller/tam"}}')


        assert serderR.said == 'ECdQJkLqcnjoH_yXlb-wTLFARLmtWQ07v8IQ8uQlsrNA'

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000108_","t":"rpy","d":"ECdQJkLqcnjoH_yXlb-wTLFA'
                    b'RLmtWQ07v8IQ8uQlsrNA","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaR'
                    b'MirZ4I8M","scheme":"http","url":"http://localhost:8080/controlle'
                    b'r/tam"}}-VBg-FABEQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M0AAA'
                    b'AAAAAAAAAAAAAAAAAAAAETbIi40gakUBXSBVi55Vnadttn4A-GKsHIAeZxnfn_zg'
                    b'-AADAAXE8h9aPJ9iOCbUUs--RjL_f0xdZKlzbRJES2OAXEPgXi0dksszbBs19Sws'
                    b'jD7VxKf69_YmcPToGodogaMLjlCgABuzSoDI9BvkG4T8WDPeHBy9aFDImSJRb9Kd'
                    b'uHScC8-r6x-qR7CZYUMIV6iR73b3SAH78uEBy20o8MROn97dT9DAACQfC_3ySkKT'
                    b'z6XBIWwVQ8KwXXlalWqOxjPVq8C2QSd8Eo-dVcEQe3bfVd9jM9HygM0y4ZWhL81e'
                    b'aa_za_DVWWDw')

        # use Tam's parser and kevery to process
        nelPrs.parse(ims=bytearray(msg))  # no kel for tam so escrow
        # check escrow
        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
        quadkeys = (serderR.said,
                        tamHab.pre,
                        f"{tamHab.kever.lastEst.s:032x}",
                        tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/loc/scheme", )  # escrow route base not full route
        [saider] = nelHab.db.rpes.get(keys=escrowkeys)
        assert saider.qb64 == serder.said

        serder1 = serderR

        # add tam kel to nel and process escrows
        tamicp = tamHab.makeOwnInception()
        nelPrs.parse(bytearray(tamicp))
        assert tamHab.pre not in nelKvy.kevers
        wesPrs.parse(bytearray(tamicp))
        assert tamHab.pre in wesKvy.kevers
        wokPrs.parse(bytearray(tamicp))
        assert tamHab.pre in wokKvy.kevers
        wamPrs.parse(bytearray(tamicp))
        assert tamHab.pre in wamKvy.kevers
        wittamicp = wesHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp))
        wittamicp = wokHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp))
        wittamicp = wamHab.witness(tamHab.iserder)
        nelPrs.parse(bytearray(wittamicp))
        nelKvy.processEscrows()
        assert tamHab.pre in nelHab.kevers

        # process escrow reply
        nelKvy.processEscrowReply()

        #verify /end/role escrow removed
        saidkeys = (serder0.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serder0.dig
        quadkeys = (serder0.said,
                    tamHab.pre,
                    f"{tamHab.kever.lastEst.s:032x}",
                    tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role", )  # escrow route base not full route
        assert not nelHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, wesHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        #verify /loc/scheme escrow removed
        saidkeys = (serder1.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serder1.dig
        quadkeys = (serder1.said,
                        tamHab.pre,
                        f"{tamHab.kever.lastEst.s:032x}",
                        tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/loc/scheme", )  # escrow route base not full route
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
        data = dict( cid=tamHab.pre,
                         role=role,
                         eid=wokHab.pre,
                         )

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)

        # use Nel's parser and kevery to authZ wok as tam end witness
        nelPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        serderR = eventing.reply(route=route, data=data,)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        assert serderR.raw == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"ESlxGHZLKc8yZHI1y4xiUNCRDy3dwjaGsHaD'
                               b'UccwnjGM","dt":"2021-01-01T00:00:00.000000+00:00","r":"/loc/scheme","a":{"ei'
                               b'd":"BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc","scheme":"http","url":"htt'
                               b'p://localhost:8080/witness/wok"}}')

        assert serderR.said == 'ESlxGHZLKc8yZHI1y4xiUNCRDy3dwjaGsHaDUccwnjGM'

        # Sign Reply
        msg = wokHab.endorse(serder=serderR)
        assert msg == (b'{"v":"KERI10JSON000105_","t":"rpy","d":"ESlxGHZLKc8yZHI1y4xiUNCR'
                    b'Dy3dwjaGsHaDUccwnjGM","dt":"2021-01-01T00:00:00.000000+00:00","r'
                    b'":"/loc/scheme","a":{"eid":"BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE'
                    b'-hgg4Stc","scheme":"http","url":"http://localhost:8080/witness/w'
                    b'ok"}}-VAi-CABBpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc0BLjgDI'
                    b'JDF1vJc3Nh1pmUGU0kfil2jXICFjfHwo0T7nM0sPfioWhhVf3legivO2q1RSUSCh'
                    b't83I09EXiKocZKYBg')

        # use Nels's parser and kevery to process
        nelPrs.parse(ims=bytearray(msg))

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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

        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_1
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
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
        data = dict( cid=tamHab.pre,
                     role=role,
                     eid=tamHab.pre,
                   )

        serderR = eventing.reply(route=route, data=data)
        assert serderR.ked['dt'] == help.helping.DTS_BASE_0

        # Sign Reply
        msg = tamHab.endorse(serder=serderR)

        # use Nel's parser and kevery to authZ tam as tam end controller
        nelPrs.parse(ims=bytearray(msg))

        #verify /end/role escrow removed
        saidkeys = (serderR.said, )
        dater = nelHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = nelHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
        quadkeys = (serderR.said,
                        tamHab.pre,
                        f"{tamHab.kever.lastEst.s:032x}",
                        tamHab.kever.lastEst.d)
        sigers = nelHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role", )  # escrow route base not full route
        assert not nelHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, tamHab.pre)
        saider = nelHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = nelHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # use Tam's parser and kevery to authZ tam as tam end controller in tam's kel
        tamHab.psr.parse(ims=bytearray(msg))

        #verify /end/role escrow removed
        saidkeys = (serderR.said, )
        dater = tamHab.db.sdts.get(keys=saidkeys)
        assert dater.dts == help.helping.DTS_BASE_0
        serder = tamHab.db.rpys.get(keys=saidkeys)
        assert serder.dig == serderR.dig
        quadkeys = (serderR.said,
                        tamHab.pre,
                        f"{tamHab.kever.lastEst.s:032x}",
                        tamHab.kever.lastEst.d)
        sigers = tamHab.db.ssgs.get(keys=quadkeys)
        assert len(sigers) == 3 == len(tamHab.kever.verfers)
        escrowkeys = ("/end/role", )  # escrow route base not full route
        assert not tamHab.db.rpes.get(keys=escrowkeys)

        endkeys = (tamHab.pre, role, tamHab.pre)
        saider = tamHab.db.eans.get(keys=endkeys)
        assert saider.qb64 == serder.said
        ender = tamHab.db.ends.get(keys=endkeys)
        assert ender.allowed == True
        assert ender.name == ""

        # get all roles in ends
        items = [ (keys, ender.allowed) for keys,  ender
                      in nelHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                        'controller',
                        'EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M'),
                       True),
                      (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                        'witness',
                        'BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY'),
                       True),
                      (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                        'witness',
                        'BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc'),
                       True)]


        items = [ (keys, ender.allowed) for keys,  ender
                      in nelHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                        'watcher',
                        'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                       True),
                      (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                        'watcher',
                        'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                       True)]



        items = [ (keys, ender.allowed) for keys,  ender
                      in tamHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'controller',
                            'EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M'),
                           True)]


        items = [ (keys, ender.allowed) for keys,  ender
                      in tamHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                           True)]

        # get all schemes in locs
        # nel locs
        items = [ (keys, locer.url) for keys,  locer
                      in nelHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M', 'http'),
                          'http://localhost:8088/controller/tam')]

        items = [ (keys, locer.url) for keys,  locer
                      in nelHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert not items

        items = [ (keys, locer.url) for keys, locer
                      in nelHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == []

        items = [ (keys, locer.url) for keys,  locer
                      in nelHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert items == [(('BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc', 'http'),
                          'http://localhost:8080/witness/wok')]

        items = [ (keys, locer.url) for keys,  locer
                      in nelHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs', 'http'),
                          'http://localhost:8080/watcher/wat')]

        items = [ (keys, locer.url) for keys,  locer
                      in nelHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert not items

        # tam locs
        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M', 'http'),
                          'http://localhost:8088/controller/tam')]

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert not items

        items = [ (keys, locer.url) for keys, locer
                      in tamHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == []

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert not items

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(wamHab.pre, ""))]
        assert not items

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs', 'http'),
                          'http://localhost:8080/watcher/wat')]


        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert not items


        # test Habitat methods to fetch urls ends and locs
        rurls = nelHab.fetchRoleUrls(cid=tamHab.pre)
        assert len(rurls.getall("controller")) == 1
        assert rurls["controller"][tamHab.pre]['http']  ==  'http://localhost:8088/controller/tam'
        assert len(rurls.getall("witness")) == 1
        assert rurls.getall("witness")[0][wokHab.pre]["http"] == 'http://localhost:8080/witness/wok'


        rurls = nelHab.fetchRoleUrls(cid=nelHab.pre)
        assert rurls == {'watcher': {'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs':
                                     {'http': 'http://localhost:8080/watcher/wat'}}}

        rurls = tamHab.fetchRoleUrls(cid=tamHab.pre)
        assert rurls == Mict([('controller',
                                    Mict([('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                                          Mict([('http', 'http://localhost:8088/controller/tam')]))]))])

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
        msgs.extend(tamHab.endrolize(eid=wesHab.pre, role=kering.Roles.witness))
        msgs.extend(tamHab.endrolize(eid=wokHab.pre, role=kering.Roles.witness))
        msgs.extend(tamHab.endrolize(eid=wamHab.pre, role=kering.Roles.witness))
        msgs.extend(wesHab.locschemize(url='http://localhost:8080/witness/wes'))
        msgs.extend(wokHab.locschemize(url='http://localhost:8080/witness/wok'))
        msgs.extend(wamHab.locschemize(url='http://localhost:8080/witness/wam'))

        tamHab.psr.parse(bytearray(msgs))
        wesHab.psr.parse(bytearray(msgs))
        wokHab.psr.parse(bytearray(msgs))
        wamHab.psr.parse(bytearray(msgs))

        nelHab.psr.parse(bytearray(msgs))
        watHab.psr.parse(bytearray(msgs))
        welHab.psr.parse(bytearray(msgs))

        msgs = bytearray()
        msgs.extend(nelHab.endrolize(eid=nelHab.pre, role=kering.Roles.controller))
        msgs.extend(nelHab.endrolize(eid=watHab.pre, role=kering.Roles.watcher))
        msgs.extend(nelHab.endrolize(eid=welHab.pre, role=kering.Roles.watcher))
        msgs.extend(nelHab.locschemize(url='http://localhost:8080/controller/nel'))
        msgs.extend(watHab.locschemize(url='http://localhost:8080/watcher/wat'))
        msgs.extend(welHab.locschemize(url='http://localhost:8080/watcher/wel'))


        tamHab.psr.parse(bytearray(msgs))
        wesHab.psr.parse(bytearray(msgs))
        wokHab.psr.parse(bytearray(msgs))
        wamHab.psr.parse(bytearray(msgs))

        nelHab.psr.parse(bytearray(msgs))
        watHab.psr.parse(bytearray(msgs))
        welHab.psr.parse(bytearray(msgs))

        # get all roles in ends
        items = [ (keys, ender.allowed) for keys,  ender
                      in nelHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'controller',
                            'EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BHKrk1-LQqCiERonyH0msupuFf_BrJIVJcqyC6bERhCk'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc'),
                           True)]

        items = [ (keys, ender.allowed) for keys,  ender
                      in nelHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'controller',
                            'Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                           True)]



        items = [ (keys, ender.allowed) for keys,  ender
                      in tamHab.db.ends.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'controller',
                            'EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BHKrk1-LQqCiERonyH0msupuFf_BrJIVJcqyC6bERhCk'),
                           True),
                          (('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M',
                            'witness',
                            'BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc'),
                           True)]


        items = [ (keys, ender.allowed) for keys,  ender
                      in tamHab.db.ends.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'controller',
                            'Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI'),
                           True),
                          (('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI',
                            'watcher',
                            'BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs'),
                           True)]


        # tam locs
        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(tamHab.pre, ""))]
        assert items == [(('EQSPzsnxx3hHA9FMk_oh_nO-nVOXYCQ-BLaRMirZ4I8M', 'http'),
                          'http://localhost:8088/controller/tam')]

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(nelHab.pre, ""))]
        assert items == [(('Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI', 'http'),
                          'http://localhost:8080/controller/nel')]

        items = [ (keys, locer.url) for keys, locer
                      in tamHab.db.locs.getItemIter(keys=(wesHab.pre, ""))]
        assert items == [(('BFUOWBaJz-sB_6b-_u_P9W8hgBQ8Su9mAtN9cY2sVGiY', 'http'),
                          'http://localhost:8080/witness/wes')]

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(wokHab.pre, ""))]
        assert [(('BpVvny4hN_jxigw_PxIE5NXAuBM70FjigRdE-hgg4Stc', 'http'),
                 'http://localhost:8080/witness/wok')]

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(wamHab.pre, ""))]
        assert [(('BHKrk1-LQqCiERonyH0msupuFf_BrJIVJcqyC6bERhCk', 'http'),
                 'http://localhost:8080/witness/wam')]

        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(watHab.pre, ""))]
        assert items == [(('BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs', 'http'),
                          'http://localhost:8080/watcher/wat')]


        items = [ (keys, locer.url) for keys,  locer
                      in tamHab.db.locs.getItemIter(keys=(welHab.pre, ""))]
        assert items == [(('BPR6e5pqTwaT-wNJasfLsf5HCozso1-IKPqTkkrPWgQI', 'http'),
                          'http://localhost:8080/watcher/wel')]


    assert not os.path.exists(nelKS.path)
    assert not os.path.exists(nelDB.path)
    assert not os.path.exists(watKS.path)
    assert not os.path.exists(watDB.path)
    assert not os.path.exists(welKS.path)
    assert not os.path.exists(welDB.path)
    assert not os.path.exists(wamKS.path)
    assert not os.path.exists(wamDB.path)
    assert not os.path.exists(wokKS.path)
    assert not os.path.exists(wokDB.path)
    assert not os.path.exists(wesKS.path)
    assert not os.path.exists(wesDB.path)
    assert not os.path.exists(tamKS.path)
    assert not os.path.exists(tamDB.path)
    """Done Test"""



if __name__ == "__main__":
    pytest.main(['-vv', 'test_reply.py::test_reply'])



