# -*- encoding: utf-8 -*-
"""
tests.test_kering module

"""
import re
import json

import cbor2 as cbor
import msgpack

from keri import kering
from keri.kering import Protocolage, Protos
from keri.kering import Serialage,  Serials
from keri.kering import Ilkage, Ilks
from keri.kering import (Versionage, Version, VERFULLSIZE,
                         versify, deversify, Rever)
from keri.kering import (VER1FULLSPAN, VER1TERM, VEREX1,
                         VER2FULLSPAN, VER2TERM, VEREX2, VEREX)




def test_protos():
    """
    Test protocols namedtuple instance Protos
    """

    assert isinstance(Protos, Protocolage)

    assert Protos.keri == 'KERI'
    assert Protos.crel == 'CREL'
    assert Protos.acdc == 'ACDC'

    assert 'KERI' in Protos
    assert 'CREL' in Protos
    assert 'ACDC' in Protos

    """End Test"""

def test_version_regex():
    """
    Test version string regexing
    """

    #VER1FULLSPAN = 17  # number of characters in full version string
    #VER1TERM = b'_'
    #VEREX1 = b'(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_'

    #VER2FULLSPAN = 16  # number of characters in full version string
    #VER2TERM = b'.'
    #VEREX2 = b'(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4}).'

    #VEREX = VEREX2 + b'|' + VEREX1

    pattern = re.compile(VEREX2)  # compile is faster

    vs = b'KERICAAJSONAAAB.'

    match = pattern.match(vs)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vs
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "major2",
                        "minor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'JSON', b'AAAB')


    pattern = re.compile(VEREX)  # compile is faster

    vs = b'KERICAAJSONAAAB.'

    match = pattern.match(vs)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vs
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "major2",
                        "minor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'JSON', b'AAAB')

    vs = b'KERI10JSON000002_'

    match = pattern.match(vs)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vs
    span = len(full)
    assert span == VER1FULLSPAN
    assert VER1TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER1TERM) == full[-1]

    groups = match.group("proto1",
                        "major1",
                        "minor1",
                        "kind1",
                        "size1")

    assert groups == (b'KERI', b'1', b'0', b'JSON', b'000002')

    raw = b'{"vs":"KERICAAJSONAAAB.","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "major2",
                        "minor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'JSON', b'AAAB')



    raw = b'{"vs":"KERI10JSON000002_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    span = len(full)
    assert span == VER1FULLSPAN
    assert VER1TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER1TERM) == full[-1]

    groups = match.group("proto1",
                        "major1",
                        "minor1",
                        "kind1",
                        "size1")

    assert groups == (b'KERI', b'1', b'0', b'JSON', b'000002')

    """End Test"""


def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """
    Vstrings = Serialage(json=versify(kind=Serials.json, size=0),
                         mgpk=versify(kind=Serials.mgpk, size=0),
                         cbor=versify(kind=Serials.cbor, size=0))

    assert Version == Versionage(major=1, minor=0)

    assert isinstance(Serials, Serialage)

    assert Serials.json == 'JSON'
    assert Serials.mgpk == 'MGPK'
    assert Serials.cbor == 'CBOR'

    assert 'JSON' in Serials
    assert 'MGPK' in Serials
    assert 'CBOR' in Serials

    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'

    icp = dict(vs=Vstrings.json,
               pre='AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
               sn='0001',
               ilk='icp',
               dig='DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
               sith=1,
               keys=['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
               nxt='DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
               toad=0,
               wits=[],
               cnfg=[],
               )

    rot = dict(vs=Vstrings.json,
               pre='AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM',
               sn='0001',
               ilk='rot',
               dig='DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfS',
               sith=1,
               keys=['AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'],
               nxt='DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM',
               toad=0,
               cuts=[],
               adds=[],
               data=[],
               )

    icps = json.dumps(icp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(icps) == 303
    assert icps == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"icp","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"wits":[],"cnfg":[]}')

    match = Rever.search(icps)
    assert match.group() == Vstrings.json.encode("utf-8")

    rots = json.dumps(rot, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert len(rots) == 313
    assert rots == (b'{"vs":"KERI10JSON000000_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'","sn":"0001","ilk":"rot","dig":"DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'S","sith":1,"keys":["AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"],"nxt":"'
                    b'DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM","toad":0,"cuts":[],"adds":[],"'
                    b'data":[]}')

    match = Rever.search(rots)
    assert match.group() == Vstrings.json.encode("utf-8")

    icp["vs"] = Vstrings.mgpk
    icps = msgpack.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\x8b\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3icp\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4wits\x90\xa4cnfg\x90')

    match = Rever.search(icps)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    rot["vs"] = Vstrings.mgpk
    rots = msgpack.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\x8c\xa2vs\xb1KERI10MGPK000000_\xa3pre\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAf'
                    b'SVPzhzS6b5CM\xa2sn\xa40001\xa3ilk\xa3rot\xa3dig\xd9,DVPzhzS6b5CMaU6JR2nmwy'
                    b'Z-i0d8JZAoTNZH3ULvYAfS\xa4sith\x01\xa4keys\x91\xd9,AaU6JR2nmwyZ-i0d8JZAoTNZ'
                    b'H3ULvYAfSVPzhzS6b5CM\xa3nxt\xd9,DZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5'
                    b'CM\xa4toad\x00\xa4cuts\x90\xa4adds\x90\xa4data\x90')

    match = Rever.search(rots)
    assert match.group() == Vstrings.mgpk.encode("utf-8")

    icp["vs"] = Vstrings.cbor
    icps = cbor.dumps(icp)
    assert len(icps) == 264
    assert icps == (b'\xabbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcicpcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dwits\x80dcnfg\x80')

    match = Rever.search(icps)
    assert match.group() == Vstrings.cbor.encode("utf-8")

    rot["vs"] = Vstrings.cbor
    rots = cbor.dumps(rot)
    assert len(rots) == 270
    assert rots == (b'\xacbvsqKERI10CBOR000000_cprex,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM'
                    b'bsnd0001cilkcrotcdigx,DVPzhzS6b5CMaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSdsith\x01'
                    b'dkeys\x81x,AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CMcnxtx,DZ-i0d8JZAoTNZ'
                    b'H3ULvaU6JR2nmwyYAfSVPzhzS6b5CMdtoad\x00dcuts\x80dadds\x80ddata\x80')

    match = Rever.search(rots)
    assert match.group() == Vstrings.cbor.encode("utf-8")
    """Done Test"""


def test_versify():
    """
    Test Versify support
    """
    vs = versify(kind=Serials.json, size=0)
    assert vs == "KERI10JSON000000_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.json
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.json, size=65)
    assert vs == "KERI10JSON000041_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.json
    assert version == Version
    assert size == 65

    vs = versify(proto=Protos.acdc, kind=Serials.json, size=86)
    assert vs == "ACDC10JSON000056_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.acdc
    assert kind == Serials.json
    assert version == Version
    assert size == 86

    vs = versify(kind=Serials.mgpk, size=0)
    assert vs == "KERI10MGPK000000_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.mgpk
    assert version == Version
    assert size == 65

    vs = versify(kind=Serials.cbor, size=0)
    assert vs == "KERI10CBOR000000_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.cbor
    assert version == Version
    assert size == 0

    vs = versify(kind=Serials.cbor, size=65)
    assert vs == "KERI10CBOR000041_"
    assert len(vs) == VERFULLSIZE
    proto, version, kind, size = deversify(vs)
    assert proto == Protos.keri
    assert kind == Serials.cbor
    assert version == Version
    assert size == 65
    """End Test"""


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    assert Ilks == Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
                          rct='rct', qry='qry', rpy='rpy',
                          exn='exn', pro='pro', bar='bar',
                          vcp='vcp', vrt='vrt',
                          iss='iss', rev='rev', bis='bis', brv='brv', )

    assert isinstance(Ilks, Ilkage)

    for fld in Ilks._fields:
        assert fld == getattr(Ilks, fld)

    assert 'icp' in Ilks
    assert Ilks.icp == 'icp'
    assert 'rot' in Ilks
    assert Ilks.rot == 'rot'
    assert 'ixn' in Ilks
    assert Ilks.ixn == 'ixn'
    assert 'dip' in Ilks
    assert Ilks.dip == 'dip'
    assert 'drt' in Ilks
    assert Ilks.drt == 'drt'
    assert 'rct' in Ilks
    assert Ilks.rct == 'rct'
    assert 'qry' in Ilks
    assert Ilks.qry == 'qry'
    assert 'rpy' in Ilks
    assert Ilks.rpy == 'rpy'
    assert 'exn' in Ilks
    assert Ilks.exn == 'exn'


    assert 'pro' in Ilks
    assert Ilks.pro == 'pro'
    assert 'bar' in Ilks
    assert Ilks.bar == 'bar'


    assert 'vcp' in Ilks
    assert Ilks.vcp == 'vcp'
    assert 'vrt' in Ilks
    assert Ilks.vrt == 'vrt'
    assert 'iss' in Ilks
    assert Ilks.iss == 'iss'
    assert 'rev' in Ilks
    assert Ilks.rev == 'rev'
    assert 'bis' in Ilks
    assert Ilks.bis == 'bis'
    assert 'brv' in Ilks
    assert Ilks.brv == 'brv'

    """End Test """


if __name__ == "__main__":
    test_protos()
    test_version_regex()
    test_serials()
    test_versify()
    test_ilks()
