# -*- encoding: utf-8 -*-
"""
tests.test_kering module

"""
import re
import json
from dataclasses import asdict, astuple

import cbor2 as cbor
import msgpack

import pytest

from keri import kering
from keri.kering import Protocolage, Protocols
from keri.kering import Kindage,  Kinds
from keri.kering import Ilkage, Ilks
from keri.kering import ColdCodex, ColdDex, TraitCodex, TraitDex
from keri.kering import (Versionage, Version, Vrsn_1_0, Vrsn_2_0, MAXVERFULLSPAN,
                         versify, deversify, Rever, Smellage, smell,
                         VER1FULLSPAN, VER1TERM, VEREX1,
                         VER2FULLSPAN, VER2TERM, VEREX2,
                         VEREX)


from keri.kering import VersionError, ProtocolError, KindError
from keri.help.helping import (intToB64, intToB64b, b64ToInt, B64_CHARS,
                         codeB64ToB2, codeB2ToB64, Reb64, nabSextets)


def test_protocols():
    """
    Test protocols namedtuple instance Protocols
    """

    assert isinstance(Protocols, Protocolage)

    assert Protocols.keri == 'KERI'
    assert Protocols.acdc == 'ACDC'

    assert 'KERI' in Protocols
    assert 'ACDC' in Protocols

    """End Test"""



def test_version_regex():
    """
    Test version string regexing

    VER1FULLSPAN = 17  # number of characters in full version string
    VER1TERM = b'_'
    VEREX1 = b'(?P<proto1>[A-Z]{4})(?P<major1>[0-9a-f])(?P<minor1>[0-9a-f])(?P<kind1>[A-Z]{4})(?P<size1>[0-9a-f]{6})_'

    VER2FULLSPAN = 16  # number of characters in full version string
    VER2TERM = b'.'
    VEREX2 = b'(?P<proto2>[A-Z]{4})(?P<major2>[0-9A-Za-z_-])(?P<minor2>[0-9A-Za-z_-]{2})(?P<kind2>[A-Z]{4})(?P<size2>[0-9A-Za-z_-]{4}).'

    VEREX = VEREX2 + b'|' + VEREX1
    """


    # Test VEREX2 by itself
    pattern = re.compile(VEREX2)  # compile is faster

    vs = b'KERICAACAAJSONAAAB.'   #b'KERICAAJSONAAAB.'

    match = pattern.match(vs)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vs
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")  # terminator
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "pmajor2",
                        "pminor2",
                        "gmajor2",
                        "gminor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'C', B'AA', b'JSON', b'AAAB')

    # Test VEREX with combined VEREXes
    pattern = re.compile(VEREX)  # compile is faster

    vs = b'KERICAACAAJSONAAAB.'

    match = pattern.match(vs)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vs
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "pmajor2",
                        "pminor2",
                        "gmajor2",
                        "gminor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'C', B'AA', b'JSON', b'AAAB')

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

    raw = b'{"v":"KERICAACAAJSONAAAB.","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    span = len(full)
    assert span == VER2FULLSPAN
    assert VER2TERM ==  chr(full[-1]).encode("utf-8")
    assert ord(VER2TERM) == full[-1]

    groups = match.group("proto2",
                        "pmajor2",
                        "pminor2",
                        "gmajor2",
                        "gminor2",
                        "kind2",
                        "size2")

    assert groups == (b'KERI', b'C', b'AA', b'C', B'AA', b'JSON', b'AAAB')


    raw = b'{"v":"KERI10JSON000002_","pre":"AaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM"}'

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


def test_smell():
    """
    Test smell function to parse into Serializations
    """

    raw = b'{"vs":"KERICAACAAJSONAAAB.","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    assert smell(raw) == Smellage(proto='KERI',
                                  pvrsn=Versionage(major=2, minor=0),
                                  kind='JSON',
                                  size=1,
                                  gvrsn=Versionage(major=2, minor=0))

    raw = b'{"vs":"KERI10JSON000002_","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    assert smell(raw) == Smellage(proto='KERI',
                                  pvrsn=Versionage(major=1, minor=0),
                                  kind='JSON',
                                  size=2,
                                  gvrsn=None)

    raw = b'{"vs":"KERICAACAAJSONAAABX.","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    with pytest.raises(ProtocolError):
        smell(raw)

    raw = b'{"vs":"KERI1XJSON000002_","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    with pytest.raises(VersionError):
        smell(raw)

    """End Test"""


def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """

    assert Version == Versionage(major=1, minor=0) == Vrsn_1_0

    assert isinstance(Kinds, Kindage)

    assert Kinds.json == 'JSON'
    assert Kinds.mgpk == 'MGPK'
    assert Kinds.cbor == 'CBOR'
    assert Kinds.cesr == 'CESR'

    assert 'JSON' in Kinds
    assert 'MGPK' in Kinds
    assert 'CBOR' in Kinds
    assert 'CESR' in Kinds

    Vstrings = Kindage(json=versify(kind=Kinds.json, size=0),
                         mgpk=versify(kind=Kinds.mgpk, size=0),
                         cbor=versify(kind=Kinds.cbor, size=0),
                         cesr=versify(pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0,
                                      kind=Kinds.cesr, size=0))


    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'
    assert Vstrings.cesr == 'KERICAACAACESRAAAA.'

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


def test_versify_v1():
    """
    Test Versify support
    """

    assert VER2FULLSPAN == MAXVERFULLSPAN

    # default version is version 1

    vs = versify()   # defaults
    assert vs == "KERI10JSON000000_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == Version
    assert size == 0

    vs = versify(kind=Kinds.json, size=65)
    assert vs == "KERI10JSON000041_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == Version
    assert size == 65

    vs = versify(proto=Protocols.acdc, kind=Kinds.json, size=86)
    assert vs == "ACDC10JSON000056_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.acdc
    assert kind == Kinds.json
    assert vrsn == Version
    assert size == 86

    vs = versify(kind=Kinds.mgpk, size=0)
    assert vs == "KERI10MGPK000000_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert vrsn == Version
    assert size == 0

    vs = versify(kind=Kinds.mgpk, size=65)
    assert vs == "KERI10MGPK000041_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert vrsn == Version
    assert size == 65

    vs = versify(kind=Kinds.cbor, size=0)
    assert vs == "KERI10CBOR000000_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert vrsn == Version
    assert size == 0

    vs = versify(kind=Kinds.cbor, size=65)
    assert vs == "KERI10CBOR000041_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert vrsn == Version
    assert size == 65

    vs = versify(pvrsn=Versionage(major=1, minor=1))   # defaults
    assert vs == "KERI11JSON000000_"
    assert len(vs) == VER1FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == (1, 1)
    assert size == 0

    # test bad version strings
    vs = "KERI20JSON000000_"
    with pytest.raises(VersionError):
        smellage = deversify(vs)

    vs = "ABLE10JSON000000_"
    with pytest.raises(ProtocolError):
        smellage = deversify(vs)

    vs = "KERI10MSON000000_"
    with pytest.raises(KindError):
        smellage = deversify(vs)


    """End Test"""


def test_versify_v2():
    """
    Test Versify support
    """
    version = Versionage(major=2, minor=0)
    assert version == (2, 0)

    vs = versify(pvrsn=version)   # defaults
    assert vs == "KERICAACAAJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == version
    assert gvrsn == version
    assert size == 0

    vs = versify(pvrsn=version, kind=Kinds.json, size=65)
    assert vs == "KERICAACAAJSONAABB."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == version
    assert gvrsn == version
    assert size == 65

    vs = versify(proto=Protocols.acdc, pvrsn=version, kind=Kinds.json, size=86)
    assert vs == "ACDCCAACAAJSONAABW."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.acdc
    assert kind == Kinds.json
    assert pvrsn == version
    assert gvrsn == version
    assert size == 86

    vs = versify(pvrsn=version, kind=Kinds.mgpk, size=0)
    assert vs == 'KERICAACAAMGPKAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert pvrsn == version
    assert gvrsn == version
    assert size == 0

    vs = versify(pvrsn=version, kind=Kinds.mgpk, size=65)
    assert vs == 'KERICAACAAMGPKAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert pvrsn == version
    assert gvrsn == version
    assert size == 65

    vs = versify(pvrsn=version, kind=Kinds.cbor, size=0)
    assert vs == 'KERICAACAACBORAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert pvrsn == version
    assert gvrsn == version
    assert size == 0

    vs = versify(pvrsn=version, kind=Kinds.cbor, size=65)
    assert vs == 'KERICAACAACBORAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert pvrsn == version
    assert gvrsn == version
    assert size == 65

    vs = versify(pvrsn=Versionage(major=2, minor=1))   # defaults
    assert vs == "KERICABCABJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == (2, 1)
    assert gvrsn == (2, 1)
    assert size == 0

    # gvrsn.minor not equal pvrsn.minor
    pvrsn2 = Vrsn_2_0
    gvrsn2 = Versionage(2, 2)
    vs = versify(pvrsn=pvrsn2, gvrsn=gvrsn2)
    assert vs == "KERICAACACJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 0

    vs = versify(pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.json, size=65)
    assert vs == "KERICAACACJSONAABB."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 65

    vs = versify(proto=Protocols.acdc, pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.json, size=86)
    assert vs == "ACDCCAACACJSONAABW."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.acdc
    assert kind == Kinds.json
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 86

    vs = versify(pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.mgpk, size=0)
    assert vs == 'KERICAACACMGPKAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 0

    vs = versify(pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.mgpk, size=65)
    assert vs == 'KERICAACACMGPKAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 65

    vs = versify(pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.cbor, size=0)
    assert vs == 'KERICAACACCBORAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 0

    vs = versify(pvrsn=pvrsn2,gvrsn=gvrsn2, kind=Kinds.cbor, size=65)
    assert vs == 'KERICAACACCBORAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 65

    pvrsn2 = Versionage(major=2, minor=2)
    gvrsn2 = Versionage(major=2, minor=1)
    vs = versify(pvrsn=pvrsn2, gvrsn=gvrsn2)
    assert vs == "KERICACCABJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, pvrsn, kind, size, gvrsn = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert pvrsn == pvrsn2
    assert gvrsn == gvrsn2
    assert size == 0

    # test bad version strings
    vs = "KERIBAACAAJSONAAAA."
    with pytest.raises(VersionError):
        smellage = deversify(vs)

    vs = "KERI20JSON000000"
    with pytest.raises(VersionError):
        smellage = deversify(vs)

    vs = "ABLECAACAAJSONAAAA."
    with pytest.raises(ProtocolError):
        smellage = deversify(vs)

    vs = "KERICAACAAMSONAAAA."
    with pytest.raises(KindError):
        smellage = deversify(vs)

    """End Test"""


def test_colddex():
    """
    Test ColdDex instance of ColdCodex dataclass
    """

    assert isinstance(ColdDex, ColdCodex)

    assert asdict(ColdDex) == \
        {
            'AnB64': 0,
            'CtB64': 1,
            'OpB64': 2,
            'JSON': 3,
            'MGPK1': 4,
            'CBOR': 5,
            'MGPK2': 6,
            'CtOpB2': 7
        }

    assert 0o0 in ColdDex
    assert 0o1 in ColdDex
    assert 0o2 in ColdDex
    assert 0o3 in ColdDex
    assert 0o4 in ColdDex
    assert 0o5 in ColdDex
    assert 0o6 in ColdDex
    assert 0o7 in ColdDex

    """End Test"""


def test_ilks():
    """
    Test Ilkage namedtuple instance Ilks
    """
    Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt',
              rct='rct',
              qry='qry', rpy='rpy', xip='xip', exn='exn', pro='pro', bar='bar',
              vcp='vcp', vrt='vrt', iss='iss', rev='rev', bis='bis', brv='brv',
              rip='rip', bup='bup', upd='upd', acm='acm', act='act', acg='acg', ace='ace',
              sch='sch', att='att', agg='agg', edg='edg', rul='rul')

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

    assert 'rip' in Ilks
    assert Ilks.rip == 'rip'
    assert 'upd' in Ilks
    assert Ilks.upd == 'upd'

    assert 'acm' in Ilks
    assert Ilks.acm == 'acm'
    assert 'act' in Ilks
    assert Ilks.act == 'act'
    assert 'acg' in Ilks
    assert Ilks.acg == 'acg'
    assert 'ace' in Ilks
    assert Ilks.ace == 'ace'
    assert 'sch' in Ilks
    assert Ilks.sch == 'sch'
    assert 'att' in Ilks
    assert Ilks.att == 'att'
    assert 'agg' in Ilks
    assert Ilks.agg == 'agg'
    assert 'edg' in Ilks
    assert Ilks.edg == 'edg'
    assert 'rul' in Ilks
    assert Ilks.rul == 'rul'

    """End Test """

def test_traitdex():
    """
    Test TraitDex instance of TraitCodex dataclass
    """

    assert isinstance(TraitDex, TraitCodex)

    assert asdict(TraitDex) == \
        {
            'EstOnly': 'EO',
            'DoNotDelegate': 'DND',
            'RegistrarBackers': 'RB',
            'NoBackers': 'NB',
            'NoRegistrarBackers': 'NRB',
            'DelegateIsDelegator': 'DID',
        }

    assert 'EO' in TraitDex
    assert 'DND' in TraitDex
    assert 'RB' in TraitDex
    assert 'NB' in TraitDex
    assert 'NRB' in TraitDex
    assert 'DID' in TraitDex

    """End Test"""



if __name__ == "__main__":
    test_protocols()

    test_version_regex()
    test_smell()
    test_serials()
    test_versify_v1()
    test_versify_v2()
    test_ilks()
    test_colddex()
    test_traitdex()
