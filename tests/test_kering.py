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
from keri.kering import (Versionage, Version, MAXVERFULLSPAN,
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

    # Test VEREX with combined VEREXes
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


def test_smell():
    """
    Test smell function to parse into Serializations
    """

    raw = b'{"vs":"KERICAAJSONAAAB.","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    assert smell(raw) == Smellage(proto='KERI',
                                  vrsn=Versionage(major=2, minor=0),
                                  kind='JSON',
                                  size=1,
                                  gvrsn=None)

    raw = b'{"vs":"KERI10JSON000002_","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    assert smell(raw) == Smellage(proto='KERI',
                                  vrsn=Versionage(major=1, minor=0),
                                  kind='JSON',
                                  size=2,
                                  gvrsn=None)

    raw = b'{"vs":"KERICAAJSONAAABX.","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    with pytest.raises(ProtocolError):
        smell(raw)

    raw = b'{"vs":"KERI1XJSON000002_","t":"ixn","d":"EPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf"}'
    with pytest.raises(VersionError):
        smell(raw)

    """End Test"""


def test_snuff():
    """
    Test snuff for looking ahead at CESR native messages from stream

    VER0FULLSPAN = 12  # number of characters in full version string
    VEREX0 = b'0N(?P<proto0>[A-Z]{4})(?P<major0>[0-9A-Za-z_-])(?P<minor0>[0-9A-Za-z_-]{2})(?P<gmajor0>[0-9A-Za-z_-])(?P<gminor0>[0-9A-Za-z_-]{2})'


    """

    # version field in CESR native serialization
    VFFULLSPAN = 12  # number of characters in full version string
    VFREX = b'0N(?P<proto0>[A-Z]{4})(?P<major0>[0-9A-Za-z_-])(?P<minor0>[0-9A-Za-z_-]{2})(?P<gmajor0>[0-9A-Za-z_-])(?P<gminor0>[0-9A-Za-z_-]{2})'

    Revfer = re.compile(VFREX)  # compile is faster

    MAXVFOFFSET = 12

    SNUFFSIZE = MAXVFOFFSET + VFFULLSPAN

    def snatch(match, size=0):
        """ Returns:
            smellage (Smellage): named tuple extracted from version string regex match
                                (protocol, version, kind, size)

        Parameters:
            match (re.Match):  instance of Match class
            size (int): provided size to substitute when missing

        Notes:
            regular expressions work with memoryview objects not just bytes or
            bytearrays
        """
        full = match.group()  # full matched version string
        if len(full) == VFFULLSPAN:
            proto, major, minor, gmajor, gminor = match.group("proto0",
                                                         "major0",
                                                         "minor0",
                                                         "gmajor0",
                                                         "gminor0")
            proto = proto.decode("utf-8")
            if proto not in Protocols:
                raise ProtocolError(f"Invalid protocol type = {proto}.")
            vrsn = Versionage(major=b64ToInt(major), minor=b64ToInt(minor))
            if vrsn.major < 2:  # version2 vs but major < 2
                raise VersionError(f"Incompatible {vrsn=} with version string.")

            gvrsn = Versionage(major=b64ToInt(gmajor), minor=b64ToInt(gminor))
            if gvrsn.major < 2:  # version2 vs but major < 2
                raise VersionError(f"Incompatible {gvrsn=} with CESR native version"
                                   f"field.")
            kind = Kinds.cesr
            size = size
        else:
            raise VersionError(f"Bad snatch.")

        return Smellage(proto=proto, vrsn=vrsn, kind=kind, size=size, gvrsn=gvrsn)


    def snuff(raw, size=0):
        """Extract and return instance of Smellage from version string inside
        raw serialization.

        Returns:
            smellage (Smellage): named Tuple of (protocol, version, kind, size)

        Parameters:
            raw (bytearray) of serialized incoming message stream. Assumes start
                of stream is JSON, CBOR, or MGPK field map with first field
                is labeled 'v' and value is version string.
            size (int): provided size to substitute when missing

        """
        if len(raw) < SNUFFSIZE:
            raise kering.ShortageError(f"Need more raw bytes to smell full version string.")

        match = Rever.search(raw)  # Rever regex takes bytes/bytearray not str
        if not match or match.start() > MAXVFOFFSET:
            raise kering.VersionError(f"Invalid version string from smelled raw = "
                               f"{raw[: SNUFFSIZE]}.")

        return snatch(match, size=size)







    #pattern = re.compile(VFREX)  # compile is faster
    pattern = Revfer

    vv = b'0NKERICAACAB'

    match = pattern.match(vv)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')

    raw = b'-FAM' + vv
    assert raw == b'-FAM0NKERICAACAB'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')

    raw = b'-0FAAAAM' + vv
    assert raw == b'-0FAAAAM0NKERICAACAB'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')


    vv = b'0NKERICAACAB'

    match = pattern.match(vv)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')

    raw = b'-FAM' + vv
    assert raw == b'-FAM0NKERICAACAB'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')

    raw = b'-0FAAAAM' + vv
    assert raw == b'-0FAAAAM0NKERICAACAB'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'C', b'AA', b'C', b'AB')

    vv = b'0NKERI______'
    raw = b'-0FAAAAM' + vv
    assert raw == b'-0FAAAAM0NKERI______'

    match = pattern.search(raw)
    assert match

    full = match.group()  # not group args so returns full  match
    assert full == vv
    span = len(full)
    assert span == VFFULLSPAN

    groups = match.group("proto0",
                        "major0",
                        "minor0",
                        "gmajor0",
                        "gminor0")

    assert groups == (b'KERI', b'_', b'__', b'_', b'__')



    #raw = b'-FAM0NKERICAACABXicpEPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf'
    #assert smell(raw) == Smellage(protocol='KERI',
                                  #version=Versionage(major=2, minor=0),
                                  #kind='CESR',
                                  #size=0)

    #raw =b'-0FAAAAM0NKERICAACABXrotEPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf'
    #assert smell(raw, size=4096) == Smellage(protocol='KERI',
                                             #version=Versionage(major=2, minor=0),
                                             #kind='CESR',
                                             #size=4096)

    #raw =b'-0FAAAAM0MKERICAACABXrotEPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf'
    #with pytest.raises(VersionError):
        #smell(raw)

    #raw =b'-0FAAAAMNKERICAACABXrotEPTgL0UEOa8xUWBqghryJYMLOd2eYjmclndQN4bArjSf'
    #with pytest.raises(VersionError):
        #smell(raw)



def test_serials():
    """
    Test Serializations namedtuple instance Serials
    """

    assert Version == Versionage(major=1, minor=0)

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
                         cesr=versify(kind=Kinds.cesr, size=0))


    assert Vstrings.json == 'KERI10JSON000000_'
    assert Vstrings.mgpk == 'KERI10MGPK000000_'
    assert Vstrings.cbor == 'KERI10CBOR000000_'
    assert Vstrings.cesr == 'KERI10CESR000000_'

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

    assert VER1FULLSPAN == MAXVERFULLSPAN

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

    vs = versify(protocol=Protocols.acdc, kind=Kinds.json, size=86)
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

    vs = versify(version=Versionage(major=1, minor=1))   # defaults
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

    vs = versify(version=version)   # defaults
    assert vs == "KERICAAJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == version
    assert size == 0

    vs = versify(version=version, kind=Kinds.json, size=65)
    assert vs == "KERICAAJSONAABB."
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == version
    assert size == 65

    vs = versify(protocol=Protocols.acdc, version=version, kind=Kinds.json, size=86)
    assert vs == "ACDCCAAJSONAABW."
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.acdc
    assert kind == Kinds.json
    assert version == version
    assert size == 86

    vs = versify(version=version, kind=Kinds.mgpk, size=0)
    assert vs == 'KERICAAMGPKAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert vrsn == version
    assert size == 0

    vs = versify(version=version, kind=Kinds.mgpk, size=65)
    assert vs == 'KERICAAMGPKAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.mgpk
    assert vrsn == version
    assert size == 65

    vs = versify(version=version, kind=Kinds.cbor, size=0)
    assert vs == 'KERICAACBORAAAA.'
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert vrsn == version
    assert size == 0

    vs = versify(version=version, kind=Kinds.cbor, size=65)
    assert vs == 'KERICAACBORAABB.'
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.cbor
    assert vrsn == version
    assert size == 65

    vs = versify(version=Versionage(major=2, minor=1))   # defaults
    assert vs == "KERICABJSONAAAA."
    assert len(vs) == VER2FULLSPAN
    proto, vrsn, kind, size, opt = deversify(vs)
    assert proto == Protocols.keri
    assert kind == Kinds.json
    assert vrsn == (2, 1)
    assert size == 0

    # test bad version strings
    vs = "KERIBAAJSONAAAA."
    with pytest.raises(VersionError):
        smellage = deversify(vs)

    vs = "KERI20JSON000000"
    with pytest.raises(VersionError):
        smellage = deversify(vs)

    vs = "ABLECAAJSONAAAA."
    with pytest.raises(ProtocolError):
        smellage = deversify(vs)

    vs = "KERICAAMSONAAAA."
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
              rip='rip', upd='upd', acd='acd', ace='ace',
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

    assert 'acd' in Ilks
    assert Ilks.acd == 'acd'
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
    test_snuff()
    test_serials()
    test_versify_v1()
    test_versify_v2()
    test_ilks()
    test_colddex()
    test_traitdex()
