# -*- encoding: utf-8 -*-
"""
tests.core.test_counting module

"""
from dataclasses import dataclass, astuple, asdict
from  ordered_set import OrderedSet as oset
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pytest


from keri import kering

from keri.help import helping
from keri.help.helping import sceil
from keri.help.helping import (intToB64,  b64ToInt, codeB64ToB2, codeB2ToB64,
                            nabSextets)

from keri.core import counting
from keri.core.counting import Sizage, MapDom, MapCodex, Counter
from keri.core.counting import Versionage, Version, Vrsn_1_0, Vrsn_2_0, AllTags


def test_mapdom():
    """Test MapDom base dataclass"""

    @dataclass
    class TestMapDom(MapDom):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmd = TestMapDom()

    assert 'X' in tmd
    assert 'Y' in tmd
    assert 'Z' in tmd

    assert tmd["xray"] == tmd.xray == 'X'
    assert tmd["yankee"] == tmd.yankee == 'Y'
    assert tmd["zulu"] == tmd.zulu == 'Z'


    tmd["xray"] = "x"
    assert tmd.xray == tmd["xray"] == "x"

    tmd["yankee"] = "y"
    assert tmd.yankee == tmd["yankee"] == "y"

    tmd["zulu"] = "z"
    assert tmd.zulu == tmd["zulu"] == "z"

    delattr(tmd, "zulu")  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    tmd["zulu"] = "z"
    assert tmd["zulu"] == "z"

    del tmd["zulu"]  # deletes instance attribute
    assert tmd.zulu == "Z"  # so returns so class attribute default  value

    # create dynamic attribute
    with pytest.raises(AttributeError):
        assert tmd.alpha == None

    with pytest.raises(IndexError):
        assert tmd["alpha"] == None

    tmd["alpha"] = "A"  # add new attribute but without default
    assert tmd.alpha == tmd["alpha"] == "A"

    del tmd["alpha"]  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.alpha == "A"

    with pytest.raises(IndexError):
        assert tmd["alpha"] == "A"

    # another dynamic attribut but delattr instead of del
    with pytest.raises(AttributeError):
        assert tmd.beta == None

    with pytest.raises(IndexError):
        assert tmd["beta"] == None

    tmd["beta"] = "B"  # add new attribute but without default
    assert tmd.beta == tmd["beta"] == "B"

    delattr(tmd, "beta")  # deletes instance attribute and no class default

    with pytest.raises(AttributeError):
        assert tmd.beta == "B"

    with pytest.raises(IndexError):
        assert tmd["beta"] == "B"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmd["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmd, "gamma")

    """End Test"""


def test_mapcodex():
    """Test MapCodex base dataclass frozen"""


    @dataclass(frozen=True)
    class TestMapCodex(MapCodex):
        """

        """
        xray: str = 'X'
        yankee: str = 'Y'
        zulu: str = 'Z'

        def __iter__(self):  # so value in dataclass not key in dataclass
            return iter(astuple(self))

    tmc = TestMapCodex()

    assert 'X' in tmc
    assert 'Y' in tmc
    assert 'Z' in tmc

    assert tmc.xray == tmc["xray"] == 'X'
    assert tmc.yankee == tmc["yankee"] == 'Y'
    assert tmc.zulu == tmc["zulu"] == 'Z'

    with pytest.raises(IndexError):
        tmc["xray"] = "x"

    with pytest.raises(AttributeError):
        tmc.xray = "x"

    with pytest.raises(IndexError):
        del tmc["xray"]

    with pytest.raises(AttributeError):
        delattr(tmc, "xray")

    with pytest.raises(IndexError):
        tmc["alpha"] = "A"

    with pytest.raises(AttributeError):
        tmc.alpha = "A"

    # attempt to delete non-existing
    with pytest.raises(IndexError):
        del tmc["gamma"]

    with pytest.raises(AttributeError):
        delattr(tmc, "gamma")

    """End Test"""

def test_codexes_tags():
    """
    Test supporting module attributes
    """
    assert asdict(counting.CtrDex_1_0) == \
    {
        'ControllerIdxSigs': '-A',
        'WitnessIdxSigs': '-B',
        'NonTransReceiptCouples': '-C',
        'TransReceiptQuadruples': '-D',
        'FirstSeenReplayCouples': '-E',
        'TransIdxSigGroups': '-F',
        'SealSourceCouples': '-G',
        'TransLastIdxSigGroups': '-H',
        'SealSourceTriples': '-I',
        'SadPathSig': '-J',
        'SadPathSigGroup': '-K',
        'PathedMaterialQuadlets': '-L',
        'AttachedMaterialQuadlets': '-V',
        'BigAttachedMaterialQuadlets': '-0V',
        'KERIProtocolStack': '--AAA',
    }

    assert asdict(counting.CtrDex_2_0) == \
    {
        'ControllerIdxSigs': '-A',
        'WitnessIdxSigs': '-B',
        'NonTransReceiptCouples': '-C',
        'TransReceiptQuadruples': '-D',
        'FirstSeenReplayCouples': '-E',
        'TransIdxSigGroups': '-F',
        'SealSourceCouples': '-G',
        'TransLastIdxSigGroups': '-H',
        'SealSourceTriples': '-I',
        'SadPathSig': '-J',
        'SadPathSigGroup': '-K',
        'PathedMaterialQuadlets': '-L',
        'AttachedMaterialQuadlets': '-V',
        'BigAttachedMaterialQuadlets': '-0V',
        'KERIProtocolStack': '--AAA',
    }

    assert counting.Tags_1_0._asdict() == \
    {
        'ControllerIdxSigs': 'ControllerIdxSigs',
        'WitnessIdxSigs': 'WitnessIdxSigs',
        'NonTransReceiptCouples': 'NonTransReceiptCouples',
        'TransReceiptQuadruples': 'TransReceiptQuadruples',
        'FirstSeenReplayCouples': 'FirstSeenReplayCouples',
        'TransIdxSigGroups': 'TransIdxSigGroups',
        'SealSourceCouples': 'SealSourceCouples',
        'TransLastIdxSigGroups': 'TransLastIdxSigGroups',
        'SealSourceTriples': 'SealSourceTriples',
        'SadPathSig': 'SadPathSig',
        'SadPathSigGroup': 'SadPathSigGroup',
        'PathedMaterialQuadlets': 'PathedMaterialQuadlets',
        'AttachedMaterialQuadlets': 'AttachedMaterialQuadlets',
        'BigAttachedMaterialQuadlets': 'BigAttachedMaterialQuadlets',
        'KERIProtocolStack': 'KERIProtocolStack'
    }

    assert counting.Tags_1_0.ControllerIdxSigs == 'ControllerIdxSigs'

    assert counting.Tags_2_0._asdict() == \
    {
        'ControllerIdxSigs': 'ControllerIdxSigs',
        'WitnessIdxSigs': 'WitnessIdxSigs',
        'NonTransReceiptCouples': 'NonTransReceiptCouples',
        'TransReceiptQuadruples': 'TransReceiptQuadruples',
        'FirstSeenReplayCouples': 'FirstSeenReplayCouples',
        'TransIdxSigGroups': 'TransIdxSigGroups',
        'SealSourceCouples': 'SealSourceCouples',
        'TransLastIdxSigGroups': 'TransLastIdxSigGroups',
        'SealSourceTriples': 'SealSourceTriples',
        'SadPathSig': 'SadPathSig',
        'SadPathSigGroup': 'SadPathSigGroup',
        'PathedMaterialQuadlets': 'PathedMaterialQuadlets',
        'AttachedMaterialQuadlets': 'AttachedMaterialQuadlets',
        'BigAttachedMaterialQuadlets': 'BigAttachedMaterialQuadlets',
        'KERIProtocolStack': 'KERIProtocolStack'
    }

    assert counting.Tags_2_0.ControllerIdxSigs == 'ControllerIdxSigs'

    assert counting.AllTags._asdict() == \
    {
        'ControllerIdxSigs': 'ControllerIdxSigs',
        'WitnessIdxSigs': 'WitnessIdxSigs',
        'NonTransReceiptCouples': 'NonTransReceiptCouples',
        'TransReceiptQuadruples': 'TransReceiptQuadruples',
        'FirstSeenReplayCouples': 'FirstSeenReplayCouples',
        'TransIdxSigGroups': 'TransIdxSigGroups',
        'SealSourceCouples': 'SealSourceCouples',
        'TransLastIdxSigGroups': 'TransLastIdxSigGroups',
        'SealSourceTriples': 'SealSourceTriples',
        'SadPathSig': 'SadPathSig',
        'SadPathSigGroup': 'SadPathSigGroup',
        'PathedMaterialQuadlets': 'PathedMaterialQuadlets',
        'AttachedMaterialQuadlets': 'AttachedMaterialQuadlets',
        'BigAttachedMaterialQuadlets': 'BigAttachedMaterialQuadlets',
        'KERIProtocolStack': 'KERIProtocolStack'
    }

    """End Test"""


def test_counter():
    """
    Test Counter class
    """
    assert Counter.Codes == \
    {
        counting.Vrsn_1_0: counting.CtrDex_1_0,
        counting.Vrsn_2_0: counting.CtrDex_2_0,
    }

    assert Counter.Tags == \
    {
        counting.Vrsn_1_0: counting.Tags_1_0,
        counting.Vrsn_2_0: counting.Tags_2_0,
    }


    # first character of code with hard size of code
    assert Counter.Hards == \
    {
        '-A': 2, '-B': 2, '-C': 2, '-D': 2, '-E': 2, '-F': 2, '-G': 2, '-H': 2, '-I': 2,
        '-J': 2, '-K': 2, '-L': 2, '-M': 2, '-N': 2, '-O': 2, '-P': 2, '-Q': 2, '-R': 2,
        '-S': 2, '-T': 2, '-U': 2, '-V': 2, '-W': 2, '-X': 2, '-Y': 2, '-Z': 2,
        '-a': 2, '-b': 2, '-c': 2, '-d': 2, '-e': 2, '-f': 2, '-g': 2, '-h': 2, '-i': 2,
        '-j': 2, '-k': 2, '-l': 2, '-m': 2, '-n': 2, '-o': 2, '-p': 2, '-q': 2, '-r': 2,
        '-s': 2, '-t': 2, '-u': 2, '-v': 2, '-w': 2, '-x': 2, '-y': 2, '-z': 2,
        '-0': 3, '--': 5,
    }

    # Codes table with sizes of code (hard) and full primitive material
    assert Counter.Sizes == \
    {
        counting.Vrsn_1_0: \
        {
            '-A': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-B': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-C': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-D': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-E': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-F': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-G': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-H': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-I': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-J': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-K': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-L': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
            '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0)
        },
        counting.Vrsn_2_0: \
        {
            '-A': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-B': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-C': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-D': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-E': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-F': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-G': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-H': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-I': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-J': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-K': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-L': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
            '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0)
        }
    }

    assert Counter.Sizes[counting.Vrsn_1_0]['-A'].hs == 2  # hard size
    assert Counter.Sizes[counting.Vrsn_1_0]['-A'].ss == 2  # soft size
    assert Counter.Sizes[counting.Vrsn_1_0]['-A'].fs == 4  # full size
    assert Counter.Sizes[counting.Vrsn_1_0]['-A'].ls == 0  # lead size

    # verify first hs Sizes matches hs in Codes for same first char
    for vsize in Counter.Sizes.values():
        for ckey, cval in vsize.items():
            assert Counter.Hards[ckey[:2]] == cval.hs

    #  verify all Codes have hs >= 2 and ss > 0 and fs = hs + ss and not fs % 4
    # if hs < 2 or ss <= 0 or fs != cs or cs % 4   cs = hs + ss
    for vsize in Counter.Sizes.values():
        for val in vsize.values():
            assert val.hs >= 2 and val.ss > 0 and val.hs + val.ss == val.fs and not val.fs % 4

    # Bizes maps bytes of sextet of decoded first character of code with hard size of code
    # verify equivalents of items for Sizes and Bizes
    for skey, sval in Counter.Hards.items():
        ckey = codeB64ToB2(skey)
        assert Counter.Bards[ckey] == sval

    # test Counter static methods
    assert Counter.verToB64() == "AAA"

    assert Counter.b64ToVer('AAA') == Versionage(major=0, minor=0)
    assert Counter.b64ToVer('AAA', texted=True) == "0.0"
    assert Counter.b64ToVer('BBC', texted=True) == "1.66"
    assert Counter.b64ToVer('bbc', texted=True) == '27.1756'

    with pytest.raises(ValueError):
        Counter.b64ToVer("!AA")

    with pytest.raises(ValueError):
        Counter.b64ToVer("AA#")

    assert Counter.b64ToVer(Counter.verToB64(text='1.1'), texted=True) == "1.1"
    assert Counter.verToB64(text=Counter.b64ToVer('BAB', texted=True)) == "BAB"
    assert Counter.b64ToVer(Counter.verToB64(text='12.2345'), texted=True) == '12.2345'
    assert Counter.verToB64(text='12.2345') == 'Mkp'
    assert Counter.verToB64(text=Counter.b64ToVer('Mkp', texted=True)) == 'Mkp'

    assert Counter.verToB64(counting.Vrsn_1_0) == "BAA"
    assert Counter.verToB64(counting.Vrsn_2_0) == "CAA"

    assert Counter.verToB64(text="1.2") == "BAC"

    assert Counter.verToB64(major=1) == "BAA"
    assert Counter.verToB64(minor=1) == "AAB"
    assert Counter.verToB64(major=3, minor=4) == "DAE"

    # test defaults for missing parts in string version
    assert Counter.verToB64(text="1.1") == "BAB"
    assert Counter.verToB64(text="1.1.") == "BAB"  # ignores extra parts
    assert Counter.verToB64(text="1.1.0") == "BAB"  # ignores extra parts
    assert Counter.verToB64(text="1.") == "BAA"
    assert Counter.verToB64(text="1") == "BAA"
    assert Counter.verToB64(text="1.2") == "BAC"
    assert Counter.verToB64(text=".") == "AAA"
    assert Counter.verToB64(text="1.3") == "BAD"
    assert Counter.verToB64(text="4", major=1, minor=2) == "EAC"

    with pytest.raises(ValueError):
        Counter.verToB64(text="64.0")
    with pytest.raises(ValueError):
        Counter.verToB64(text="63.4096")
    with pytest.raises(ValueError):
        Counter.verToB64(text="-1.0")
    with pytest.raises(ValueError):
        Counter.verToB64(text="0.-1")
    with pytest.raises(ValueError):
        Counter.verToB64(major=64)
    with pytest.raises(ValueError):
        Counter.verToB64(minor=4096)
    with pytest.raises(ValueError):
        Counter.verToB64(major=-1)
    with pytest.raises(ValueError):
        Counter.verToB64(minor=-1)






    """ Done Test """

def test_counter_v1():
    """
    test Counter instances for verision 1.0 code tables
    """
    # test Counter instances
    with pytest.raises(kering.EmptyMaterialError):
        counter = Counter()

    # create code manually
    count = 1
    qsc = counting.CtrDex_1_0.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # version 1_0 tests  default version is Version
    assert Version == Vrsn_1_0
    CtrDex = Counter.Codes[Version]  # set CtrDex to Vrsn_1_0

    counter = Counter(tag="ControllerIdxSigs", count=count)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(tag=AllTags.ControllerIdxSigs, count=count)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test tag takes precedence
    counter = Counter(tag=AllTags.ControllerIdxSigs,
                      code=CtrDex.WitnessIdxSigs,
                      count=count)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.ControllerIdxSigs)  # default count = 1
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64)
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb64=shortqsc64)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb2=shortqscb2)

    # test with non-zero count=5
    count = 5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachedMaterialQuadlets, count=count)
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # Test ._bexfil
    counter = Counter(qb64=qsc)  #
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2

    # Test ._binfil
    test = counter._binfil()
    assert test == qb2

    # Test with strip
    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # strip ignored if qb64
    counter = Counter(qb64=qsc, strip=True)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray(qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == counter.sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == counter.sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True)

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    # test protocol genus with CESR protocol genus version
    # test with big codes index=1024
    genverint = 0
    genver = intToB64(genverint, l=3)
    assert genver == 'AAA'
    assert genverint == b64ToInt(genver)
    qsc = CtrDex.KERIProtocolStack + genver
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIProtocolStack, count=genverint)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.KERIProtocolStack, countB64=genver)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    """End Test"""

def test_counter_v2():
    """
    test Counter instances for verision 2.0 code tables
    """
    # test Counter instances
    with pytest.raises(kering.EmptyMaterialError):
        counter = Counter()

    # create code manually
    count = 1
    qsc = counting.CtrDex_1_0.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)
    # version 2_0 tests  default version is Version
    #assert Version == Vrsn_2_0

    CtrDex = Counter.Codes[Vrsn_2_0]  # set CtrDex to Vrsn_2_0

    # default count = 1
    counter = Counter(code=CtrDex.ControllerIdxSigs, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64, version=Vrsn_2_0)
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb64=shortqsc64, version=Vrsn_2_0)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2, version=Vrsn_2_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb2=shortqscb2, version=Vrsn_2_0)

    # test with non-zero count=5
    count = 5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(tag="ControllerIdxSigs", count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(tag=AllTags.ControllerIdxSigs, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test tag takes precedence
    counter = Counter(tag=AllTags.ControllerIdxSigs,
                      code=CtrDex.WitnessIdxSigs,
                      count=count,
                      version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachedMaterialQuadlets, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # Test ._bexfil
    counter = Counter(qb64=qsc, version=Vrsn_2_0)
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2

    # Test ._binfil
    test = counter._binfil()
    assert test == qb2

    # Test with strip
    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # strip ignored if qb64
    counter = Counter(qb64=qsc, strip=True, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray(qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == counter.sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == counter.sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachedMaterialQuadlets + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigAttachedMaterialQuadlets
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert not ims

    # test protocol genus with CESR version
    # test with big codes index=1024
    genverint = 0
    genver = intToB64(genverint, l=3)
    assert genver == 'AAA'
    assert genverint == b64ToInt(genver)
    qsc = CtrDex.KERIProtocolStack + genver
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIProtocolStack, count=genverint, version=Vrsn_2_0)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    counter = Counter(code=CtrDex.KERIProtocolStack, countB64=genver, version=Vrsn_2_0)
    assert counter.code == CtrDex.KERIProtocolStack
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2

    """End Test"""


if __name__ == "__main__":
    test_mapdom()
    test_mapcodex()
    test_codexes_tags()
    test_counter()
    test_counter_v1()
    test_counter_v2()


