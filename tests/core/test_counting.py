# -*- coding: utf-8 -*-
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
from keri.core.counting import GenDex, Cizage, Counter, Codens
from keri.core.counting import Versionage, Vrsn_1_0, Vrsn_2_0



def test_genus_codex():
    """
    Test protocol genera in GenDex as instance of GenusCodex

    """

    assert asdict(GenDex) == \
    {
        'KERI_ACDC_SPAC': '--AAA',
        'KERI': '--AAA',
        'ACDC': '--AAA',
        'SPAC': '--AAA'
    }

    assert '--AAA' in GenDex
    assert GenDex.KERI == "--AAA"
    assert GenDex.ACDC == "--AAA"
    assert GenDex.SPAC == "--AAA"
    assert GenDex.KERI_ACDC_SPAC == "--AAA"
    assert GenDex.KERI == GenDex.ACDC

    assert hasattr(GenDex, "KERI")
    assert hasattr(GenDex, "ACDC")
    assert hasattr(GenDex, "SPAC")
    assert hasattr(GenDex, "KERI_ACDC_SPAC")

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
        'SadPathSigGroups': '-J',
        'RootSadPathSigGroups': '-K',
        'PathedMaterialGroup': '-L',
        'BigPathedMaterialGroup': '-0L',
        'AttachmentGroup': '-V',
        'BigAttachmentGroup': '-0V',
        'GenericGroup': '-W',
        'BigGenericGroup': '-0W',
        'ESSRPayloadGroup': '-Z',
        'BigESSRPayloadGroup': '-0Z',
        'KERIACDCGenusVersion': '--AAA'
    }


    assert asdict(counting.CtrDex_2_0) == \
    {
        'GenericGroup': '-A',
        'BigGenericGroup': '-0A',
        'MessageGroup': '-B',
        'BigMessageGroup': '-0B',
        'AttachmentGroup': '-C',
        'BigAttachmentGroup': '-0C',
        'DatagramSegmentGroup': '-D',
        'BigDatagramSegmentGroup': '-0D',
        'ESSRWrapperGroup': '-E',
        'BigESSRWrapperGroup': '-0E',
        'FixedMessageBodyGroup': '-F',
        'BigFixedMessageBodyGroup': '-0F',
        'MapMessageBodyGroup': '-G',
        'BigMapMessageBodyGroup': '-0G',
        'GenericMapGroup': '-H',
        'BigGenericMapGroup': '-0H',
        'GenericListGroup': '-I',
        'BigGenericListGroup': '-0I',
        'ControllerIdxSigs': '-J',
        'BigControllerIdxSigs': '-0J',
        'WitnessIdxSigs': '-K',
        'BigWitnessIdxSigs': '-0K',
        'NonTransReceiptCouples': '-L',
        'BigNonTransReceiptCouples': '-0L',
        'TransReceiptQuadruples': '-M',
        'BigTransReceiptQuadruples': '-0M',
        'FirstSeenReplayCouples': '-N',
        'BigFirstSeenReplayCouples': '-0N',
        'TransIdxSigGroups': '-O',
        'BigTransIdxSigGroups': '-0O',
        'TransLastIdxSigGroups': '-P',
        'BigTransLastIdxSigGroups': '-0P',
        'SealSourceCouples': '-Q',
        'BigSealSourceCouples': '-0Q',
        'SealSourceTriples': '-R',
        'BigSealSourceTriples': '-0R',
        'PathedMaterialGroup': '-S',
        'BigPathedMaterialGroup': '-0S',
        'SadPathSigGroups': '-T',
        'BigSadPathSigGroups': '-0T',
        'RootSadPathSigGroups': '-U',
        'BigRootSadPathSigGroups': '-0U',
        'DigestSealSingles': '-V',
        'BigDigestSealSingles': '-0V',
        'MerkleRootSealSingles': '-W',
        'BigMerkleRootSealSingles': '-0W',
        'BackerRegistrarSealCouples': '-X',
        'BigBackerRegistrarSealCouples': '-0X',
        'SealSourceLastSingles': '-Y',
        'BigSealSourceLastSingles': '-0Y',
        'ESSRPayloadGroup': '-Z',
        'BigESSRPayloadGroup': '-0Z',
        'KERIACDCGenusVersion': '--AAA'
    }

    assert counting.CodeNames == (
        'GenericGroup',
        'BigGenericGroup',
        'MessageGroup',
        'BigMessageGroup',
        'AttachmentGroup',
        'BigAttachmentGroup',
        'DatagramSegmentGroup',
        'BigDatagramSegmentGroup',
        'ESSRWrapperGroup',
        'BigESSRWrapperGroup',
        'FixedMessageBodyGroup',
        'BigFixedMessageBodyGroup',
        'MapMessageBodyGroup',
        'BigMapMessageBodyGroup',
        'GenericMapGroup',
        'BigGenericMapGroup',
        'GenericListGroup',
        'BigGenericListGroup',
        'ControllerIdxSigs',
        'BigControllerIdxSigs',
        'WitnessIdxSigs',
        'BigWitnessIdxSigs',
        'NonTransReceiptCouples',
        'BigNonTransReceiptCouples',
        'TransReceiptQuadruples',
        'BigTransReceiptQuadruples',
        'FirstSeenReplayCouples',
        'BigFirstSeenReplayCouples',
        'TransIdxSigGroups',
        'BigTransIdxSigGroups',
        'TransLastIdxSigGroups',
        'BigTransLastIdxSigGroups',
        'SealSourceCouples',
        'BigSealSourceCouples',
        'SealSourceTriples',
        'BigSealSourceTriples',
        'PathedMaterialGroup',
        'BigPathedMaterialGroup',
        'SadPathSigGroups',
        'BigSadPathSigGroups',
        'RootSadPathSigGroups',
        'BigRootSadPathSigGroups',
        'DigestSealSingles',
        'BigDigestSealSingles',
        'MerkleRootSealSingles',
        'BigMerkleRootSealSingles',
        'BackerRegistrarSealCouples',
        'BigBackerRegistrarSealCouples',
        'SealSourceLastSingles',
        'BigSealSourceLastSingles',
        'ESSRPayloadGroup',
        'BigESSRPayloadGroup',
        'KERIACDCGenusVersion'
    )
    assert 'ControllerIdxSigs' in counting.CodeNames

    assert counting.Codens == counting.Codenage(
        GenericGroup='GenericGroup',
        BigGenericGroup='BigGenericGroup',
        MessageGroup='MessageGroup',
        BigMessageGroup='BigMessageGroup',
        AttachmentGroup='AttachmentGroup',
        BigAttachmentGroup='BigAttachmentGroup',
        DatagramSegmentGroup='DatagramSegmentGroup',
        BigDatagramSegmentGroup='BigDatagramSegmentGroup',
        ESSRWrapperGroup='ESSRWrapperGroup',
        BigESSRWrapperGroup='BigESSRWrapperGroup',
        FixedMessageBodyGroup='FixedMessageBodyGroup',
        BigFixedMessageBodyGroup='BigFixedMessageBodyGroup',
        MapMessageBodyGroup='MapMessageBodyGroup',
        BigMapMessageBodyGroup='BigMapMessageBodyGroup',
        GenericMapGroup='GenericMapGroup',
        BigGenericMapGroup='BigGenericMapGroup',
        GenericListGroup='GenericListGroup',
        BigGenericListGroup='BigGenericListGroup',
        ControllerIdxSigs='ControllerIdxSigs',
        BigControllerIdxSigs='BigControllerIdxSigs',
        WitnessIdxSigs='WitnessIdxSigs',
        BigWitnessIdxSigs='BigWitnessIdxSigs',
        NonTransReceiptCouples='NonTransReceiptCouples',
        BigNonTransReceiptCouples='BigNonTransReceiptCouples',
        TransReceiptQuadruples='TransReceiptQuadruples',
        BigTransReceiptQuadruples='BigTransReceiptQuadruples',
        FirstSeenReplayCouples='FirstSeenReplayCouples',
        BigFirstSeenReplayCouples='BigFirstSeenReplayCouples',
        TransIdxSigGroups='TransIdxSigGroups',
        BigTransIdxSigGroups='BigTransIdxSigGroups',
        TransLastIdxSigGroups='TransLastIdxSigGroups',
        BigTransLastIdxSigGroups='BigTransLastIdxSigGroups',
        SealSourceCouples='SealSourceCouples',
        BigSealSourceCouples='BigSealSourceCouples',
        SealSourceTriples='SealSourceTriples',
        BigSealSourceTriples='BigSealSourceTriples',
        PathedMaterialGroup='PathedMaterialGroup',
        BigPathedMaterialGroup='BigPathedMaterialGroup',
        SadPathSigGroups='SadPathSigGroups',
        BigSadPathSigGroups='BigSadPathSigGroups',
        RootSadPathSigGroups='RootSadPathSigGroups',
        BigRootSadPathSigGroups='BigRootSadPathSigGroups',
        DigestSealSingles='DigestSealSingles',
        BigDigestSealSingles='BigDigestSealSingles',
        MerkleRootSealSingles='MerkleRootSealSingles',
        BigMerkleRootSealSingles='BigMerkleRootSealSingles',
        BackerRegistrarSealCouples='BackerRegistrarSealCouples',
        BigBackerRegistrarSealCouples='BigBackerRegistrarSealCouples',
        SealSourceLastSingles='SealSourceLastSingles',
        BigSealSourceLastSingles='BigSealSourceLastSingles',
        ESSRPayloadGroup='ESSRPayloadGroup',
        BigESSRPayloadGroup='BigESSRPayloadGroup',
        KERIACDCGenusVersion='KERIACDCGenusVersion'
    )

    assert counting.Codens.ControllerIdxSigs == 'ControllerIdxSigs'



    assert asdict(counting.SealDex_2_0) == \
    {
        'SealSourceCouples': '-Q',
        'BigSealSourceCouples': '-0Q',
        'SealSourceTriples': '-R',
        'BigSealSourceTriples': '-0R',
        'DigestSealSingles': '-V',
        'BigDigestSealSingles': '-0V',
        'MerkleRootSealSingles': '-W',
        'BigMerkleRootSealSingles': '-0W',
        'BackerRegistrarSealCouples': '-X',
        'BigBackerRegistrarSealCouples': '-0X',
        'SealSourceLastSingles': '-Y',
        'BigSealSourceLastSingles': '-0Y',
    }



    """End Test"""


def test_counter_class():
    """
    Test Counter class variables
    """
    # test class attributes

    assert Counter.Codes == \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: counting.CtrDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: counting.CtrDex_2_0,
        },
    }

    assert Counter.Names == \
        {1:
            {0:
                {
                    '-A': 'ControllerIdxSigs',
                    '-B': 'WitnessIdxSigs',
                    '-C': 'NonTransReceiptCouples',
                    '-D': 'TransReceiptQuadruples',
                    '-E': 'FirstSeenReplayCouples',
                    '-F': 'TransIdxSigGroups',
                    '-G': 'SealSourceCouples',
                    '-H': 'TransLastIdxSigGroups',
                    '-I': 'SealSourceTriples',
                    '-J': 'SadPathSigGroups',
                    '-K': 'RootSadPathSigGroups',
                    '-L': 'PathedMaterialGroup',
                    '-0L': 'BigPathedMaterialGroup',
                    '-V': 'AttachmentGroup',
                    '-0V': 'BigAttachmentGroup',
                    '-W': 'GenericGroup',
                    '-0W': 'BigGenericGroup',
                    '-Z': 'ESSRPayloadGroup',
                    '-0Z': 'BigESSRPayloadGroup',
                    '--AAA': 'KERIACDCGenusVersion',
                }
            },
        2:
            {0:
                {
                    '-A': 'GenericGroup',
                    '-0A': 'BigGenericGroup',
                    '-B': 'MessageGroup',
                    '-0B': 'BigMessageGroup',
                    '-C': 'AttachmentGroup',
                    '-0C': 'BigAttachmentGroup',
                    '-D': 'DatagramSegmentGroup',
                    '-0D': 'BigDatagramSegmentGroup',
                    '-E': 'ESSRWrapperGroup',
                    '-0E': 'BigESSRWrapperGroup',
                    '-F': 'FixedMessageBodyGroup',
                    '-0F': 'BigFixedMessageBodyGroup',
                    '-G': 'MapMessageBodyGroup',
                    '-0G': 'BigMapMessageBodyGroup',
                    '-H': 'GenericMapGroup',
                    '-0H': 'BigGenericMapGroup',
                    '-I': 'GenericListGroup',
                    '-0I': 'BigGenericListGroup',
                    '-J': 'ControllerIdxSigs',
                    '-0J': 'BigControllerIdxSigs',
                    '-K': 'WitnessIdxSigs',
                    '-0K': 'BigWitnessIdxSigs',
                    '-L': 'NonTransReceiptCouples',
                    '-0L': 'BigNonTransReceiptCouples',
                    '-M': 'TransReceiptQuadruples',
                    '-0M': 'BigTransReceiptQuadruples',
                    '-N': 'FirstSeenReplayCouples',
                    '-0N': 'BigFirstSeenReplayCouples',
                    '-O': 'TransIdxSigGroups',
                    '-0O': 'BigTransIdxSigGroups',
                    '-P': 'TransLastIdxSigGroups',
                    '-0P': 'BigTransLastIdxSigGroups',
                    '-Q': 'SealSourceCouples',
                    '-0Q': 'BigSealSourceCouples',
                    '-R': 'SealSourceTriples',
                    '-0R': 'BigSealSourceTriples',
                    '-S': 'PathedMaterialGroup',
                    '-0S': 'BigPathedMaterialGroup',
                    '-T': 'SadPathSigGroups',
                    '-0T': 'BigSadPathSigGroups',
                    '-U': 'RootSadPathSigGroups',
                    '-0U': 'BigRootSadPathSigGroups',
                    '-V': 'DigestSealSingles',
                    '-0V': 'BigDigestSealSingles',
                    '-W': 'MerkleRootSealSingles',
                    '-0W': 'BigMerkleRootSealSingles',
                    '-X': 'BackerRegistrarSealCouples',
                    '-0X': 'BigBackerRegistrarSealCouples',
                    '-Y': 'SealSourceLastSingles',
                    '-0Y': 'BigSealSourceLastSingles',
                    '-Z': 'ESSRPayloadGroup',
                    '-0Z': 'BigESSRPayloadGroup',
                    '--AAA': 'KERIACDCGenusVersion'
                }
            }
        }


    # Codes table with sizes of code (hard) and full primitive material
    assert Counter.Sizes == \
        {
            1:
            {
                0:
                {
                    '-A': Cizage(hs=2, ss=2, fs=4),
                    '-B': Cizage(hs=2, ss=2, fs=4),
                    '-C': Cizage(hs=2, ss=2, fs=4),
                    '-D': Cizage(hs=2, ss=2, fs=4),
                    '-E': Cizage(hs=2, ss=2, fs=4),
                    '-F': Cizage(hs=2, ss=2, fs=4),
                    '-G': Cizage(hs=2, ss=2, fs=4),
                    '-H': Cizage(hs=2, ss=2, fs=4),
                    '-I': Cizage(hs=2, ss=2, fs=4),
                    '-J': Cizage(hs=2, ss=2, fs=4),
                    '-K': Cizage(hs=2, ss=2, fs=4),
                    '-L': Cizage(hs=2, ss=2, fs=4),
                    '-0L': Cizage(hs=3, ss=5, fs=8),
                    '-V': Cizage(hs=2, ss=2, fs=4),
                    '-0V': Cizage(hs=3, ss=5, fs=8),
                    '-W': Cizage(hs=2, ss=2, fs=4),
                    '-0W': Cizage(hs=3, ss=5, fs=8),
                    '-Z': Cizage(hs=2, ss=2, fs=4),
                    '-0Z': Cizage(hs=3, ss=5, fs=8),
                    '--AAA': Cizage(hs=5, ss=3, fs=8)
                }
            },
            2:
            {
                0:
                {
                    '-A': Cizage(hs=2, ss=2, fs=4),
                    '-0A': Cizage(hs=3, ss=5, fs=8),
                    '-B': Cizage(hs=2, ss=2, fs=4),
                    '-0B': Cizage(hs=3, ss=5, fs=8),
                    '-C': Cizage(hs=2, ss=2, fs=4),
                    '-0C': Cizage(hs=3, ss=5, fs=8),
                    '-D': Cizage(hs=2, ss=2, fs=4),
                    '-0D': Cizage(hs=3, ss=5, fs=8),
                    '-E': Cizage(hs=2, ss=2, fs=4),
                    '-0E': Cizage(hs=3, ss=5, fs=8),
                    '-F': Cizage(hs=2, ss=2, fs=4),
                    '-0F': Cizage(hs=3, ss=5, fs=8),
                    '-G': Cizage(hs=2, ss=2, fs=4),
                    '-0G': Cizage(hs=3, ss=5, fs=8),
                    '-H': Cizage(hs=2, ss=2, fs=4),
                    '-0H': Cizage(hs=3, ss=5, fs=8),
                    '-I': Cizage(hs=2, ss=2, fs=4),
                    '-0I': Cizage(hs=3, ss=5, fs=8),
                    '-J': Cizage(hs=2, ss=2, fs=4),
                    '-0J': Cizage(hs=3, ss=5, fs=8),
                    '-K': Cizage(hs=2, ss=2, fs=4),
                    '-0K': Cizage(hs=3, ss=5, fs=8),
                    '-L': Cizage(hs=2, ss=2, fs=4),
                    '-0L': Cizage(hs=3, ss=5, fs=8),
                    '-M': Cizage(hs=2, ss=2, fs=4),
                    '-0M': Cizage(hs=3, ss=5, fs=8),
                    '-N': Cizage(hs=2, ss=2, fs=4),
                    '-0N': Cizage(hs=3, ss=5, fs=8),
                    '-O': Cizage(hs=2, ss=2, fs=4),
                    '-0O': Cizage(hs=3, ss=5, fs=8),
                    '-P': Cizage(hs=2, ss=2, fs=4),
                    '-0P': Cizage(hs=3, ss=5, fs=8),
                    '-Q': Cizage(hs=2, ss=2, fs=4),
                    '-0Q': Cizage(hs=3, ss=5, fs=8),
                    '-R': Cizage(hs=2, ss=2, fs=4),
                    '-0R': Cizage(hs=3, ss=5, fs=8),
                    '-S': Cizage(hs=2, ss=2, fs=4),
                    '-0S': Cizage(hs=3, ss=5, fs=8),
                    '-T': Cizage(hs=2, ss=2, fs=4),
                    '-0T': Cizage(hs=3, ss=5, fs=8),
                    '-U': Cizage(hs=2, ss=2, fs=4),
                    '-0U': Cizage(hs=3, ss=5, fs=8),
                    '-V': Cizage(hs=2, ss=2, fs=4),
                    '-0V': Cizage(hs=3, ss=5, fs=8),
                    '-W': Cizage(hs=2, ss=2, fs=4),
                    '-0W': Cizage(hs=3, ss=5, fs=8),
                    '-X': Cizage(hs=2, ss=2, fs=4),
                    '-0X': Cizage(hs=3, ss=5, fs=8),
                    '-Y': Cizage(hs=2, ss=2, fs=4),
                    '-0Y': Cizage(hs=3, ss=5, fs=8),
                    '-Z': Cizage(hs=2, ss=2, fs=4),
                    '-0Z': Cizage(hs=3, ss=5, fs=8),
                    '--AAA': Cizage(hs=5, ss=3, fs=8)
                }
            }
        }

    # Ensure there is an entry in Sizes for each entry in Codes
    assert Counter.Codes.keys() == Counter.Sizes.keys()
    for majorc, majors in zip(Counter.Codes.items(), Counter.Sizes.items(), strict=True):
        assert majorc[0] == majors[0]  # major version, keys match
        for minorc, minors in zip(majorc[1].items(), majors[1].items(), strict=True):
            assert minorc[0] == minors[0]  # minor version keys match
            for code, size in zip(asdict(minorc[1]).items(), minors[1].items(), strict=True):
                code[0] == size[0]  # code and size keys match


    assert Counter.Sizes[Vrsn_1_0.major][Vrsn_1_0.minor]['-A'].hs == 2  # hard size
    assert Counter.Sizes[Vrsn_1_0.major][Vrsn_1_0.minor]['-A'].ss == 2 # soft size
    assert Counter.Sizes[Vrsn_1_0.major][Vrsn_1_0.minor]['-A'].fs == 4  # full size

    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['-0A'].hs == 3  # hard size
    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['-0A'].ss == 5  # soft size
    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['-0A'].fs == 8  # full size

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



    # verify first hs Sizes matches hs in Codes for same first char
    for vmajor in Counter.Sizes.values():
        for vminor in vmajor.values():
            for key, val in vminor.items(): # size table items
                assert Counter.Hards[key[:2]] == val.hs

    #  verify all Codes have hs >= 2 and ss > 0 and fs = hs + ss and not fs % 4
    for vmajor in Counter.Sizes.values():
        for vminor in vmajor.values():
            for val in vminor.values():  # size table values
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
    # version 1_0 tests
    CtrDex = Counter.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]  # set CtrDex to Vrsn_1_0

    # test Counter instances
    with pytest.raises(kering.EmptyMaterialError):
        counter = Counter(gvrsn=Vrsn_1_0)

    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(Codens.ControllerIdxSigs, count=count, gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs == counter.hard
    assert counter.name == "ControllerIdxSigs"

    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.fullSize == 4
    assert counter.soft =='AB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64
    assert counter.codes == counting.CtrDex_1_0
    #assert counter.tags == counting.Tags_1_0
    assert counter.sizes == Counter.Sizes[1][0]

    counter = Counter(Codens.ControllerIdxSigs, count=count, gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test keyword buth with code name
    counter = Counter(code=Codens.ControllerIdxSigs,
                      count=count,
                      gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(code=CtrDex.ControllerIdxSigs, gvrsn=Vrsn_1_0)  # default count = 1
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64, gvrsn=Vrsn_1_0)
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb64=shortqsc64, gvrsn=Vrsn_1_0)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2, gvrsn=Vrsn_1_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb2=shortqscb2, gvrsn=Vrsn_1_0)

    # test with non-zero count=5
    count = 5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count, gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test with big codes index=100024000
    count = 100024000
    qsc = CtrDex.BigAttachmentGroup + intToB64(count, l=5)
    assert qsc == '-0VF9j7A'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachmentGroup, count=count, gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  #
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2
    assert counter.version == Vrsn_1_0

    # Test ._binfil
    test = counter._binfil()
    assert test == qb2

    # test BigPathedMaterialGroup with big codes index=100024000
    count = 100024000
    qsc = CtrDex.BigPathedMaterialGroup + intToB64(count, l=5)
    assert qsc == '-0LF9j7A'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigPathedMaterialGroup, count=count, gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.BigPathedMaterialGroup
    assert counter.name == "BigPathedMaterialGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.BigPathedMaterialGroup
    assert counter.name == "BigPathedMaterialGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.BigPathedMaterialGroup
    assert counter.name == "BigPathedMaterialGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.BigPathedMaterialGroup
    assert counter.name == "BigPathedMaterialGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, gvrsn=Vrsn_1_0)  #
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.name == "BigPathedMaterialGroup"
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2
    assert counter.version == Vrsn_1_0

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
    counter = Counter(qb64=qsc, strip=True, gvrsn=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_1_0)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_1_0)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray(qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_1_0)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == counter.sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_1_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == counter.sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_1_0)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_1_0)

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachmentGroup + intToB64(count, l=5)
    assert qsc == '-0VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.fullSize == 8
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.fullSize == 8
    assert not ims

    # test protocol genus with CESR protocol genus version
    # test with big codes index=1024
    genverint = 0
    genver = intToB64(genverint, l=3)
    assert genver == 'AAA'
    assert genverint == b64ToInt(genver)
    qsc = CtrDex.KERIACDCGenusVersion + genver
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      count=genverint,
                      gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.codes == counting.CtrDex_1_0
    #assert counter.tags == counting.Tags_1_0
    assert counter.sizes == Counter.Sizes[1][0]


    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      countB64=genver,
                      gvrsn=Vrsn_1_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    """End Test"""

def test_counter_v2():
    """
    test Counter instances for verision 2.0 code tables
    """
    # version 2_0 tests  default version is Version
    CtrDex = Counter.Codes[Vrsn_2_0.major][Vrsn_2_0.minor]  # set CtrDex to Vrsn_2_0

    # test Counter instances
    with pytest.raises(kering.EmptyMaterialError):
        counter = Counter()

    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-JAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # default version and default count = 1
    counter = Counter(code=CtrDex.ControllerIdxSigs)
    assert counter.code == CtrDex.ControllerIdxSigs == counter.hard
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.fullSize == 4
    assert counter.soft =='AB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64
    assert counter.codes == counting.CtrDex_2_0
    #assert counter.tags == counting.Tags_2_0
    assert counter.sizes == Counter.Sizes[2][0]



    # default count = 1
    counter = Counter(code=CtrDex.ControllerIdxSigs, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64, gvrsn=Vrsn_2_0)
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb64=shortqsc64, gvrsn=Vrsn_2_0)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2, gvrsn=Vrsn_2_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb2=shortqscb2, gvrsn=Vrsn_2_0)

    # test with non-zero count=5
    count = 5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-JAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(Codens.ControllerIdxSigs, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(Codens.ControllerIdxSigs,
                      count=count,
                      gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test keyword with code name
    counter = Counter(code=Codens.ControllerIdxSigs,
                      count=count,
                      gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, gvrsn=Vrsn_2_0)
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64 == qsc
    assert counter.qb2 == qb2
    assert counter.version == Vrsn_2_0

    # Test ._binfil
    test = counter._binfil()
    assert test == qb2

    # Test with strip
    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-JAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # strip ignored if qb64
    counter = Counter(qb64=qsc, strip=True, gvrsn=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_2_0)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_2_0)
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test with longer ims for qb64b
    extra = b"ABCD"
    ims = bytearray(qscb + b"ABCD")
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_2_0)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == counter.sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_2_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == counter.sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_2_0)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_2_0)

    # test with big codes count=1024
    count = 1024
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '-0AAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigGenericGroup, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test ims with big codes count=1024
    count = 1024
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '-0AAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert not ims

    # test with big codes count=8193
    count = 8193
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '-0AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigGenericGroup, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup == counter.hard
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.fullSize == 8
    assert counter.soft == 'AACAB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64

    counter = Counter(qb64b=qscb, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, gvrsn=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test ims with big codes count=8193
    count = 8193
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '-0AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, gvrsn=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.fullSize == 8
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True, gvrsn=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert not ims

    # test with promotion from small to big codes with count=8193
    count = 8193
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '-0AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.GenericGroup, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup == counter.hard
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.soft =='AACAB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64

    counter = Counter(Codens.GenericGroup, count=count, gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test protocol genus with CESR version
    genverint = 0
    genver = intToB64(genverint, l=3)
    assert genver == 'AAA'
    assert genverint == b64ToInt(genver)
    qsc = CtrDex.KERIACDCGenusVersion + genver
    assert qsc == '--AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      count=genverint,
                      gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.fullSize == 8
    assert counter.codes == counting.CtrDex_2_0
    #assert counter.tags == counting.Tags_2_0
    assert counter.sizes == Counter.Sizes[2][0]

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      countB64=genver,
                      gvrsn=Vrsn_2_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    """End Test"""


if __name__ == "__main__":
    test_genus_codex()
    test_codexes_tags()
    test_counter_class()
    test_counter_v1()
    test_counter_v2()


