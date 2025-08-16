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
from keri.kering import Colds, Protocols

from keri.help import helping
from keri.help.helping import sceil
from keri.help.helping import (intToB64,  b64ToInt, codeB64ToB2, codeB2ToB64,
                            nabSextets)



from keri.core import counting, Texter
from keri.core.counting import (GenDex, Cizage, Counter, Codens,
                                 CtrDex_1_0, CtrDex_2_0, ProGen,
                                Versionage, Vrsn_1_0, Vrsn_2_0)



def test_genus_codex_pro_gen():
    """
    Test protocol genera in GenDex as instance of GenusCodex and shared genus
    code table mapping from Protocols via ProGen

    """

    assert asdict(GenDex) == \
    {
        'KERI': '-_AAA',
        'ACDC': '-_AAB',
        'SPAC': '-_AAC',
        'TSP_': '-_AAD',
    }

    assert '-_AAA' in GenDex
    assert '-_AAB' in GenDex
    assert '-_AAC' in GenDex
    assert '-_AAD' in GenDex

    assert GenDex.KERI == "-_AAA"
    assert GenDex.ACDC == "-_AAB"
    assert GenDex.SPAC == "-_AAC"
    assert GenDex.TSP_ == "-_AAD"


    assert hasattr(GenDex, "KERI")
    assert hasattr(GenDex, "ACDC")
    assert hasattr(GenDex, "SPAC")
    assert hasattr(GenDex, "TSP_")


    assert ProGen == \
    {
        'KERI': 'KERI',
        'ACDC': 'KERI'
    }

    assert GenDex[ProGen[Protocols.keri]] == GenDex.KERI == '-_AAA'
    assert GenDex[ProGen[Protocols.acdc]] == GenDex.KERI == '-_AAA'

    """End Test"""



def test_codexes_tags():
    """
    Test supporting module attributes
    """


    assert  asdict(counting.CtrDex_1_0) == \
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
        'PathedMaterialCouples': '-L',
        'BigPathedMaterialCouples': '--L',
        'GenericGroup': '-T',
        'BigGenericGroup': '--T',
        'BodyWithAttachmentGroup': '-U',
        'BigBodyWithAttachmentGroup': '--U',
        'AttachmentGroup': '-V',
        'BigAttachmentGroup': '--V',
        'NonNativeBodyGroup': '-W',
        'BigNonNativeBodyGroup': '--W',
        'ESSRPayloadGroup': '-Z',
        'BigESSRPayloadGroup': '--Z',
        'KERIACDCGenusVersion': '-_AAA'
    }

    assert  asdict(counting.QTDex_1_0) == \
    {
        'PathedMaterialCouples': '-L',
        'BigPathedMaterialCouples': '--L',
        'GenericGroup': '-T',
        'BigGenericGroup': '--T',
        'BodyWithAttachmentGroup': '-U',
        'BigBodyWithAttachmentGroup': '--U',
        'AttachmentGroup': '-V',
        'BigAttachmentGroup': '--V',
        'NonNativeBodyGroup': '-W',
        'BigNonNativeBodyGroup': '--W',
        'ESSRPayloadGroup': '-Z',
        'BigESSRPayloadGroup': '--Z',
    }

    assert  asdict(counting.SUDex_1_0) == \
    {
        'GenericGroup': '-T',
        'BigGenericGroup': '--T',
        'BodyWithAttachmentGroup': '-U',
        'BigBodyWithAttachmentGroup': '--U',
        'AttachmentGroup': '-V',
        'BigAttachmentGroup': '--V',
    }

    assert  asdict(counting.MUDex_1_0) == \
    {
        'NonNativeBodyGroup': '-W',
        'BigNonNativeBodyGroup': '--W',
    }


    assert asdict(counting.CtrDex_2_0) == \
    {
        'GenericGroup': '-A',
        'BigGenericGroup': '--A',
        'BodyWithAttachmentGroup': '-B',
        'BigBodyWithAttachmentGroup': '--B',
        'AttachmentGroup': '-C',
        'BigAttachmentGroup': '--C',
        'DatagramSegmentGroup': '-D',
        'BigDatagramSegmentGroup': '--D',
        'ESSRWrapperGroup': '-E',
        'BigESSRWrapperGroup': '--E',
        'FixBodyGroup': '-F',
        'BigFixBodyGroup': '--F',
        'MapBodyGroup': '-G',
        'BigMapBodyGroup': '--G',
        'NonNativeBodyGroup': '-H',
        'BigNonNativeBodyGroup': '--H',
        'GenericMapGroup': '-I',
        'BigGenericMapGroup': '--I',
        'GenericListGroup': '-J',
        'BigGenericListGroup': '--J',
        'ControllerIdxSigs': '-K',
        'BigControllerIdxSigs': '--K',
        'WitnessIdxSigs': '-L',
        'BigWitnessIdxSigs': '--L',
        'NonTransReceiptCouples': '-M',
        'BigNonTransReceiptCouples': '--M',
        'TransReceiptQuadruples': '-N',
        'BigTransReceiptQuadruples': '--N',
        'FirstSeenReplayCouples': '-O',
        'BigFirstSeenReplayCouples': '--O',
        'PathedMaterialCouples': '-P',
        'BigPathedMaterialCouples': '--P',
        'DigestSealSingles': '-Q',
        'BigDigestSealSingles': '--Q',
        'MerkleRootSealSingles': '-R',
        'BigMerkleRootSealSingles': '--R',
        'SealSourceCouples': '-S',
        'BigSealSourceCouples': '--S',
        'SealSourceTriples': '-T',
        'BigSealSourceTriples': '--T',
        'SealSourceLastSingles': '-U',
        'BigSealSourceLastSingles': '--U',
        'BackerRegistrarSealCouples': '-V',
        'BigBackerRegistrarSealCouples': '--V',
        'TypedDigestSealCouples': '-W',
        'BigTypedDigestSealCouples': '--W',
        'TransIdxSigGroups': '-X',
        'BigTransIdxSigGroups': '--X',
        'TransLastIdxSigGroups': '-Y',
        'BigTransLastIdxSigGroups': '--Y',
        'ESSRPayloadGroup': '-Z',
        'BigESSRPayloadGroup': '--Z',
        'BlindedStateQuadruples': '-a',
        'BigBlindedStateQuadruples': '--a',
        'BoundStateSextuples': '-b',
        'BigBoundStateSextuples': '--b',
        'TypedMediaQuadruples': '-c',
        'BigTypedMediaQuadruples': '--c',
        'KERIACDCGenusVersion': '-_AAA'
    }


    assert asdict(counting.UniDex_2_0) == \
    {
        'GenericGroup': '-A',
        'BigGenericGroup': '--A',
        'BodyWithAttachmentGroup': '-B',
        'BigBodyWithAttachmentGroup': '--B',
        'AttachmentGroup': '-C',
        'BigAttachmentGroup': '--C',
        'DatagramSegmentGroup': '-D',
        'BigDatagramSegmentGroup': '--D',
        'ESSRWrapperGroup': '-E',
        'BigESSRWrapperGroup': '--E',
        'FixBodyGroup': '-F',
        'BigFixBodyGroup': '--F',
        'MapBodyGroup': '-G',
        'BigMapBodyGroup': '--G',
        'NonNativeBodyGroup': '-H',
        'BigNonNativeBodyGroup': '--H',
        'GenericMapGroup': '-I',
        'BigGenericMapGroup': '--I',
        'GenericListGroup': '-J',
        'BigGenericListGroup': '--J',
        'KERIACDCGenusVersion': '-_AAA'
    }

    assert asdict(counting.SUDex_2_0) == \
    {
        'GenericGroup': '-A',
        'BigGenericGroup': '--A',
        'BodyWithAttachmentGroup': '-B',
        'BigBodyWithAttachmentGroup': '--B',
        'AttachmentGroup': '-C',
        'BigAttachmentGroup': '--C',
    }

    assert asdict(counting.MUDex_2_0) == \
    {
        'DatagramSegmentGroup': '-D',
        'BigDatagramSegmentGroup': '--D',
        'ESSRWrapperGroup': '-E',
        'BigESSRWrapperGroup': '--E',
        'FixBodyGroup': '-F',
        'BigFixBodyGroup': '--F',
        'MapBodyGroup': '-G',
        'BigMapBodyGroup': '--G',
        'NonNativeBodyGroup': '-H',
        'BigNonNativeBodyGroup': '--H',
    }


    assert counting.CodeNames == \
    (
        'GenericGroup',
        'BigGenericGroup',
        'BodyWithAttachmentGroup',
        'BigBodyWithAttachmentGroup',
        'AttachmentGroup',
        'BigAttachmentGroup',
        'DatagramSegmentGroup',
        'BigDatagramSegmentGroup',
        'ESSRWrapperGroup',
        'BigESSRWrapperGroup',
        'FixBodyGroup',
        'BigFixBodyGroup',
        'MapBodyGroup',
        'BigMapBodyGroup',
        'NonNativeBodyGroup',
        'BigNonNativeBodyGroup',
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
        'PathedMaterialCouples',
        'BigPathedMaterialCouples',
        'DigestSealSingles',
        'BigDigestSealSingles',
        'MerkleRootSealSingles',
        'BigMerkleRootSealSingles',
        'SealSourceCouples',
        'BigSealSourceCouples',
        'SealSourceTriples',
        'BigSealSourceTriples',
        'SealSourceLastSingles',
        'BigSealSourceLastSingles',
        'BackerRegistrarSealCouples',
        'BigBackerRegistrarSealCouples',
        'TypedDigestSealCouples',
        'BigTypedDigestSealCouples',
        'TransIdxSigGroups',
        'BigTransIdxSigGroups',
        'TransLastIdxSigGroups',
        'BigTransLastIdxSigGroups',
        'ESSRPayloadGroup',
        'BigESSRPayloadGroup',
        'BlindedStateQuadruples',
        'BigBlindedStateQuadruples',
        'BoundStateSextuples',
        'BigBoundStateSextuples',
        'TypedMediaQuadruples',
        'BigTypedMediaQuadruples',
        'KERIACDCGenusVersion',
    )

    assert 'ControllerIdxSigs' in counting.CodeNames

    assert counting.Codens == counting.Codenage(
        GenericGroup='GenericGroup',
        BigGenericGroup='BigGenericGroup',
        BodyWithAttachmentGroup='BodyWithAttachmentGroup',
        BigBodyWithAttachmentGroup='BigBodyWithAttachmentGroup',
        AttachmentGroup='AttachmentGroup',
        BigAttachmentGroup='BigAttachmentGroup',
        DatagramSegmentGroup='DatagramSegmentGroup',
        BigDatagramSegmentGroup='BigDatagramSegmentGroup',
        ESSRWrapperGroup='ESSRWrapperGroup',
        BigESSRWrapperGroup='BigESSRWrapperGroup',
        FixBodyGroup='FixBodyGroup',
        BigFixBodyGroup='BigFixBodyGroup',
        MapBodyGroup='MapBodyGroup',
        BigMapBodyGroup='BigMapBodyGroup',
        NonNativeBodyGroup='NonNativeBodyGroup',
        BigNonNativeBodyGroup='BigNonNativeBodyGroup',
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
        DigestSealSingles='DigestSealSingles',
        BigDigestSealSingles='BigDigestSealSingles',
        PathedMaterialCouples='PathedMaterialCouples',
        BigPathedMaterialCouples='BigPathedMaterialCouples',
        MerkleRootSealSingles='MerkleRootSealSingles',
        BigMerkleRootSealSingles='BigMerkleRootSealSingles',
        SealSourceCouples='SealSourceCouples',
        BigSealSourceCouples='BigSealSourceCouples',
        SealSourceTriples='SealSourceTriples',
        BigSealSourceTriples='BigSealSourceTriples',
        SealSourceLastSingles='SealSourceLastSingles',
        BigSealSourceLastSingles='BigSealSourceLastSingles',
        BackerRegistrarSealCouples='BackerRegistrarSealCouples',
        BigBackerRegistrarSealCouples='BigBackerRegistrarSealCouples',
        TypedDigestSealCouples='TypedDigestSealCouples',
        BigTypedDigestSealCouples='BigTypedDigestSealCouples',
        TransIdxSigGroups='TransIdxSigGroups',
        BigTransIdxSigGroups='BigTransIdxSigGroups',
        TransLastIdxSigGroups='TransLastIdxSigGroups',
        BigTransLastIdxSigGroups='BigTransLastIdxSigGroups',
        ESSRPayloadGroup='ESSRPayloadGroup',
        BigESSRPayloadGroup='BigESSRPayloadGroup',
        BlindedStateQuadruples='BlindedStateQuadruples',
        BigBlindedStateQuadruples='BigBlindedStateQuadruples',
        KERIACDCGenusVersion='KERIACDCGenusVersion'
    )


    assert counting.Codens.ControllerIdxSigs == 'ControllerIdxSigs'



    assert asdict(counting.SealDex_2_0) == \
    {
        'DigestSealSingles': '-Q',
        'BigDigestSealSingles': '--Q',
        'MerkleRootSealSingles': '-R',
        'BigMerkleRootSealSingles': '--R',
        'SealSourceCouples': '-S',
        'BigSealSourceCouples': '--S',
        'SealSourceTriples': '-T',
        'BigSealSourceTriples': '--T',
        'SealSourceLastSingles': '-U',
        'BigSealSourceLastSingles': '--U',
        'BackerRegistrarSealCouples': '-V',
        'BigBackerRegistrarSealCouples': '--V',
        'TypedDigestSealCouples': '-W',
        'BigTypedDigestSealCouples': '--W',
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

    assert Counter.SUCodes == \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: counting.SUDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: counting.SUDex_2_0,
        },
    }

    assert Counter.MUCodes == \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: counting.MUDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: counting.MUDex_2_0,
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
                    '-L': 'PathedMaterialCouples',
                    '--L': 'BigPathedMaterialCouples',
                    '-T': 'GenericGroup',
                    '--T': 'BigGenericGroup',
                    '-U': 'BodyWithAttachmentGroup',
                    '--U': 'BigBodyWithAttachmentGroup',
                    '-V': 'AttachmentGroup',
                    '--V': 'BigAttachmentGroup',
                    '-W': 'NonNativeBodyGroup',
                    '--W': 'BigNonNativeBodyGroup',
                    '-Z': 'ESSRPayloadGroup',
                    '--Z': 'BigESSRPayloadGroup',
                    '-_AAA': 'KERIACDCGenusVersion',
                }
            },
        2:
            {0:
                {
                    '-A': 'GenericGroup',
                    '--A': 'BigGenericGroup',
                    '-B': 'BodyWithAttachmentGroup',
                    '--B': 'BigBodyWithAttachmentGroup',
                    '-C': 'AttachmentGroup',
                    '--C': 'BigAttachmentGroup',
                    '-D': 'DatagramSegmentGroup',
                    '--D': 'BigDatagramSegmentGroup',
                    '-E': 'ESSRWrapperGroup',
                    '--E': 'BigESSRWrapperGroup',
                    '-F': 'FixBodyGroup',
                    '--F': 'BigFixBodyGroup',
                    '-G': 'MapBodyGroup',
                    '--G': 'BigMapBodyGroup',
                    '-H': 'NonNativeBodyGroup',
                    '--H': 'BigNonNativeBodyGroup',
                    '-I': 'GenericMapGroup',
                    '--I': 'BigGenericMapGroup',
                    '-J': 'GenericListGroup',
                    '--J': 'BigGenericListGroup',
                    '-K': 'ControllerIdxSigs',
                    '--K': 'BigControllerIdxSigs',
                    '-L': 'WitnessIdxSigs',
                    '--L': 'BigWitnessIdxSigs',
                    '-M': 'NonTransReceiptCouples',
                    '--M': 'BigNonTransReceiptCouples',
                    '-N': 'TransReceiptQuadruples',
                    '--N': 'BigTransReceiptQuadruples',
                    '-O': 'FirstSeenReplayCouples',
                    '--O': 'BigFirstSeenReplayCouples',
                    '-P': 'PathedMaterialCouples',
                    '--P': 'BigPathedMaterialCouples',
                    '-Q': 'DigestSealSingles',
                    '--Q': 'BigDigestSealSingles',
                    '-R': 'MerkleRootSealSingles',
                    '--R': 'BigMerkleRootSealSingles',
                    '-S': 'SealSourceCouples',
                    '--S': 'BigSealSourceCouples',
                    '-T': 'SealSourceTriples',
                    '--T': 'BigSealSourceTriples',
                    '-U': 'SealSourceLastSingles',
                    '--U': 'BigSealSourceLastSingles',
                    '-V': 'BackerRegistrarSealCouples',
                    '--V': 'BigBackerRegistrarSealCouples',
                     '-W': 'TypedDigestSealCouples',
                    '--W': 'BigTypedDigestSealCouples' ,
                    '-X': 'TransIdxSigGroups',
                    '--X': 'BigTransIdxSigGroups',
                    '-Y': 'TransLastIdxSigGroups',
                    '--Y': 'BigTransLastIdxSigGroups',
                    '-Z': 'ESSRPayloadGroup',
                    '--Z': 'BigESSRPayloadGroup',
                    '-a': 'BlindedStateQuadruples',
                    '--a': 'BigBlindedStateQuadruples',
                    '-b': 'BoundStateSextuples',
                    '--b': 'BigBoundStateSextuples',
                    '-c': 'TypedMediaQuadruples',
                    '--c': 'BigTypedMediaQuadruples',
                    '-_AAA': 'KERIACDCGenusVersion'
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
                    '-L': Cizage(hs=2, ss=2, fs=4),
                    '--L': Cizage(hs=3, ss=5, fs=8),
                    '-T': Cizage(hs=2, ss=2, fs=4),
                    '--T': Cizage(hs=3, ss=5, fs=8),
                    '-U': Cizage(hs=2, ss=2, fs=4),
                    '--U': Cizage(hs=3, ss=5, fs=8),
                    '-V': Cizage(hs=2, ss=2, fs=4),
                    '--V': Cizage(hs=3, ss=5, fs=8),
                    '-W': Cizage(hs=2, ss=2, fs=4),
                    '--W': Cizage(hs=3, ss=5, fs=8),
                    '-Z': Cizage(hs=2, ss=2, fs=4),
                    '--Z': Cizage(hs=3, ss=5, fs=8),
                    '-_AAA': Cizage(hs=5, ss=3, fs=8)
                }
            },
            2:
            {
                0:
                {
                    '-A': Cizage(hs=2, ss=2, fs=4),
                    '--A': Cizage(hs=3, ss=5, fs=8),
                    '-B': Cizage(hs=2, ss=2, fs=4),
                    '--B': Cizage(hs=3, ss=5, fs=8),
                    '-C': Cizage(hs=2, ss=2, fs=4),
                    '--C': Cizage(hs=3, ss=5, fs=8),
                    '-D': Cizage(hs=2, ss=2, fs=4),
                    '--D': Cizage(hs=3, ss=5, fs=8),
                    '-E': Cizage(hs=2, ss=2, fs=4),
                    '--E': Cizage(hs=3, ss=5, fs=8),
                    '-F': Cizage(hs=2, ss=2, fs=4),
                    '--F': Cizage(hs=3, ss=5, fs=8),
                    '-G': Cizage(hs=2, ss=2, fs=4),
                    '--G': Cizage(hs=3, ss=5, fs=8),
                    '-H': Cizage(hs=2, ss=2, fs=4),
                    '--H': Cizage(hs=3, ss=5, fs=8),
                    '-I': Cizage(hs=2, ss=2, fs=4),
                    '--I': Cizage(hs=3, ss=5, fs=8),
                    '-J': Cizage(hs=2, ss=2, fs=4),
                    '--J': Cizage(hs=3, ss=5, fs=8),
                    '-K': Cizage(hs=2, ss=2, fs=4),
                    '--K': Cizage(hs=3, ss=5, fs=8),
                    '-L': Cizage(hs=2, ss=2, fs=4),
                    '--L': Cizage(hs=3, ss=5, fs=8),
                    '-M': Cizage(hs=2, ss=2, fs=4),
                    '--M': Cizage(hs=3, ss=5, fs=8),
                    '-N': Cizage(hs=2, ss=2, fs=4),
                    '--N': Cizage(hs=3, ss=5, fs=8),
                    '-O': Cizage(hs=2, ss=2, fs=4),
                    '--O': Cizage(hs=3, ss=5, fs=8),
                    '-P': Cizage(hs=2, ss=2, fs=4),
                    '--P': Cizage(hs=3, ss=5, fs=8),
                    '-Q': Cizage(hs=2, ss=2, fs=4),
                    '--Q': Cizage(hs=3, ss=5, fs=8),
                    '-R': Cizage(hs=2, ss=2, fs=4),
                    '--R': Cizage(hs=3, ss=5, fs=8),
                    '-S': Cizage(hs=2, ss=2, fs=4),
                    '--S': Cizage(hs=3, ss=5, fs=8),
                    '-T': Cizage(hs=2, ss=2, fs=4),
                    '--T': Cizage(hs=3, ss=5, fs=8),
                    '-U': Cizage(hs=2, ss=2, fs=4),
                    '--U': Cizage(hs=3, ss=5, fs=8),
                    '-V': Cizage(hs=2, ss=2, fs=4),
                    '--V': Cizage(hs=3, ss=5, fs=8),
                    '-W': Cizage(hs=2, ss=2, fs=4),
                    '--W': Cizage(hs=3, ss=5, fs=8),
                    '-X': Cizage(hs=2, ss=2, fs=4),
                    '--X': Cizage(hs=3, ss=5, fs=8),
                    '-Y': Cizage(hs=2, ss=2, fs=4),
                    '--Y': Cizage(hs=3, ss=5, fs=8),
                    '-Z': Cizage(hs=2, ss=2, fs=4),
                    '--Z': Cizage(hs=3, ss=5, fs=8),
                    '-a': Cizage(hs=2, ss=2, fs=4),
                    '--a': Cizage(hs=3, ss=5, fs=8),
                    '-b': Cizage(hs=2, ss=2, fs=4),
                    '--b': Cizage(hs=3, ss=5, fs=8),
                    '-c': Cizage(hs=2, ss=2, fs=4),
                    '--c': Cizage(hs=3, ss=5, fs=8),
                    '-_AAA': Cizage(hs=5, ss=3, fs=8)
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

    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['--A'].hs == 3  # hard size
    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['--A'].ss == 5  # soft size
    assert Counter.Sizes[Vrsn_2_0.major][Vrsn_2_0.minor]['--A'].fs == 8  # full size

    # first character of code with hard size of code
    assert Counter.Hards == \
    {
        '-A': 2, '-B': 2, '-C': 2, '-D': 2, '-E': 2, '-F': 2, '-G': 2, '-H': 2, '-I': 2,
        '-J': 2, '-K': 2, '-L': 2, '-M': 2, '-N': 2, '-O': 2, '-P': 2, '-Q': 2, '-R': 2,
        '-S': 2, '-T': 2, '-U': 2, '-V': 2, '-W': 2, '-X': 2, '-Y': 2, '-Z': 2,
        '-a': 2, '-b': 2, '-c': 2, '-d': 2, '-e': 2, '-f': 2, '-g': 2, '-h': 2, '-i': 2,
        '-j': 2, '-k': 2, '-l': 2, '-m': 2, '-n': 2, '-o': 2, '-p': 2, '-q': 2, '-r': 2,
        '-s': 2, '-t': 2, '-u': 2, '-v': 2, '-w': 2, '-x': 2, '-y': 2, '-z': 2,
        '--': 3, '-_': 5,
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

    # Test class methods
    # Test .enclose default V2
    enclosure = Counter.enclose()  # test defaults
    assert enclosure == bytearray(b'-CAA')

    enclosure = Counter.enclose(qb64=b'') # test empty
    assert enclosure == bytearray(b'-CAA')
    assert len(enclosure) == 4
    # round trip
    counter = Counter(qb64b=enclosure)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_2_0.AttachmentGroup
    assert counter.count == 0

    enclosure = Counter.enclose(qb2=b'') # test empty
    assert enclosure == bytearray(b'\xf8 \x00')
    assert len(enclosure) == 3
    # round trip
    counter = Counter(qb2=enclosure)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_2_0.AttachmentGroup
    assert counter.count == 0

    enclosure = Counter.enclose(qb64=b'', qb2=b'') # test empty qb64 priority
    assert enclosure == bytearray(b'-CAA')
    assert len(enclosure) == 4

    # test with something to enclose
    texter = Texter(text="How ya doing babe?")
    assert texter.qb64 == '4BAGSG93IHlhIGRvaW5nIGJhYmU_'
    assert texter.qb2 == b'\xe0\x10\x06How ya doing babe?'

    enclosure = Counter.enclose(qb64=texter.qb64)
    assert enclosure == bytearray(b'-CAH4BAGSG93IHlhIGRvaW5nIGJhYmU_')
    # round trip
    counter = Counter(qb64b=enclosure)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_2_0.AttachmentGroup
    assert counter.count == 7 == len(texter.qb64) // 4

    enclosure = Counter.enclose(qb2=texter.qb2)
    assert enclosure == bytearray(b'\xf8 \x07\xe0\x10\x06How ya doing babe?')
    # round trip
    counter = Counter(qb2=enclosure)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_2_0.AttachmentGroup
    assert counter.count == 7 == len(texter.qb2) // 3

    # test with other than default code
    enclosure = Counter.enclose(qb64=texter.qb64, code=Codens.GenericGroup)
    assert enclosure == bytearray(b'-AAH4BAGSG93IHlhIGRvaW5nIGJhYmU_')

    enclosure = Counter.enclose(qb2=texter.qb2, code=Codens.GenericGroup)
    assert enclosure ==bytearray(b'\xf8\x00\x07\xe0\x10\x06How ya doing babe?')

    # error cases
    with pytest.raises(kering.InvalidCodeError):
        enclosure = Counter.enclose(qb64=texter.qb64, code="MadeUpCode")

    with pytest.raises(ValueError):  # not aligned 24 bit
        enclosure = Counter.enclose(qb64=texter.qb64[:-1])

    with pytest.raises(ValueError):  # not aligned 24 bit
        enclosure = Counter.enclose(qb2=texter.qb2[:-1])

    # Test .enclose V1
    enclosure = Counter.enclose(version=Vrsn_1_0)  # test defaults
    assert enclosure == bytearray(b'-VAA')

    enclosure = Counter.enclose(qb64=b'', version=Vrsn_1_0) # test empty
    assert enclosure == bytearray(b'-VAA')
    assert len(enclosure) == 4
    # round trip
    counter = Counter(qb64b=enclosure, version=Vrsn_1_0)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_1_0.AttachmentGroup
    assert counter.count == 0

    enclosure = Counter.enclose(qb2=b'', version=Vrsn_1_0) # test empty
    assert enclosure == bytearray(b'\xf9P\x00')
    assert len(enclosure) == 3
    # round trip
    counter = Counter(qb2=enclosure, version=Vrsn_1_0)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_1_0.AttachmentGroup
    assert counter.count == 0

    # test with something to enclose
    texter = Texter(text="How ya doing babe?")
    assert texter.qb64 == '4BAGSG93IHlhIGRvaW5nIGJhYmU_'
    assert texter.qb2 == b'\xe0\x10\x06How ya doing babe?'

    enclosure = Counter.enclose(qb64=texter.qb64, version=Vrsn_1_0)
    assert enclosure == bytearray(b'-VAH4BAGSG93IHlhIGRvaW5nIGJhYmU_')
    # round trip
    counter = Counter(qb64b=enclosure, version=Vrsn_1_0)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_1_0.AttachmentGroup
    assert counter.count == 7 == len(texter.qb64) // 4

    enclosure = Counter.enclose(qb2=texter.qb2, version=Vrsn_1_0)
    assert enclosure == bytearray(b'\xf9P\x07\xe0\x10\x06How ya doing babe?')
    # round trip
    counter = Counter(qb2=enclosure, version=Vrsn_1_0)
    assert counter.name == Codens.AttachmentGroup
    assert counter.code == CtrDex_1_0.AttachmentGroup
    assert counter.count == 7 == len(texter.qb2) // 3

    # test with other than default code
    enclosure = Counter.enclose(qb64=texter.qb64,
                                code=Codens.GenericGroup,
                                version=Vrsn_1_0)
    assert enclosure == bytearray(b'-TAH4BAGSG93IHlhIGRvaW5nIGJhYmU_')

    enclosure = Counter.enclose(qb2=texter.qb2,
                                code=Codens.GenericGroup,
                                version=Vrsn_1_0)
    assert enclosure == bytearray(b'\xf90\x07\xe0\x10\x06How ya doing babe?')

    # error cases
    with pytest.raises(ValueError):  # not a QTDex code
        enclosure = Counter.enclose(qb64=texter.qb64,
                                    code=Codens.ControllerIdxSigs,
                                    version=Vrsn_1_0)

    with pytest.raises(ValueError):  # not a QTDex code
        enclosure = Counter.enclose(qb2=texter.qb2,
                                    code=Codens.ControllerIdxSigs,
                                    version=Vrsn_1_0)

    """ Done Test """

def test_counter_v1():
    """
    test Counter instances for verision 1.0 code tables
    """
    # version 1_0 tests
    CtrDex = Counter.Codes[Vrsn_1_0.major][Vrsn_1_0.minor]  # set CtrDex to Vrsn_1_0

    # test Counter instances
    with pytest.raises(kering.EmptyMaterialError):
        counter = Counter(version=Vrsn_1_0)

    # create code manually
    count = 1
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs == counter.hard
    assert counter.name == "ControllerIdxSigs"

    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.fullSize == 4
    assert counter.byteSize(cold=Colds.txt) == counter.fullSize
    assert counter.byteSize(cold=Colds.bny) == (counter.fullSize // 4) * 3 == 3
    assert counter.soft =='AB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64
    assert counter.codes == counting.CtrDex_1_0
    assert counter.sizes == Counter.Sizes[1][0]

    counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_1_0)
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
                      version=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(code=CtrDex.ControllerIdxSigs, version=Vrsn_1_0)  # default count = 1
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, version=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, version=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, version=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test truncates extra bytes from qb64 parameter
    longqsc64 = qsc + "ABCD"
    counter = Counter(qb64=longqsc64, version=Vrsn_1_0)
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb64 parameter
    shortqsc64 = qsc[:-1]  # too short
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb64=shortqsc64, version=Vrsn_1_0)

    # test truncates extra bytes from qb2 parameter
    longqscb2 = qscb2 + bytearray([1, 2, 3, 4, 5])  # extra bytes in size
    counter = Counter(qb2=longqscb2, version=Vrsn_1_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb64) == counter.sizes[counter.code].fs

    # test raises ShortageError if not enough bytes in qb2 parameter
    shortqscb2 = qscb2[:-4]  # too few bytes in  size
    with pytest.raises(kering.ShortageError):
        counter = Counter(qb2=shortqscb2, version=Vrsn_1_0)

    # test with non-zero count=5
    count = 5
    qsc = CtrDex.ControllerIdxSigs + intToB64(count, l=2)
    assert qsc == '-AAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count, version=Vrsn_1_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, version=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, version=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, version=Vrsn_1_0)  # test with qb2
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
    assert qsc == '--VF9j7A'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigAttachmentGroup, count=count, version=Vrsn_1_0)
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0
    assert counter.fullSize == 8
    assert counter.byteSize(cold=Colds.txt) == counter.fullSize
    assert counter.byteSize(cold=Colds.bny) == (counter.fullSize // 4) * 3 == 6

    counter = Counter(qb64b=qscb, version=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, version=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, version=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.BigAttachmentGroup
    assert counter.name == "BigAttachmentGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, version=Vrsn_1_0)  #
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

    # test BigPathedMaterialCouples with big codes index=100024000
    count = 100024000
    qsc = CtrDex.BigPathedMaterialCouples + intToB64(count, l=5)
    assert qsc == '--LF9j7A'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigPathedMaterialCouples, count=count, version=Vrsn_1_0)
    assert counter.code == CtrDex.BigPathedMaterialCouples
    assert counter.name == "BigPathedMaterialCouples"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64b=qscb, version=Vrsn_1_0)  # test with bytes not str
    assert counter.code == CtrDex.BigPathedMaterialCouples
    assert counter.name == "BigPathedMaterialCouples"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb64=qsc, version=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.BigPathedMaterialCouples
    assert counter.name == "BigPathedMaterialCouples"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    counter = Counter(qb2=qscb2, version=Vrsn_1_0)  # test with qb2
    assert counter.code == CtrDex.BigPathedMaterialCouples
    assert counter.name == "BigPathedMaterialCouples"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, version=Vrsn_1_0)  #
    code = counter.code
    count = counter.count
    qb2 = counter.qb2
    counter._bexfil(qb2)
    assert counter.code == code
    assert counter.name == "BigPathedMaterialCouples"
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
    counter = Counter(qb64=qsc, strip=True, version=Vrsn_1_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_1_0)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True, version=Vrsn_1_0)
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
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_1_0)
    assert counter.qb64b == qscb
    assert len(counter.qb64b) == counter.sizes[counter.code].fs
    assert ims == extra

    # test with longer ims for qb2
    extra = bytearray([1, 2, 3, 4, 5])
    ims = bytearray(qscb2) + extra
    counter = Counter(qb2=ims, strip=True, version=Vrsn_1_0)
    assert counter.qb2 == qscb2
    assert len(counter.qb2) == counter.sizes[counter.code].fs * 3 // 4
    assert ims == extra

    # raises error if not bytearray

    ims = bytes(qscb)  # test with qb64b
    with pytest.raises(TypeError):
        counter = Counter(qb64b=ims, strip=True, version=Vrsn_1_0)  # strip

    ims = bytes(qscb2)  # test with qb2
    with pytest.raises(TypeError):
        counter = Counter(qb2=ims, strip=True, version=Vrsn_1_0)

    # test with big codes index=1024
    count = 1024
    qsc = CtrDex.BigAttachmentGroup + intToB64(count, l=5)
    assert qsc == '--VAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_1_0)  # test with bytes not str
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
    counter = Counter(qb2=ims, strip=True, version=Vrsn_1_0)  # test with qb2
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
    assert qsc == '-_AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      count=genverint,
                      version=Vrsn_1_0)
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
    assert counter.sizes == Counter.Sizes[1][0]


    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      countB64=genver,
                      version=Vrsn_1_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_1_0

    # test byteCount
    count = 10  # quadlets
    counter = Counter(count=count, code=Codens.AttachmentGroup, version=Vrsn_1_0)
    assert counter.code == CtrDex.AttachmentGroup
    assert counter.name == "AttachmentGroup"
    assert counter.version == Vrsn_1_0
    assert counter.count == count
    assert counter.byteCount() == count * 4
    assert counter.byteCount(cold=Colds.txt) == count * 4
    assert counter.byteCount(cold=Colds.bny) == count * 3
    with pytest.raises(ValueError):
        counter.byteCount(cold=Colds.msg)

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
    assert qsc == '-KAB'
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
    assert counter.byteSize(cold=Colds.txt) == counter.fullSize
    assert counter.byteSize(cold=Colds.bny) == (counter.fullSize // 4) * 3 == 3
    assert counter.soft =='AB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64
    assert counter.codes == counting.CtrDex_2_0
    #assert counter.tags == counting.Tags_2_0
    assert counter.sizes == Counter.Sizes[2][0]



    # default count = 1
    counter = Counter(code=CtrDex.ControllerIdxSigs, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

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
    assert qsc == '-KAF'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(Codens.ControllerIdxSigs, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(Codens.ControllerIdxSigs,
                      count=count,
                      version=Vrsn_2_0)
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
                      version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(code=CtrDex.ControllerIdxSigs, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # Test ._bexfil
    counter = Counter(qb64=qsc, version=Vrsn_2_0)
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
    assert qsc == '-KAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    # strip ignored if qb64
    counter = Counter(qb64=qsc, strip=True, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    ims = bytearray(qscb)  # test with qb64b
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # strip
    assert not ims  # deleted
    assert counter.code == CtrDex.ControllerIdxSigs
    assert counter.name == "ControllerIdxSigs"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    ims = bytearray(qscb2)  # test with qb2
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)
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

    # test with big codes count=1024
    count = 1024
    qsc = CtrDex.BigGenericGroup + intToB64(count, l=5)
    assert qsc == '--AAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigGenericGroup, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.fullSize == 8
    assert counter.byteSize(cold=Colds.txt) == counter.fullSize
    assert counter.byteSize(cold=Colds.bny) == (counter.fullSize // 4) * 3 == 6

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
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
    assert qsc == '--AAAAQA'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert not ims

    ims = bytearray(qscb2)
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)  # test with qb2
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
    assert qsc == '--AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.BigGenericGroup, count=count, version=Vrsn_2_0)
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

    counter = Counter(qb64b=qscb, version=Vrsn_2_0)  # test with bytes not str
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb64=qsc, version=Vrsn_2_0)  # test with str not bytes
    assert counter.code == CtrDex.BigGenericGroup
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    counter = Counter(qb2=qscb2, version=Vrsn_2_0)  # test with qb2
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
    assert qsc == '--AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    ims = bytearray(qscb)
    counter = Counter(qb64b=ims, strip=True, version=Vrsn_2_0)  # test with bytes not str
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
    counter = Counter(qb2=ims, strip=True, version=Vrsn_2_0)  # test with qb2
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
    assert qsc == '--AAACAB'
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.GenericGroup, count=count, version=Vrsn_2_0)
    assert counter.code == CtrDex.BigGenericGroup == counter.hard
    assert counter.name == "BigGenericGroup"
    assert counter.count == count
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0
    assert counter.soft =='AACAB'
    assert counter.both == qsc == counter.hard + counter.soft == counter.qb64

    counter = Counter(Codens.GenericGroup, count=count, version=Vrsn_2_0)
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
    assert qsc == '-_AAAAAA'  # keri Cesr version 0.0.0
    qscb = qsc.encode("utf-8")
    qscb2 = decodeB64(qscb)

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      count=genverint,
                      version=Vrsn_2_0)
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
    assert counter.sizes == Counter.Sizes[2][0]

    counter = Counter(code=CtrDex.KERIACDCGenusVersion,
                      countB64=genver,
                      version=Vrsn_2_0)
    assert counter.code == CtrDex.KERIACDCGenusVersion
    assert counter.name == "KERIACDCGenusVersion"
    assert counter.count == genverint
    assert counter.countToB64(l=3) == genver
    assert counter.countToB64() == genver  # default length
    assert counter.qb64b == qscb
    assert counter.qb64 == qsc
    assert counter.qb2 == qscb2
    assert counter.version == Vrsn_2_0

    # test byteCount
    count = 10  # quadlets
    counter = Counter(count=count, code=Codens.AttachmentGroup, version=Vrsn_2_0)
    assert counter.code == CtrDex.AttachmentGroup
    assert counter.name == "AttachmentGroup"
    assert counter.version == Vrsn_2_0
    assert counter.count == count
    assert counter.byteCount() == count * 4
    assert counter.byteCount(cold=Colds.txt) == count * 4
    assert counter.byteCount(cold=Colds.bny) == count * 3
    with pytest.raises(ValueError):
        counter.byteCount(cold=Colds.msg)

    """End Test"""


if __name__ == "__main__":
    test_genus_codex_pro_gen()
    test_codexes_tags()
    test_counter_class()
    test_counter_v1()
    test_counter_v2()


