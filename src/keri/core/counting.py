# -*- coding: utf-8 -*-
"""
keri.core.counting module

Provides versioning support for Counter classes and codes
"""
import copy

from dataclasses import dataclass, astuple, asdict
from collections import namedtuple

from ..help import helping
from ..help.helping import sceil
from ..help.helping import (intToB64,  b64ToInt, codeB64ToB2, codeB2ToB64, Reb64,
                            nabSextets)

from .. import kering
from ..kering import (Colds, Versionage, Vrsn_1_0, Vrsn_2_0)

from ..core.coring import IceMapDom



@dataclass(frozen=True)
class GenusCodex(IceMapDom):
    """GenusCodex is codex of protocol genera for code table.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    KERI: str = '-_AAA'  # KERI Tables may be shared by ACDC and SPAC and TSP_
    ACDC: str = '-_AAB'  # Reserved in case ACDC can no longer share with KERI
    SPAC: str = '-_AAC'  # Reserved in case SPAC can no longer share with KERI
    TSP_: str = '-_AAD'  # Reserved in case TSP_ can no longer share with KERI


    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"
        # duplicate values above just result in multiple entries in tuple so
        # in inclusion still works

GenDex = GenusCodex()  # Make instance

# maps Protocol code from Protocols = Protocolage(keri="KERI", acdc="ACDC")
# to Genus Name in GenDex so can lookup chared CESR Genus code from Protocol Code
# Usage:   genus code = GenDex[ProGen["ACDC"]] == '-_AAA'
ProGen = dict(KERI='KERI', ACDC='KERI')


@dataclass(frozen=True)
class CounterCodex_1_0(IceMapDom):
    """CounterCodex_1_0 is codex hard (stable) part of all V1 counter codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    ControllerIdxSigs: str = '-A'  # Qualified Base64 Indexed Signature.
    WitnessIdxSigs: str = '-B'  # Qualified Base64 Indexed Signature.
    NonTransReceiptCouples: str = '-C'  # Composed Base64 Couple, pre+cig.
    TransReceiptQuadruples: str = '-D'  # Composed Base64 Quadruple, pre+snu+dig+sig.
    FirstSeenReplayCouples: str = '-E'  # Composed Base64 Couple, fnu+dts.
    TransIdxSigGroups: str = '-F'  # Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
    SealSourceCouples: str = '-G'  # Composed Base64 couple, snu+dig of given delegator/issuer/transaction event
    TransLastIdxSigGroups: str = '-H'  # Composed Base64 Group, pre+ControllerIdxSigs group.
    SealSourceTriples: str = '-I'  # Composed Base64 triple, pre+snu+dig of anchoring source event
    PathedMaterialGroup: str = '-L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    BigPathedMaterialGroup: str = '--L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    GenericGroup: str = '-T'  # Generic Material Quadlet (Universal with override)
    BigGenericGroup: str = '--T'  # Big Generic Material Quadlet (Universal with override)
    BodyWithAttachmentGroup: str = '-U'  # Message Body plus Attachments Quadlet (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--U'  # Big Message Body plus Attachments Quadlet (Universal with Override)
    AttachmentGroup: str = '-V'  # Message Attachments Only Quadlet (Universal with Override)
    BigAttachmentGroup: str = '--V'  # Message Attachments Only Quadlet (Universal with Override)
    NonNativeBodyGroup: str = '-W'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--W'  # Big Message body Non-native enclosed with Texter
    ESSRPayloadGroup: str = '-Z'  # ESSR Payload Group Quadlets (not implemented as quadlets)
    BigESSRPayloadGroup: str = '--Z'  # Big ESSR Payload Group Quadlets (not implemented as quadlets)
    KERIACDCGenusVersion: str = '-_AAA'  # KERI ACDC Protocol Stack CESR Version


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

CtrDex_1_0 = CounterCodex_1_0()

@dataclass(frozen=True)
class QuadTripCodex_1_0(IceMapDom):
    """QuadTripCodex_1_0 is codex hard (stable) part of all V1 counter codes that
    count quadlets/triplets.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    PathedMaterialGroup: str = '-L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    BigPathedMaterialGroup: str = '--L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    GenericGroup: str = '-T'  # Generic Material Quadlet (Universal with override)
    BigGenericGroup: str = '--T'  # Big Generic Material Quadlet (Universal with override)
    BodyWithAttachmentGroup: str = '-U'  # Message Body plus Attachments Quadlet (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--U'  # Big Message Body plus Attachments Quadlet (Universal with Override)
    AttachmentGroup: str = '-V'  # Message Attachments Only Quadlet (Universal with Override)
    BigAttachmentGroup: str = '--V'  # Message Attachments Only Quadlet (Universal with Override)
    NonNativeBodyGroup: str = '-W'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--W'  # Big Message body Non-native enclosed with Texter
    ESSRPayloadGroup: str = '-Z'  # ESSR Payload Group Quadlets (not implemented as quadlets)
    BigESSRPayloadGroup: str = '--Z'  # Big ESSR Payload Group Quadlets (not implemented as quadlets)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

QTDex_1_0 = QuadTripCodex_1_0()

@dataclass(frozen=True)
class UniversalCodex_1_0(IceMapDom):
    """CounterCodex_1_0 is codex hard (stable) part of all V1 universal counter codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    GenericGroup: str = '-T'  # Generic Material Quadlet (Universal with override)
    BigGenericGroup: str = '--T'  # Big Generic Material Quadlet (Universal with override)
    BodyWithAttachmentGroup: str = '-U'  # Message Body plus Attachments Quadlet (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--U'  # Big Message Body plus Attachments Quadlet (Universal with Override)
    AttachmentGroup: str = '-V'  # Message Attachments Only Quadlet (Universal with Override)
    BigAttachmentGroup: str = '--V'  # Message Attachments Only Quadlet (Universal with Override)
    NonNativeBodyGroup: str = '-W'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--W'  # Big Message body Non-native enclosed with Texter
    KERIACDCGenusVersion: str = '-_AAA'  # KERI ACDC Stack CESR Protocol Genus Version (Universal)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

UniDex_1_0 = UniversalCodex_1_0()

@dataclass(frozen=True)
class SpecialUniversalCodex_1_0(IceMapDom):
    """SpecialUniversalCodex_1_0 is codex hard (stable) part of all V1 special
    universal counter codes that may have optional genus-version override as
    first code in enclosed group.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    GenericGroup: str = '-T'  # Generic Material Quadlet (Universal with override)
    BigGenericGroup: str = '--T'  # Big Generic Material Quadlet (Universal with override)
    BodyWithAttachmentGroup: str = '-U'  # Message Body plus Attachments Quadlet (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--U'  # Big Message Body plus Attachments Quadlet (Universal with Override)
    AttachmentGroup: str = '-V'  # Message Attachments Only Quadlet (Universal with Override)
    BigAttachmentGroup: str = '--V'  # Message Attachments Only Quadlet (Universal with Override)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SUDex_1_0 = SpecialUniversalCodex_1_0()

@dataclass(frozen=True)
class MessageUniversalCodex_1_0(IceMapDom):
    """MessageUniversalCodex_1_0 is codex hard (stable) part of all V1 message
    universal counter codes that support CESR native messages. (currently none)
    But needed for symmetry when changing versions in how lookup happens in parser.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    NonNativeBodyGroup: str = '-W'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--W'  # Big Message body Non-native enclosed with Texter

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

MUDex_1_0 = MessageUniversalCodex_1_0()


@dataclass(frozen=True)
class CounterCodex_2_0(IceMapDom):
    """CounterCodex_2_0 is codex hard (stable) part of all V2 counter codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    GenericGroup: str = '-A'  # Generic Group (Universal with Override).
    BigGenericGroup: str = '--A'  # Big Generic Group (Universal with Override).
    BodyWithAttachmentGroup: str = '-B'  # Message Body plus Attachments Group (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--B'  # Big Message Body plus Attachments Group (Universal with Override).
    AttachmentGroup: str = '-C'  # Message Attachments Only Group (Universal with Override).
    BigAttachmentGroup: str = '--C'  # Big Attachments Only Group (Universal with Override).
    DatagramSegmentGroup: str = '-D'  # Datagram Segment Group (Universal).
    BigDatagramSegmentGroup: str = '--D'  # Big Datagram Segment Group (Universal).
    ESSRWrapperGroup: str = '-E'  # ESSR Wrapper Group (Universal).
    BigESSRWrapperGroup: str = '--E'  # Big ESSR Wrapper Group (Universal).
    FixBodyGroup: str = '-F'  # Fixed Field Message Body Group (Universal).
    BigFixBodyGroup: str = '--F'  # Big Fixed Field Message Body Group (Universal).
    MapBodyGroup: str = '-G'  # Field Map Message Body Group (Universal).
    BigMapBodyGroup: str = '--G'  # Big Field Map Message Body Group (Universal).
    NonNativeBodyGroup: str = '-H'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--H'  # Big Message body Non-native enclosed with Texter
    GenericMapGroup: str = '-I'  # Generic Field Map Group (Universal).
    BigGenericMapGroup: str = '--I'  # Big Generic Field Map Group (Universal).
    GenericListGroup: str = '-J'  # Generic List Group (Universal).
    BigGenericListGroup: str = '--J'  # Big Generic List Group (Universal).
    ControllerIdxSigs: str = '-K'  # Controller Indexed Signature(s) of qb64.
    BigControllerIdxSigs: str = '--K'  # Big Controller Indexed Signature(s) of qb64.
    WitnessIdxSigs: str = '-L'  # Witness Indexed Signature(s) of qb64.
    BigWitnessIdxSigs: str = '--L'  # Big Witness Indexed Signature(s) of qb64.
    NonTransReceiptCouples: str = '-M'  # NonTrans Receipt Couple(s), pre+cig.
    BigNonTransReceiptCouples: str = '--M'  # Big NonTrans Receipt Couple(s), pre+cig.
    TransReceiptQuadruples: str = '-N'  # Trans Receipt Quadruple(s), pre+snu+dig+sig.
    BigTransReceiptQuadruples: str = '--N'  # Big Trans Receipt Quadruple(s), pre+snu+dig+sig.
    FirstSeenReplayCouples: str = '-O'  # First Seen Replay Couple(s), fnu+dts.
    BigFirstSeenReplayCouples: str = '--O'  # First Seen Replay Couple(s), fnu+dts.
    PathedMaterialGroup: str = '-P'  # Pathed Material Group.
    BigPathedMaterialGroup: str = '--P'  # Big Pathed Material Group.
    DigestSealSingles: str = '-Q'  # Digest Seal Single(s), dig of sealed data.
    BigDigestSealSingles: str = '--Q'  # Big Digest Seal Single(s), dig of sealed data.
    MerkleRootSealSingles: str = '-R'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    BigMerkleRootSealSingles: str = '--R'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    SealSourceTriples: str = '-S'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    BigSealSourceTriples: str = '--S'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    SealSourceCouples: str = '-T'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    BigSealSourceCouples: str = '--T'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    SealSourceLastSingles: str = '-U'  # Seal Source Couple(s), pre of last source sealing or sealed event.
    BigSealSourceLastSingles: str = '--U'  # Big Seal Source Couple(s), pre of last source sealing or sealed event.
    BackerRegistrarSealCouples: str = '-V'  # Backer Registrar Seal Couple(s), brid+dig of sealed data.
    BigBackerRegistrarSealCouples: str = '--V'  # Big Backer Registrar Seal Couple(s), brid+dig of sealed data.
    TypedDigestSealCouples: str = '-W'  # Typed Digest Seal Couple(s), type seal +dig of sealed data.
    BigTypedDigestSealCouples: str = '--W'  # Big Typed Digest Seal Couple(s), type seal +dig of sealed data.
    TransIdxSigGroups: str = '-X'  # Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.
    BigTransIdxSigGroups: str = '--X'  # Big Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.
    TransLastIdxSigGroups: str = '-Y'  # Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.
    BigTransLastIdxSigGroups: str = '--Y'  # Big Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.
    ESSRPayloadGroup: str = '-Z'  # ESSR Payload Group.
    BigESSRPayloadGroup: str = '--Z'  # Big ESSR Payload Group.
    BlindedStateQuadruples: str = '-a'  # Blinded transaction event state quadruples dig+uuid+said+state.
    BigBlindedStateQuadruples: str = '--a'  # Big Blinded transaction event state quadruples dig+uuid+said+state.
    KERIACDCGenusVersion: str = '-_AAA'  # KERI ACDC Stack CESR Protocol Genus Version (Universal)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

CtrDex_2_0 = CounterCodex_2_0()

@dataclass(frozen=True)
class UniversalCodex_2_0(IceMapDom):
    """CounterCodex_2_0 is codex hard (stable) part of all V2 universal counter codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    GenericGroup: str = '-A'  # Generic Group (Universal with Override).
    BigGenericGroup: str = '--A'  # Big Generic Group (Universal with Override).
    BodyWithAttachmentGroup: str = '-B'  # Message Body plus Attachments Group (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--B'  # Big Message Body plus Attachments Group (Universal with Override).
    AttachmentGroup: str = '-C'  # Message Attachments Only Group (Universal with Override).
    BigAttachmentGroup: str = '--C'  # Big Attachments Only Group (Universal with Override).
    DatagramSegmentGroup: str = '-D'  # Datagram Segment Group (Universal).
    BigDatagramSegmentGroup: str = '--D'  # Big Datagram Segment Group (Universal).
    ESSRWrapperGroup: str = '-E'  # ESSR Wrapper Group (Universal).
    BigESSRWrapperGroup: str = '--E'  # Big ESSR Wrapper Group (Universal).
    FixBodyGroup: str = '-F'  # Fixed Field Message Body Group (Universal).
    BigFixBodyGroup: str = '--F'  # Big Fixed Field Message Body Group (Universal).
    MapBodyGroup: str = '-G'  # Field Map Message Body Group (Universal).
    BigMapBodyGroup: str = '--G'  # Big Field Map Message Body Group (Universal).
    NonNativeBodyGroup: str = '-H'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--H'  # Big Message body Non-native enclosed with Texter
    GenericMapGroup: str = '-I'  # Generic Field Map Group (Universal).
    BigGenericMapGroup: str = '--I'  # Big Generic Field Map Group (Universal).
    GenericListGroup: str = '-J'  # Generic List Group (Universal).
    BigGenericListGroup: str = '--J'  # Big Generic List Group (Universal).
    KERIACDCGenusVersion: str = '-_AAA'  # KERI ACDC Stack CESR Protocol Genus Version (Universal)

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

UniDex_2_0 = UniversalCodex_2_0()

@dataclass(frozen=True)
class SpecialUniversalCodex_2_0(IceMapDom):
    """SpecialUniversalCodex_2_0 is codex hard (stable) part of all V2 special
    universal counter codes that may have optional genus-version override as
    first code in enclosed group.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    GenericGroup: str = '-A'  # Generic Group (Universal with Override).
    BigGenericGroup: str = '--A'  # Big Generic Group (Universal with Override).
    BodyWithAttachmentGroup: str = '-B'  # Message Body plus Attachments Group (Universal with Override).
    BigBodyWithAttachmentGroup: str = '--B'  # Big Message Body plus Attachments Group (Universal with Override).
    AttachmentGroup: str = '-C'  # Message Attachments Only Group (Universal with Override).
    BigAttachmentGroup: str = '--C'  # Big Attachments Only Group (Universal with Override).


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SUDex_2_0 = SpecialUniversalCodex_2_0()

@dataclass(frozen=True)
class MessageUniversalCodex_2_0(IceMapDom):
    """MessageUniversalCodex_2_0 is codex hard (stable) part of all V2 message
    universal counter codes that support CESR native messages.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    DatagramSegmentGroup: str = '-D'  # Datagram Segment Group (Universal).
    BigDatagramSegmentGroup: str = '--D'  # Big Datagram Segment Group (Universal).
    ESSRWrapperGroup: str = '-E'  # ESSR Wrapper Group (Universal).
    BigESSRWrapperGroup: str = '--E'  # Big ESSR Wrapper Group (Universal).
    FixBodyGroup: str = '-F'  # Fixed Field Message Body Group (Universal).
    BigFixBodyGroup: str = '--F'  # Big Fixed Field Message Body Group (Universal).
    MapBodyGroup: str = '-G'  # Field Map Message Body Group (Universal).
    BigMapBodyGroup: str = '--G'  # Big Field Map Message Body Group (Universal).
    NonNativeBodyGroup: str = '-H'  # Message body Non-native enclosed with Texter
    BigNonNativeBodyGroup: str = '--H'  # Big Message body Non-native enclosed with Texter

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

MUDex_2_0 = MessageUniversalCodex_2_0()


# CodeNames  is tuple of codes names given by attributes of union of codices
CodeNames = tuple(asdict(CtrDex_2_0) | asdict(CtrDex_1_0))
# Codens  is namedtuple of CodeNames where its names are the code names
# Codens enables using the attributes of the named tuple to specify a code by
# name (indirection) so that changes in the code itself do not break the
# creation of a counter. Enables specifying a counter by the code name not the
# code itself. The code may change between versions but the code name does not.
Codenage = namedtuple("Codenage", CodeNames, defaults=CodeNames)
Codens = Codenage()


@dataclass(frozen=True)
class SealCodex_2_0(IceMapDom):
    """
    SealCodex_2_0 is codex of seal counter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    As subclass of MapCodex can get codes with item syntax using tag variables.
    Example: codex[tag]
    """
    DigestSealSingles: str = '-Q'  # Digest Seal Single(s), dig of sealed data.
    BigDigestSealSingles: str = '--Q'  # Big Digest Seal Single(s), dig of sealed data.
    MerkleRootSealSingles: str = '-R'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    BigMerkleRootSealSingles: str = '--R'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    SealSourceTriples: str = '-S'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    BigSealSourceTriples: str = '--S'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    SealSourceCouples: str = '-T'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    BigSealSourceCouples: str = '--T'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    SealSourceLastSingles: str = '-U'  # Seal Source Couple(s), pre of last source sealing event.
    BigSealSourceLastSingles: str = '--U'  # Big Seal Source Couple(s), pre of last source sealing event.
    BackerRegistrarSealCouples: str = '-V'  # Backer Registrar Seal Couple(s), brid+dig of sealed data.
    BigBackerRegistrarSealCouples: str = '--V'  # Big Backer Registrar Seal Couple(s), brid+dig of sealed data.
    TypedDigestSealCouples: str = '-W'  # Typed Digest Seal Couple(s), type seal +dig of sealed data.
    BigTypedDigestSealCouples: str = '--W'  # Big Typed Digest Seal Couple(s), type seal +dig of sealed data.


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

SealDex_2_0 = SealCodex_2_0()

# namedtuple for size entries in Counter derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# fs is the full size int number of chars in code
Cizage = namedtuple("Cizage", "hs ss fs")


class Counter:
    """
    Counter is fully qualified cryptographic material primitive base class for
    counter primitives (framing composition grouping count codes).

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Class Attributes:
        Codes (dict): nested of codexes keyed by major and minor version
        Names (dict): nested of map of code names to codes keyed by
                        major and minor version
        Hards (dict): of hard code sizes keyed by text domain selector
        Bards (dict): of hard code sizes keyed by binary domain selector
        Sizes (dict): of size tables keyed by version. Size table is dict
                      of Sizages keyed by hard code

    Attributes:


    Properties:
        version (Versionage): current CESR code table protocol genus version
        codes (CounterCodex_1_0 | CounterCodex_1_0): version specific codex
        sizes (dict): version specific sizes table
        code (str): hard part of derivation code to indicate cypher suite
        raw (bytes): crypto material only without code
        pad  (int): number of pad chars given raw
        count (int): count of quadlets/triplets of following framed material
                      (not including code)
        qb64 (str | bytes | bytearray): in Base64 fully qualified with
                                          derivation code + crypto mat
        qb64b (bytes | bytearray): in Base64 fully qualified with
                                    derivation code + crypto mat
        qb2  (bytes | bytearray): in binary with derivation code +
                                  crypto material

    Hidden:
        _version (Versionage): value for .version property
        _codes (CounterCodex_1_0 | CounterCodex_1_0): version specific codex
        _sizes (dict): version specific sizes table
        _code (str): value for .code property
        _raw (bytes): value for .raw property
        _count (int): value for .count property


    Versioning:
        CESR Genus specific code tables have a major and a minor version.

        For a given major version all minor versions must be backwards compatible.
        This means that minor version changes to tables are append only. New
        codes may be added but no existing codes may be changed. This means that
        a given implementation need only use use the latest minor version of
        the code table for a given major version when generating or parsing a
        primitive or group. Assuming the major versions match, when parsing,
        a primitive, when that primitive was generated with a later minor version
        than the implementation supports then it will not be recognized and
        raise an error. But if a primitive was generated with any earlier minor
        version than the version the implementation supports then the primitive
        will parse correctly using any later minor version of the code table.

        Likewise a given protocol stack may have message bodies that carry
        a major and a minor version.

        A given CESR Genus and a given Protocol message stack may be paired in
        order to synchronize versioning between the two when the message bodies
        use primitives and or groups defined by codes in the CESR Genus table.

        In this case pairing is between the CESR Genus labeled KERI_ACDC_SPAC
        and the message body protocol stack labeled KERI/ACDC/SPAC

        The two versions, CESR Genus and Protocol Stack, may be synchronized in
        the following way:

        * Major versions must match or be compatible

        * Minor versions may differ but must be compatible within a
        major version.

        Importantly the CESR code table version may not be included in the
        message body itself but only provided in the surrounding CESR stream.
        This means the code table version used by a message body may not be
        signed. Therefore the receiver of a message body with embedded CESR
        primitives and groups must be protected from a CESR code table genus
        version malleability attack.

        When the major versions of the CESR code table and protocol stack
        match, the signed embedded protocol stack major version protects
        the receiver from a major version malleability attack on the CESR
        code table. Otherwise the major versions must be compatible in a way
        that does not allow malleability. For example the set of allowed codes
        for a given message protocol version are compatible across CESR code
        table major versions.

        This, however, does not protect the receiver of a message body from
        a minor version malleability attack on the CESR code table.
        Nevertheless, the requirement that all minor versions of a CESR code
        table for a given major version must be backwards compatible,
        does indeed provide this protection.

        Either, the receiver of the message body recognizes exactly
        all primitives and groups in the message body because the CESR code
        table minor version supported by the receiver is greater than or equal
        to that used by the the minor version of the sender or any unsupported
        (later appended) primitives or group codes will be unrecognized by
        the received thereby raising an error that results in the message being
        dropped.

    """
    Codes = \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: CtrDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: CtrDex_2_0,
        },
    }

    # special universal codes
    SUCodes = \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: SUDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: SUDex_2_0,
        },
    }

    # special universal codes
    MUCodes = \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: MUDex_1_0,
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: MUDex_2_0,
        },
    }


    # invert dataclass codenames: codes to dict codes: codenames
    Names = copy.deepcopy(Codes)  # make deep nested copy so can invert nested values
    for minor in Names.values():
        for key in minor:
            minor[key] = {val: key for key, val in asdict(minor[key]).items()}


    # Hards table maps from bytes Base64 first two code chars to int of
    # hard size, hs,(stable) of code. The soft size, ss, (unstable) for Counter
    # is always > 0 and hs + ss = fs always
    Hards = ({('-' + chr(c)): 2 for c in range(65, 65 + 26)})
    Hards.update({('-' + chr(c)): 2 for c in range(97, 97 + 26)})
    Hards.update([('--', 3)])
    Hards.update([('-_', 5)])

    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first two code char. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    # Sizes table indexes size tables first by major version and then by
    # lastest minor version
    # Each size table maps hs chars of code to Cizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 and hs+ss=fs for Counter
    Sizes = \
    {
        Vrsn_1_0.major: \
        {
            Vrsn_1_0.minor: \
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
                '-_AAA': Cizage(hs=5, ss=3, fs=8),
            },
        },
        Vrsn_2_0.major: \
        {
            Vrsn_2_0.minor: \
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
                '--G': Cizage(hs=3, ss=5, fs=8,),
                '-H': Cizage(hs=2, ss=2, fs=4),
                '--H': Cizage(hs=3, ss=5, fs=8),
                '-I': Cizage(hs=2, ss=2, fs=4),
                '--I': Cizage(hs=3, ss=5, fs=8),
                '-J': Cizage(hs=2, ss=2, fs=4,),
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
                '-_AAA': Cizage(hs=5, ss=3, fs=8),
            },
        },
    }


    def __init__(self, code=None, *, count=None, countB64=None,
                 qb64b=None, qb64=None, qb2=None, strip=False,
                 version=Vrsn_2_0, **kwa):
        """Validate as fully qualified
        Parameters:
            code (str | None):  either stable (hard) part of derivation code or
                                code name. When code name then look up code from
                                ._codes. This allows versioning to change code
                                but keep stable code name.

            count (int | None): count of framed material in quadlets/triplets
                               for composition. Count does not include code.
                               When both count and countB64 are None then count
                               defaults to 1
            countB64 (str | None): count of framed material in quadlets/triplets
                                for composition as Base64 representation of int.
                                useful for genus-version version as count
            qb64b (bytes | bytearray | None): fully qualified crypto material text domain
                if code nor tag is provided
            qb64 (str | None) fully qualified crypto material text domain
                if code nor tag not qb64b is provided
            qb2 (bytes | bytearray | None)  fully qualified crypto material binary domain
                if code nor tag not qb64b nor qb54 is provided
            strip (bool):  True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip.
                default False
            version (Versionage): instance of genera version of CESR code tables


        Needs either code or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When code and count provided then validate that code and count are correct
        Else when qb64b or qb64 or qb2 provided extract and assign
        .code and .count

        """
        if version.major not in self.Sizes:
            raise kering.InvalidVersionError(f"Unsupported major version="
                                             f"{version.major}.")

        latest = list(self.Sizes[version.major])[-1]  # get latest supported minor version
        if version.minor > latest:
            raise kering.InvalidVersionError(f"Minor version={version.minor} "
                                             f" exceeds latest supported minor"
                                             f" version={latest}.")

        self._codes = self.Codes[version.major][latest]  # use latest supported version codes
        self._sizes = self.Sizes[version.major][latest]  # use latest supported version sizes
        self._version = version  # provided version may be earlier than supported version


        if code:  # code (hard) provided
             # assumes ._sizes ._codes coherent
            if code not in self._sizes or len(code) < 2:
                try:
                    code = self._codes[code]  # code is code name so look up code
                    if code not in self._sizes or len(code) < 2:
                        raise kering.InvalidCodeError(f"Unsupported {code=}.")
                except Exception as ex:
                    raise kering.InvalidCodeError(f"Unsupported {code=}.") from ex

            hs, ss, fs = self._sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if hs < 2 or fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
                raise kering.InvalidCodeSizeError(f"Whole code size not full "
                                                  f"size or not multiple of 4. "
                                                  f"{cs=} {fs=}.")

            if count is None:
                count = 1 if countB64 is None else b64ToInt(countB64)

            if code[1] not in ("0123456789_"):  # small or opcode [A-Z,a-z] or large [-]
                if ss not in (2, 5):  # not valid dynamic soft sizes
                    raise kering.InvalidVarIndexError(f"Invalid {ss=} "
                                                      f"for {code=}.")
                # dynamically promote code based on count
                if code[1] != '-' and count > (64 ** 2 - 1):  # small code but large count
                    # elevate code due to large count
                    code = f"--{code[1]}"  # promote hard
                    ss = 5

            if count < 0 or count > (64 ** ss - 1):
                raise kering.InvalidVarIndexError(f"Invalid {count=} for "
                                                  f"{code=} with {ss=}.")

            self._code = code
            self._count = count

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self._sizes[self.code].fs]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:  # rewrite to use direct binary exfiltration
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self._sizes[self.code].fs * 3 // 4]

        else:
            raise kering.EmptyMaterialError("Improper initialization need either "
                                     "(code and count) or qb64b or "
                                     "qb64 or qb2.")

        self._name = self.Names[version.major][latest][self.code]


    @classmethod
    def enclose(cls, *, qb64=None, qb2=None, code=Codens.AttachmentGroup,
                version=Vrsn_2_0):
        """Encloses (frames) CESR stream in qb64 (as bytes) or qb2 (as bytes)
        with prepended counter of type code. Assumes counter in quadlets/triplets.
        In V2 CESR, will work with all counters which must count quadlets/triplets)
        In V1 CESR, will only work with counters that count quadlets/triplets

        Returns:
            enclosure (bytearray): stream in qb64 or qb2 with prepended counter
                of type code. If both qb64 and qb2 are None then empty counter.
                If qb64 then returns enclosure as bytearray in qb64 text domain
                If qb2 then returns enclosure as bytearray in qb2 binary domain

        Parameters:
            qb64 (str|bytes|bytearray|memoryview|None): qualified Base64 sub-stream
                to be enclosed. May be empty. None means use qb2 if provided.
            qb2 (bytes|bytearray|memoryview|None): qualified Base2 sub-stream
                to be enclosed. May be empty. None means ignore
            code (str):  either stable (hard) part of derivation code or code name.
                When code name then look up code from ._codes. This allows
                versioning to change code but keep stable code name.
        """
        if qb64 is None and qb2 is None:
            qb64 = b''

        if qb64 is not None:  # process qb64 in text domain
            if hasattr(qb64, "encode"):
                qb64 = qb64.encode()  # convert to bytes
            if isinstance(qb64, memoryview):
                qb64 = bytearray(qb64)  # converts memoryview to bytearray
            length = len(qb64)
            if length % 4:  # invalid sized qb64 not aligned on 24 bit boundaries
                raise ValueError(f"Bad enclosed qb64 {length=}")
            count = length // 4
            # processes code as codens code name
            counter = cls(code=code, count=count, version=version)
            if version.major < Vrsn_2_0.major and counter.code not in (QTDex_1_0):
                raise ValueError("Non V1 quadlet/triplet counter code={counter.code}")
            enclosure = bytearray(counter.qb64b)
            enclosure.extend(qb64)
            return enclosure

        # process qb2 in binary domain
        if isinstance(qb2, memoryview):
            qb2 = bytearray(qb2)  # converts memoryview to bytearray
        length = len(qb2)
        if length % 3:  # invalid sized qb64 not aligned on 24 bit boundaries
            raise ValueError(f"Bad enclosed qb2 {length=}")
        count = length // 3
        # processes code as codens code name
        counter = cls(code=code, count=count, version=version)
        if version.major < Vrsn_2_0.major and counter.code not in (QTDex_1_0):
            raise ValueError("Non V1 quadlet/triplet counter code={counter.code}")
        enclosure = bytearray(counter.qb2)
        enclosure.extend(qb2)
        return enclosure



    @property
    def version(self):
        """Makes .version read only
        Returns ._version  genusversion
        """
        return self._version


    @property
    def codes(self):
        """Makes .codes read only
        Returns ._codes
        """
        return self._codes


    @property
    def sizes(self):
        """Makes .sizes read only
        Returns ._sizes
        """
        return self._sizes


    @property
    def code(self):
        """Property for code
        Returns:
            code (str): hard part only of full text code.
                Getter for ._code. Makes .code read only

        Soft part is count
        """
        return self._code


    @property
    def name(self):
        """Getter for ._name. Makes .name read only
        Returns:
            name (str): code name for self.code. Match interface
                        for annotation for primitives like Matter
        """
        return self._name


    @property
    def hard(self):
        """Alias for .code
        Returns:
            hard (str): hard part only of full text code. Alias for .code.
        """
        return self.code


    @property
    def count(self):
        """Getter for ._count. Makes ._count read only
        Returns:
            count (int):  count value in quadlets/triples chars/bytes of material
                framed by counter.

        """
        return self._count


    @property
    def soft(self):
        """Converts .count to b64
        Returns:
            soft (str):  Base64 soft part of full counter code. Count value in
                quadlets/triples chars/bytes of material framed by counter.

        """
        _, ss, _ = self.sizes[self.code]
        return intToB64(self._count, l=ss)


    @property
    def both(self):
        """Getter for combined hard + soft parts of full text code
        Returns:
            both (str):  hard + soft parts of full text code
        """
        return f"{self.hard}{self.soft}"


    @property
    def fullSize(self):
        """Getter for full size of counter in bytes in text domain
        Returns"
           fs (int): full size of counter in bytes in text domain

        """
        _, _, fs = self.sizes[self.code]  # get from sizes table

        return fs


    @property
    def qb64b(self):
        """Property qb64b:
        Returns:
            Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """Property qb64:
        Returns:
            Fully Qualified Base64 Version, same as .both
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """Property qb2:
        Returns Fully Qualified Binary Version Bytes
        """
        return self._binfil()


    def countToB64(self, l=None):
        """ Returns count as Base64 left padded with "A"s
            Parameters:
                l (int | None): minimum number characters including left padding
                    When not provided use the softsize of .code

        """
        if l is None:
            _, ss, _ = self._sizes[self.code]
            l = ss
        return (intToB64(self.count, l=l))


    def byteCount(self, cold=Colds.txt):
        """Computes number of bytes from .count quadlets/triplets given cold

        Returns:
            byteCount (int): number of bytes in .count quadlets/triplets given cold

        Parameters:
            cold (str): value of Coldage to indicate if text (qb64) or binary (qb2)
                        in order to convert .count quadlets/triplets to byte count
                        if not Colds.txt or Colds.bny raises ValueError
        """
        if cold == Colds.txt:  # quadlets
            return self.count * 4

        if cold == Colds.bny:  # triplets
            return self.count * 3

        raise ValueError(f"Invalid {cold=} for byte count conversion")


    def byteSize(self, cold=Colds.txt):
        """Computes number of bytes from .fullSize given cold (text or binary domain)
        so can strip appropriate number of bytes from stream when peeking at
        counter in stream without stripping it.

        Returns:
            byteSize (int): number of bytes given cold (text or binary domain)

        Parameters:
            cold (str): value of Coldage to indicate if text (qb64) or binary (qb2)
                        in order to convert .count quadlets/triplets to byte count
                        if not Colds.txt or Colds.bny raises ValueError
        """
        if cold == Colds.txt:
            return self.fullSize

        if cold == Colds.bny:
            return (self.fullSize // 4) * 3

        raise ValueError(f"Invalid {cold=} for byte size conversion")



    @staticmethod
    def verToB64(version=None, *, text="", major=0, minor=0):
        """ Converts version to Base64 representation of countB64
        suitable for CESR protocol genus and version

        Returns:
            countB64 (str): suitable for input to Counter param countB64 for
                            creating genus-version code version count portion

        Parameters:
            version (Versionage): instange of namedtuple
                         Versionage(major=major,minor=minor)
            text (str): text format of version as dotted decimal "major.minor"
            major (int): When version is None and verstr is empty then use major minor
                        range [0, 63] for one Base64 character
            minor (int): When version is None and verstr is  empty then use major minor
                        range [0, 4095] for two Base64 characters

        Example:
            Counter(countB64=Counter.verToB64(text = "1.0"))
            Counter(countB64=Counter.verToB64(major=1, minor=0))

        """
        if version:
            major = version.major
            minor = version.minor

        elif text:
            splits = text.split(".", maxsplit=2)
            splits = [(int(s) if s else 0) for s in splits]
            parts = [major, minor]
            for i in range(2-len(splits),0, -1):  # append missing minor and/or major
                splits.append(parts[-i])
            major = splits[0]
            minor = splits[1]

        if major < 0 or major > 63 or minor < 0 or minor > 4095:
                raise ValueError(f"Out of bounds version = {major}.{minor}.")

        return (f"{intToB64(major)}{intToB64(minor, l=2)}")


    @staticmethod
    def b64ToVer(b64, *, texted=False):
        """ Converts Base64 representation of version to Versionage or
        text dotted decimal format

        default is Versionage

        Returns:
            version (Versionage | str):

        Example:
            Counter(version=Counter.b64ToVer("BAA"))

        Parameters:
            b64 (str): base64 string of three characters Mmm for Major minor
            texted (bool): return text format dotted decimal string


        """
        if not Reb64.match(b64.encode("utf-8")):
            raise ValueError("Invalid Base64.")

        if texted:
            return ".".join([f"{b64ToInt(b64[0])}", f"{b64ToInt(b64[1:3])}"])

        return Versionage(major=b64ToInt(b64[0]), minor=b64ToInt(b64[1:3]))


    def _infil(self):
        """Returns fully qualified attached sig base64 bytes computed from
        self.code and self.count.
        """
        code = self.code  # codex value chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs = self._sizes[code]
        # assumes fs = hs + ss  # both hard + soft size
        # assumes unit tests ensure ._sizes table entries are consistent
        # hs >= 2, ss > 0 fs == hs + ss, not (fs % 4)

        if count < 0 or count > (64 ** ss - 1):
            raise kering.InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both = "{}{}".format(code, intToB64(count, l=ss))

        # check valid pad size for whole code size
        if len(both) % 4:  # no pad
            raise kering.InvalidCodeSizeError("Invalid size = {} of {} not a multiple of 4."
                                       .format(len(both), both))
        # prepending full derivation code with index and strip off trailing pad characters
        return (both.encode("utf-8"))


    def _binfil(self):
        """Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs = self._sizes[code]
        # assumes fs = hs + ss
        # assumes unit tests ensure ._sizes table entries are consistent
        # hs >= 2, ss>0 fs ==  hs + ss, not (fs % 4)

        if count < 0 or count > (64 ** ss - 1):
            raise kering.InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both = "{}{}".format(code, intToB64(count, l=ss))
        if len(both) != fs:
            raise kering.InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(fs, len(both)))

        return (codeB64ToB2(both))  # convert to b2 left shift if any


    def _exfil(self, qb64b):
        """Extracts self.code and self.count from qualified base64 bytes qb64b
        """
        if not qb64b or len(qb64b) < 2:  # need more bytes
            raise kering.ShortageError("Empty material, Need more characters.")


        first = qb64b[:2]  # extract first two char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Hards:
            if first[0] == '_':
                raise kering.UnexpectedOpCodeError("Unexpected op code start"
                                            "while extracing Counter.")
            else:
                raise kering.UnexpectedCodeError("Unsupported code start ={}.".format(first))

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise kering.ShortageError("Need {} more characters.".format(hs - len(qb64b)))

        hard = qb64b[:hs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")  # decode converts bytearray/bytes to str
        if hard not in self._sizes:  # Sizes needs str not bytes
            raise kering.UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self._sizes[hard]  # assumes hs consistent in both tables
        # assumes fs = hs + ss  # both hard + soft code size
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs >= 2 and ss > 0 and fs = hs + ss and not fs % 4

        if len(qb64b) < fs:  # need more bytes
            raise kering.ShortageError("Need {} more characters.".format(fs - len(qb64b)))

        count = qb64b[hs:fs]  # extract count chars
        if hasattr(count, "decode"):
            count = count.decode("utf-8")
        count = b64ToInt(count)  # compute int count

        self._code = hard
        self._count = count


    def _bexfil(self, qb2):
        """Extracts self.code and self.count from qualified base2 bytes qb2
        """
        if not qb2 or len(qb2) < 2:  # need more bytes
            raise kering.ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 2)  # extract first two sextets as code selector
        if first not in self.Bards:
            if first[0] == b'\xfc':  # b64ToB2('_')
                raise kering.UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise kering.UnexpectedCodeError("Unsupported code start sextet={}.".format(first))

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise kering.ShortageError("Need {} more bytes.".format(bhs - len(qb2)))

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self._sizes:
            raise kering.UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs = self._sizes[hard]
        # assumes fs = hs + ss  # both hs and ss
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs >= 2 and ss > 0 and fs = hs + ss and not fs % 4

        bcs = sceil(fs * 3 / 4)  # bcs is min bytes to hold fs sextets
        if len(qb2) < bcs:  # need more bytes
            raise kering.ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, fs)  # extract and convert both hard and soft part of code
        count = b64ToInt(both[hs:fs])  # get count

        self._code = hard
        self._count = count

