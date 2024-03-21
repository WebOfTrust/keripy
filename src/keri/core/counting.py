# -*- encoding: utf-8 -*-
"""
keri.core.counting module

Provides versioning support for Counter classes and codes
"""

from dataclasses import dataclass, astuple, asdict
from collections import namedtuple

from ..help import helping
from ..help.helping import sceil
from ..help.helping import (intToB64,  b64ToInt, codeB64ToB2, codeB2ToB64, Reb64,
                            nabSextets)

from .. import kering
from ..kering import (Versionage, Version, Vrsn_1_0, Vrsn_2_0)

from ..core.coring import Sizage


@dataclass
class MapDom:
    """Base class for dataclasses that support map syntax
    Adds support for dunder methods for map syntax dc[name].
    Converts exceptions from attribute syntax to raise map syntax when using
    map syntax.
    """

    def __getitem__(self, name):
        try:
            return getattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __setitem__(self, name, value):
        try:
            return setattr(self, name, value)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __delitem__(self, name):
        try:
            return delattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


@dataclass(frozen=True)
class MapCodex:
    """Base class for frozen dataclasses (codexes) that support map syntax
    Adds support for dunder methods for map syntax dc[name].
    Converts exceptions from attribute syntax to raise map syntax when using
    map syntax.
    """

    def __getitem__(self, name):
        try:
            return getattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __setitem__(self, name, value):
        try:
            return setattr(self, name, value)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex


    def __delitem__(self, name):
        try:
            return delattr(self, name)
        except AttributeError as ex:
            raise IndexError(ex.args) from ex



@dataclass(frozen=True)
class CounterCodex_1_0(MapCodex):
    """
    CounterCodex is codex hard (stable) part of all counter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
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
    SadPathSigGroups: str = '-J'  # Composed Base64 Group path+TransIdxSigGroup of SAID of content
    RootSadPathSigGroups: str = '-K'  # Composed Base64 Group, root(path)+SaidPathCouples
    PathedMaterialGroup: str = '-L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    AttachmentGroup: str = '-V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigAttachmentGroup: str = '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    KERIACDCGenusVersion: str = '--AAA'  # KERI ACDC Protocol Stack CESR Version


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

CtrDex_1_0 = CounterCodex_1_0()

@dataclass(frozen=True)
class CounterCodex_2_0(MapCodex):
    """
    CounterCodex is codex hard (stable) part of all counter derivation codes.
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    GenericGroup: str = '-A'  # Generic Group (Universal with Override).
    BigGenericGroup: str = '-0A'  # Big Generic Group (Universal with Override).
    MessageGroup: str = '-B'  # Message Body plus Attachments Group (Universal with Override).
    BigMessageGroup: str = '-0B'  # Big Message Body plus Attachments Group (Universal with Override).
    AttachmentGroup: str = '-C'  # Message Attachments Only Group (Universal with Override).
    BigAttachmentGroup: str = '-0C'  # Big Attachments Only Group (Universal with Override).
    DatagramSegmentGroup: str = '-D'  # Datagram Segment Group (Universal).
    BigDatagramSegmentGroup: str = '-0D'  # Big Datagram Segment Group (Universal).
    ESSRWrapperGroup: str = '-E'  # ESSR Wrapper Group (Universal).
    BigESSRWrapperGroup: str = '-0E'  # Big ESSR Wrapper Group (Universal).
    FixedMessageBodyGroup: str = '-F'  # Fixed Field Message Body Group (Universal).
    BigFixedMessageBodyGroup: str = '-0F'  # Big Fixed Field Message Body Group (Universal).
    MapMessageBodyGroup: str = '-G'  # Field Map Message Body Group (Universal).
    BigMapMessageBodyGroup: str = '-0G'  # Big Field Map Message Body Group (Universal).
    GenericMapGroup: str = '-H'  # Generic Field Map Group (Universal).
    BigGenericMapGroup: str = '-0H'  # Big Generic Field Map Group (Universal).
    GenericListGroup: str = '-L'  # Generic List Group (Universal).
    BigGenericListGroup: str = '-0L'  # Big Generic List Group (Universal).
    ControllerIdxSigs: str = '-J'  # Controller Indexed Signature(s) of qb64.
    BigControllerIdxSigs: str = '-0J'  # Big Controller Indexed Signature(s) of qb64.
    WitnessIdxSigs: str = '-K'  # Witness Indexed Signature(s) of qb64.
    BigWitnessIdxSigs: str = '-0K'  # Big Witness Indexed Signature(s) of qb64.
    NonTransReceiptCouples: str = '-L'  # NonTrans Receipt Couple(s), pre+cig.
    BigNonTransReceiptCouples: str = '-0L'  # Big NonTrans Receipt Couple(s), pre+cig.
    TransReceiptQuadruples: str = '-M'  # Trans Receipt Quadruple(s), pre+snu+dig+sig.
    BigTransReceiptQuadruples: str = '-0M'  # Big Trans Receipt Quadruple(s), pre+snu+dig+sig.
    FirstSeenReplayCouples: str = '-N'  # First Seen Replay Couple(s), fnu+dts.
    BigFirstSeenReplayCouples: str = '-0N'  # First Seen Replay Couple(s), fnu+dts.
    TransIdxSigGroups: str = '-O'  # Trans Indexed Signature Group(s), pre+snu+dig+ControllerIdxSigs of qb64.
    TransIdxSigGroups: str = '-0O'  # Big Trans Indexed Signature Group(s), pre+snu+dig+ControllerIdxSigs of qb64.
    TransLastIdxSigGroups: str = '-P'  # Trans Last Est Evt Indexed Signature Group(s), pre+ControllerIdxSigs of qb64.
    BigTransLastIdxSigGroups: str = '-0P'  # Big Trans Last Est Evt Indexed Signature Group(s), pre+ControllerIdxSigs of qb64.
    SealSourceCouples: str = '-Q'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    BigSealSourceCouples: str = '-0Q'  # Seal Source Couple(s), snu+dig of source sealing or sealed event.
    SealSourceTriples: str = '-R'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    BigSealSourceTriples: str = '-0R'  # Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.
    PathedMaterialGroup: str = '-S'  # Pathed Material Group.
    BigPathedMaterialGroup: str = '-0S'  # Big Pathed Material Group.
    SadPathSigGroups: str = '-T'  # SAD Path Group(s) sadpath+TransIdxSigGroup(s) of SAID qb64 of content.
    BigSadPathSigGroups: str = '-0T'  # Big SAD Path Group(s) sadpath+TransIdxSigGroup(s) of SAID qb64 of content.
    RootSadPathSigGroups: str = '-U'  # Root Path SAD Path Group(s), rootpath+SadPathGroup(s).
    BigRootSadPathSigGroups: str = '-0U'  # Big Root Path SAD Path Group(s), rootpath+SadPathGroup(s).
    DigestSealSingles: str = '-V'  # Digest Seal Single(s), dig of sealed data.
    BigDigestSealSingles: str = '-0V'  # Big Digest Seal Single(s), dig of sealed data.
    MerkleRootSealSingles: str = '-W'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    BigMerkleRootSealSingles: str = '-0W'  # Merkle Tree Root Digest Seal Single(s), dig of sealed data.
    BackerRegistrarSealCouples: str = '-X'  # Backer Registrar Seal Couple(s), brid+dig of sealed data.
    BigBackerRegistrarSealCouples: str = '-0X'  # Big Backer Registrar Seal Couple(s), brid+dig of sealed data.
    ESSRPayloadGroup: str = '-Z'  # ESSR Payload Group.
    BigESSRPayloadGroup: str = '-0Z'  # Big ESSR Payload Group.
    KERIACDCGenusVersion: str = '--AAA'  # KERI ACDC Stack CESR Protocol Genus Version (Universal)



    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

CtrDex_2_0 = CounterCodex_2_0()


@dataclass(frozen=True)
class GenusCodex(MapCodex):
    """GenusCodex is codex of protocol genera for code table.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    KERI: str = '--AAA'  # KERI and ACDC Protocol Stacks share the same tables
    ACDC: str = '--AAA'  # KERI and ACDC Protocol Stacks share the same tables


    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"
        # duplicate values above just result in multiple entries in tuple so
        # in inclusion still works

GenDex = GenusCodex()  # Make instance

# keys and values as strings of keys
Codict1 = asdict(CtrDex_1_0)
Tagage_1_0 = namedtuple("Tagage_1_0", list(Codict1), defaults=list(Codict1))
Tags_1_0 = Tagage_1_0()  # uses defaults

Codict2 = asdict(CtrDex_2_0)
Tagage_2_0 = namedtuple("Tagage_2_0", list(Codict2), defaults=list(Codict2))
Tags_2_0 = Tagage_2_0()  # uses defaults

CodictAll = Codict2 | Codict1
AllTagage = namedtuple("AllTagage", list(CodictAll), defaults=list(CodictAll))
AllTags = AllTagage()  # uses defaults


class Counter:
    """
    Counter is fully qualified cryptographic material primitive base class for
    counter primitives (framing composition grouping count codes).

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Class Attributes:
        Codes (dict): of codexes keyed by version
        Tags (dict): of tagages keyed by version
        Hards (dict): of hard code sizes keyed by selector text
        Bards (dict): of hard code sizes keyed by selector binary
        Sizes (dict): of Sizages keyed by hard code

    Attributes:


    Properties:
        .version (Versionage): current CESR code table protocol genus version
        .codes (CounterCodex_1_0 | CounterCodex_1_0): version specific codex
        .sizes (dict): version specific sizes table
        .code (str) derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .pad  is int number of pad chars given raw
        .count is int count of grouped following material (not part of counter)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material

    Hidden:
        ._version (Versionage): value for .version property
        ._codes (CounterCodex_1_0 | CounterCodex_1_0): version specific codex
        ._sizes (dict): version specific sizes table
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._pad is method to compute  .pad property
        ._count is int value for .count property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Codes = {Vrsn_1_0: CtrDex_1_0, Vrsn_2_0: CtrDex_2_0}
    Tags = {Vrsn_1_0: Tags_1_0, Vrsn_2_0: Tags_2_0}

    # Hards table maps from bytes Base64 first two code chars to int of
    # hard size, hs,(stable) of code. The soft size, ss, (unstable) for Counter
    # is always > 0 and hs + ss = fs always
    Hards = ({('-' + chr(c)): 2 for c in range(65, 65 + 26)})
    Hards.update({('-' + chr(c)): 2 for c in range(97, 97 + 26)})
    Hards.update([('-0', 3)])
    Hards.update([('--', 5)])

    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first two code char. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    # Sizes table maps hs chars of code to Sizage namedtuple of (hs, ss, fs)
    # where hs is hard size, ss is soft size, and fs is full size
    # soft size, ss, should always be  > 0 and hs+ss=fs for Counter
    Sizes = \
    {
        Vrsn_1_0: \
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
            '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0),
        },
        Vrsn_2_0: \
        {
            '-A': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0A': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-B': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0B': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-C': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0C': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-D': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0D': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-E': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0E': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-F': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0F': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-G': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0G': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-H': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0H': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-I': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0I': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-J': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0J': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-K': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0K': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-L': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0L': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-M': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0M': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-N': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0N': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-O': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0O': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-P': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0P': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-Q': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0Q': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-R': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0R': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-S': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0S': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-T': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0T': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-U': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0U': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-V': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0V': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-W': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0W': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-X': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0X': Sizage(hs=3, ss=5, fs=8, ls=0),
            '-Y': Sizage(hs=2, ss=2, fs=4, ls=0),
            '-0Y': Sizage(hs=3, ss=5, fs=8, ls=0),
            '--AAA': Sizage(hs=5, ss=3, fs=8, ls=0),
        },
    }


    def __init__(self, tag=None, *, code = None, count=None, countB64=None,
                 qb64b=None, qb64=None, qb2=None, strip=False, version=Version):
        """
        Validate as fully qualified
        Parameters:
            tag (str | None):  label of stable (hard) part of derivation code
                               to lookup in codex so it can depend on version.
                               takes precedence over tag
            code (str | None):  stable (hard) part of derivation code
                            if tag provided lookup code from tag
                            else if tag is None and code provided use code
            count (int | None): count for composition.
                Count may represent quadlets/triplet, groups, primitives or
                other numericy
                When both count and countB64 are None then count defaults to 1
            countB64 (str | None): count for composition as Base64
                countB64 may represent quadlets/triplet, groups, primitives or
                other numericy
            qb64b (bytes | bytearray | None): fully qualified crypto material text domain
                if code nor tag is provided
            qb64 (str | None) fully qualified crypto material text domain
                if code nor tag not qb64b is provided
            qb2 (bytes | bytearray | None)  fully qualified crypto material binary domain
                if code nor tag not qb64b nor qb54 is provided
            strip (bool):  True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip.
                default False
            version (Versionage): instance of version of code tables to use
                                  provides protocol genera version


        Needs either code or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When code and count provided then validate that code and count are correct
        Else when qb64b or qb64 or qb2 provided extract and assign
        .code and .count

        """
        self._version = version
        self._codes = self.Codes[self._version]
        self._sizes = self.Sizes[self._version]

        if tag:
            if not hasattr(self._codes, tag):
                raise kering.InvalidCodeError(f"Unsupported {tag=}.")
            code = self._codes[tag]

        if code is not None:  # code (hard) provided
            if code not in self._sizes or len(code) < 2:
                raise kering.InvalidCodeError(f"Unsupported {code=}.")

            hs, ss, fs, ls = self._sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if hs < 2 or fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
                raise kering.InvalidCodeSizeError(f"Whole code size not full "
                                                  f"size or not multiple of 4. "
                                                  f"{cs=} {fs=}.")

            if count is None:
                count = 1 if countB64 is None else b64ToInt(countB64)

            if code[1] not in ("123456789-_"):  # small [A-Z,a-z] or large [0]
                if ss not in (2, 5):  # not valid dynamic soft sizes
                    raise kering.InvalidVarIndexError(f"Invalid {ss=} "
                                                      f"for {code=}.")
                # dynamically promote code based on count
                if code[0] != '0' and count > (64 ** 2 - 1):  # small code but large count
                    # elevate code due to large count
                    code = f"-0{code[1]}"  # promote hard
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

    @property
    def version(self):
        """
        Returns ._version
        Makes .version read only
        """
        return self._version

    @property
    def codes(self):
        """
        Returns ._codes
        Makes .codes read only
        """
        return self._codes

    @property
    def tags(self):
        """
        Returns ._tags
        Makes .tags read only
        """
        return self._tags

    @property
    def sizes(self):
        """
        Returns ._sizes
        Makes .sizes read only
        """
        return self._sizes

    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code


    @property
    def count(self):
        """
        Returns ._count
        Makes ._count read only
        """
        return self._count


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64b.decode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
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
            _, ss, _, _ = self._sizes[self.code]
            l = ss
        return (intToB64(self.count, l=l))


    @staticmethod
    def verToB64(version=None, *, text="", major=0, minor=0):
        """ Converts version to Base64 representation of countB64
        suitable for CESR protocol genus and version

        Returns:
            countB64 (str): suitable for input to Counter

        Example:
            Counter(countB64=Counter.verToB64(verstr = "1.0"))

        Parameters:
            version (Versionage): instange of namedtuple
                         Versionage(major=major,minor=minor)
            text (str): text format of version as dotted decimal "major.minor"
            major (int): When version is None and verstr is empty then use major minor
                        range [0, 63] for one Base64 character
            minor (int): When version is None and verstr is  empty then use major minor
                        range [0, 4095] for two Base64 characters

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
        """
        Returns fully qualified attached sig base64 bytes computed from
        self.code and self.count.
        """
        code = self.code  # codex value chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs, ls = self._sizes[code]
        cs = hs + ss  # both hard + soft size
        if hs < 2 or fs != cs or cs % 4:  # hs >=2 fs must be bs and multiple of 4 for count codes
            raise kering.InvalidCodeSizeError("Whole code size not full size or not "
                                       "multiple of 4. cs={} fs={}.".format(cs, fs))
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
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code converted to Base2 left shifted with pad bits
        equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs, ls = self._sizes[code]
        cs = hs + ss
        if hs < 2 or fs != cs or cs % 4:  # hs >= 2 fs must be cs and multiple of 4 for count codes
            raise kering.InvalidCodeSizeError("Whole code size not full size or not "
                                       "multiple of 4. cs={} fs={}.".format(cs, fs))

        if count < 0 or count > (64 ** ss - 1):
            raise kering.InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

        # both is hard code + converted count
        both = "{}{}".format(code, intToB64(count, l=ss))
        if len(both) != cs:
            raise kering.InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        return (codeB64ToB2(both))  # convert to b2 left shift if any


    def _exfil(self, qb64b):
        """
        Extracts self.code and self.count from qualified base64 bytes qb64b
        """
        if not qb64b:  # empty need more bytes
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

        hs, ss, fs, ls = self._sizes[hard]  # assumes hs consistent in both tables
        cs = hs + ss  # both hard + soft code size

        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        if len(qb64b) < cs:  # need more bytes
            raise kering.ShortageError("Need {} more characters.".format(cs - len(qb64b)))

        count = qb64b[hs:hs + ss]  # extract count chars
        if hasattr(count, "decode"):
            count = count.decode("utf-8")
        count = b64ToInt(count)  # compute int count

        self._code = hard
        self._count = count


    def _bexfil(self, qb2):
        """
        Extracts self.code and self.count from qualified base2 bytes qb2
        """
        if not qb2:  # empty need more bytes
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

        hs, ss, fs, ls = self._sizes[hard]
        cs = hs + ss  # both hs and ss
        # assumes that unit tests on Counter and CounterCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and fs = hs + ss and not fs % 4

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise kering.ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        count = b64ToInt(both[hs:hs + ss])  # get count

        self._code = hard
        self._count = count
