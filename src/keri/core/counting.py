# -*- encoding: utf-8 -*-
"""
keri.core.counting module

Provides versioning support for Counter classes and codes
"""

from dataclasses import dataclass, astuple


from ..help import helping
from ..help.helping import sceil
from ..help.helping import (intToB64,  b64ToInt, codeB64ToB2, codeB2ToB64,
                            nabSextets)

from .. import kering

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
class CounterCodex:
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
    SadPathSig: str = '-J'  # Composed Base64 Group path+TransIdxSigGroup of SAID of content
    SadPathSigGroup: str = '-K'  # Composed Base64 Group, root(path)+SaidPathCouples
    PathedMaterialQuadlets: str = '-L'  # Composed Grouped Pathed Material Quadlet (4 char each)
    AttachedMaterialQuadlets: str = '-V'  # Composed Grouped Attached Material Quadlet (4 char each)
    BigAttachedMaterialQuadlets: str = '-0V'  # Composed Grouped Attached Material Quadlet (4 char each)
    KERIProtocolStack: str = '--AAA'  # KERI ACDC Protocol Stack CESR Version

    def __iter__(self):
        return iter(astuple(self))  # enables value not key inclusion test with "in"

CtrDex = CounterCodex()


@dataclass(frozen=True)
class GenusCodex:
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


"""
Design Notes

Need sizes by version can assume only support KERI/ACDC Genus so do not
need to support different protocol genera in Counting
Hards and Bards are the same for both versions

Need to pass in version so Counter Instance knows what version to use
simpler than Serder since version is not provided in version string
Each instance when created needs to get its version at init

So Sizes in dictionary indexed by version.

CtrDex Codex itself is not referenced inside Counter but by external classes
making instances so use CtrDex to pass in code.  So we need versioned codex

one option is to have different dataclasses with each version codex and then
have dictionary Codex of those indexed by version as class variable.

Another option is to have code name index that is indexed by version
so the actual code is looked up for the version instead of passing in the code
itself which requires dereferencing with the version so the version gets used
twice.  Also need to reverse code and version to get codename as property

codename = label or tag.  use tag for code tag


Counter(codename=, verion=)

When using code not tag then must check against version to make sure code is
a valid code for version.  Likewise a tag may not have a code for a given version

So tags are strings that can be attribute names for dataclasses
Tags is namedtuple where each attribute value is its key so one can look up the
string by the tag

But given string value for tag then to lookup code in codex need to to use
builtin getattr

Instead maybe we just extend the codex dataclass with .__getitem__ .__setitem__ and .__delitem__ methods
so we can access a code by its tag using Codex[tag]


"""

class Counter:
    """
    Counter is fully qualified cryptographic material primitive base class for
    counter primitives (framing composition grouping count codes).

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .pad  is int number of pad chars given raw
        .count is int count of grouped following material (not part of counter)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material

    Hidden:
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._pad is method to compute  .pad property
        ._count is int value for .count property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
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
    }

    Codex = CtrDex


    def __init__(self, code=None, count=None, countB64=None,
                 qb64b=None, qb64=None, qb2=None, strip=False):
        """
        Validate as fully qualified
        Parameters:
            code (str | None):  stable (hard) part of derivation code
            count (int | None): count for composition.
                Count may represent quadlets/triplet, groups, primitives or
                other numericy
                When both count and countB64 are None then count defaults to 1
            countB64 (str | None): count for composition as Base64
                countB64 may represent quadlets/triplet, groups, primitives or
                other numericy
            qb64b (bytes | bytearray | None): fully qualified crypto material text domain
            qb64 (str | None) fully qualified crypto material text domain
            qb2 (bytes | bytearray | None)  fully qualified crypto material binary domain
            strip (bool):  True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip.
                default False


        Needs either code or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When code and count provided then validate that code and count are correct
        Else when qb64b or qb64 or qb2 provided extract and assign
        .code and .count

        """
        if code is not None:  # code provided
            if code not in self.Sizes:
                raise kering.InvalidCodeError("Unsupported code={}.".format(code))

            hs, ss, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            if fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
                raise kering.InvalidCodeSizeError("Whole code size not full size or not "
                                           "multiple of 4. cs={} fs={}.".format(cs, fs))

            if count is None:
                count = 1 if countB64 is None else b64ToInt(countB64)

            if count < 0 or count > (64 ** ss - 1):
                raise kering.InvalidVarIndexError("Invalid count={} for code={}.".format(count, code))

            self._code = code
            self._count = count

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:self.Sizes[self.code].fs]

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:  # rewrite to use direct binary exfiltration
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:self.Sizes[self.code].fs * 3 // 4]

        else:
            raise kering.EmptyMaterialError("Improper initialization need either "
                                     "(code and count) or qb64b or "
                                     "qb64 or qb2.")

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
            _, ss, _, _ = self.Sizes[self.code]
            l = ss
        return (intToB64(self.count, l=l))


    @staticmethod
    def semVerToB64(version="", major=0, minor=0, patch=0):
        """ Converts semantic version to Base64 representation of countB64
        suitable for CESR protocol genus and version

        Returns:
            countB64 (str): suitable for input to Counter
            example: Counter(countB64=semVerToB64(version = "1.0.0"))

        Parameters:
            version (str | None): dot separated semantic version string of format
                "major.minor.patch"
            major (int): When version is None or empty then use major,minor, patch
            minor (int): When version is None or empty then use major,minor, patch
            patch (int): When version is None or empty then use major,minor, patch

        each of major, minor, patch must be in range [0,63] for represenation as
        three Base64 characters

        """
        parts = [major, minor, patch]
        if version:
            splits = version.split(".", maxsplit=3)
            splits = [(int(s) if s else 0) for s in splits]
            for i in range(3-len(splits),0, -1):
                splits.append(parts[-i])
            parts = splits

        for p in parts:
            if p < 0 or p > 63:
                raise ValueError(f"Out of bounds semantic version. "
                                 f"Part={p} is < 0 or > 63.")
        return ("".join(intToB64(p, l=1) for p in parts))


    def _infil(self):
        """
        Returns fully qualified attached sig base64 bytes computed from
        self.code and self.count.
        """
        code = self.code  # codex value chars hard code
        count = self.count  # index value int used for soft

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss  # both hard + soft size
        if fs != cs or cs % 4:  # fs must be bs and multiple of 4 for count codes
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

        hs, ss, fs, ls = self.Sizes[code]
        cs = hs + ss
        if fs != cs or cs % 4:  # fs must be cs and multiple of 4 for count codes
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
        if hard not in self.Sizes:  # Sizes needs str not bytes
            raise kering.UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]  # assumes hs consistent in both tables
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
        if hard not in self.Sizes:
            raise kering.UnexpectedCodeError("Unsupported code ={}.".format(hard))

        hs, ss, fs, ls = self.Sizes[hard]
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

