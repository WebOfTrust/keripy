# -*- coding: utf-8 -*-
"""
keri.core.indexing module

Provides versioning support for Indexer classes and codes
"""
from collections import namedtuple, deque
from dataclasses import dataclass, astuple, asdict
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import pysodium


from ..kering import (EmptyMaterialError, RawMaterialError, SoftMaterialError,
                      InvalidCodeError, InvalidSoftError,
                      InvalidSizeError,
                      InvalidCodeSizeError, InvalidVarIndexError,
                      InvalidVarSizeError, InvalidVarRawSizeError,
                      ConversionError, InvalidValueError, InvalidTypeError,
                      ValidationError, VersionError, DerivationError,
                      EmptyListError,
                      ShortageError, UnexpectedCodeError, DeserializeError,
                      UnexpectedCountCodeError, UnexpectedOpCodeError)

from ..help import helping
from ..help.helping import (sceil, intToB64, b64ToInt,
                            codeB64ToB2, codeB2ToB64, nabSextets)


@dataclass(frozen=True)
class IndexerCodex:
    """ IndexerCodex is codex hard (stable) part of all indexer derivation codes.

    Codes indicate which list of keys, current and/or prior next, index is for:

        _Sig:           Indices in code may appear in both current signing and
                        prior next key lists when event has both current and prior
                        next key lists. Two character code table has only one index
                        so must be the same for both lists. Other index if for
                        prior next.
                        The indices may be different in those code tables which
                        have two sets of indices.

        _Crt_Sig:       Index in code for current signing key list only.

        _Big_:          Big index values


    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """

    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both lists.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.
    TBD0: str = '0z'  # Test of Var len label L=N*4 <= 4095 char quadlets includes code
    TBD1: str = '1z'  # Test of index sig lead 1
    TBD4: str = '4z'  # Test of index sig lead 1 big

    def __iter__(self):
        return iter(astuple(self))  # enables inclusion test with "in"

IdrDex = IndexerCodex()


@dataclass(frozen=True)
class IndexedSigCodex:
    """IndexedSigCodex is codex all indexed signature derivation codes.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both lists.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.

    def __iter__(self):
        return iter(astuple(self))

IdxSigDex = IndexedSigCodex()  # Make instance


@dataclass(frozen=True)
class IndexedCurrentSigCodex:
    """IndexedCurrentSigCodex is codex indexed signature codes for current list.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Crt_Sig: str = 'B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Crt_Sig: str = 'D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Crt_Sig: str = "F"  # ECDSA secp256r1 sig appears in current list.
    Ed448_Crt_Sig: str = '0B'  # Ed448 signature appears in current list only.
    Ed25519_Big_Crt_Sig: str = '2B'  # Ed25519 sig appears in current list only.
    ECDSA_256k1_Big_Crt_Sig: str = '2D'  # ECDSA secp256k1 sig appears in current list only.
    ECDSA_256r1_Big_Crt_Sig: str = "2F"  # ECDSA secp256r1 sig appears in current list only.
    Ed448_Big_Crt_Sig: str = '3B'  # Ed448 signature appears in current list only.

    def __iter__(self):
        return iter(astuple(self))

IdxCrtSigDex = IndexedCurrentSigCodex()  # Make instance



@dataclass(frozen=True)
class IndexedBothSigCodex:
    """IndexedBothSigCodex is codex indexed signature codes for both lists.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Ed25519_Sig: str = 'A'  # Ed25519 sig appears same in both lists if any.
    ECDSA_256k1_Sig: str = 'C'  # ECDSA secp256k1 sig appears same in both lists if any.
    ECDSA_256r1_Sig: str = "E"  # ECDSA secp256r1 sig appears same in both lists if any.
    Ed448_Sig: str = '0A'  # Ed448 signature appears in both lists.
    Ed25519_Big_Sig: str = '2A'  # Ed25519 sig appears in both listsy.
    ECDSA_256k1_Big_Sig: str = '2C'  # ECDSA secp256k1 sig appears in both lists.
    ECDSA_256r1_Big_Sig: str = "2E"  # ECDSA secp256r1 sig appears in both lists.
    Ed448_Big_Sig: str = '3A'  # Ed448 signature appears in both lists.

    def __iter__(self):
        return iter(astuple(self))

IdxBthSigDex = IndexedBothSigCodex()  # Make instance

# namedtuple for size entries in Incexer derivation code tables
# hs is the hard size int number of chars in hard (stable) part of code
# ss is the soft size int number of chars in soft (unstable) part of code
# os is the other size int number of chars in other index part of soft
# ms = ss - os main index size computed
# fs is the full size int number of chars in code plus appended material if any
# ls is the lead size int number of bytes to pre-pad pre-converted raw binary
Xizage = namedtuple("Xizage", "hs ss os fs ls")

class Indexer:
    """ Indexer is fully qualified cryptographic material primitive base class for
    indexed primitives. In special cases some codes in the Index code table
    may be of variable length (i.e. not indexed) when the full size table entry
    is None. In that case the index is used instread as the length.

    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:

    Properties:
        code is str of stable (hard) part of derivation code
        raw (bytes): unqualified crypto material usable for crypto operations
        index (int): main index offset into list or length of material
        ondex (int | None): other index offset into list or length of material
        qb64b (bytes): fully qualified Base64 crypto material
        qb64 (str | bytes):  fully qualified Base64 crypto material
        qb2 (bytes): fully qualified binary crypto material

    Hidden:
        ._code (str): value for .code property
        ._raw (bytes): value for .raw property
        ._index (int): value for .index property
        ._ondex (int): value for .ondex property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._binfil is method to compute fully qualified Base2 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64
        ._bexfil is method to extract .code and .raw from fully qualified Base2

    """
    # Hards table maps from bytes Base64 first code char to int of hard size, hs,
    # (stable) of code. The soft size, ss, (unstable) is always > 0 for Indexer.
    Hards = ({chr(c): 1 for c in range(65, 65 + 26)})
    Hards.update({chr(c): 1 for c in range(97, 97 + 26)})
    Hards.update([('0', 2), ('1', 2), ('2', 2), ('3', 2), ('4', 2)])
    # Sizes table maps hs chars of code to Xizage namedtuple of (hs, ss, os, fs, ls)
    # where hs is hard size, ss is soft size, os is other index size,
    # and fs is full size, ls is lead size.
    # where ss includes os, so main index size ms = ss - os
    # soft size, ss, should always be  > 0 for Indexer
    Sizes = {
        'A': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'B': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'C': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'D': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'E': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        'F': Xizage(hs=1, ss=1, os=0, fs=88, ls=0),
        '0A': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '0B': Xizage(hs=2, ss=2, os=1, fs=156, ls=0),
        '2A': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2B': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2C': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2D': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2E': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '2F': Xizage(hs=2, ss=4, os=2, fs=92, ls=0),
        '3A': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '3B': Xizage(hs=2, ss=6, os=3, fs=160, ls=0),
        '0z': Xizage(hs=2, ss=2, os=0, fs=None, ls=0),
        '1z': Xizage(hs=2, ss=2, os=1, fs=76, ls=1),
        '4z': Xizage(hs=2, ss=6, os=3, fs=80, ls=1),
    }
    # Bards table maps to hard size, hs, of code from bytes holding sextets
    # converted from first code char. Used for ._bexfil.
    Bards = ({codeB64ToB2(c): hs for c, hs in Hards.items()})

    Codes = asdict(IdrDex)  # map code name to code
    Names = {val : key for key, val in Codes.items()} # invert map code to code name



    def __init__(self, raw=None, code=IdrDex.Ed25519_Sig, index=0, ondex=None,
                 qb64b=None, qb64=None, qb2=None, strip=False, **kwa):
        """
        Validate as fully qualified
        Parameters:
            raw (bytes): unqualified crypto material usable for crypto operations
            code is str of stable (hard) part of derivation code
            index (int): main index offset into list or length of material
            ondex (int | None): other index offset into list or length of material
            qb64b (bytes): fully qualified Base64 crypto material
            qb64 (str | bytes):  fully qualified Base64 crypto material
            qb2 (bytes): fully qualified binary crypto material
            strip (bool): True means strip counter contents from input stream
                bytearray after parsing qb64b or qb2. False means do not strip

        Needs either (raw and code and index) or qb64b or qb64 or qb2
        Otherwise raises EmptyMaterialError
        When raw and code provided then validate that code is correct
        for length of raw  and assign .raw
        Else when qb64b or qb64 or qb2 provided extract and assign
        .raw, .code, .index, .ondex.

        """
        if raw is not None:  # raw provided
            if not code:
                raise EmptyMaterialError("Improper initialization need either "
                                         "(raw and code) or qb64b or qb64 or qb2.")
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError(f"Not a bytes or bytearray, raw={raw}.")

            if code not in self.Sizes:
                raise UnexpectedCodeError(f"Unsupported code={code}.")

            hs, ss, os, fs, ls = self.Sizes[code]  # get sizes for code
            cs = hs + ss  # both hard + soft code size
            ms = ss - os

            if not isinstance(index, int) or index < 0 or index > (64 ** ms - 1):
                raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

            if isinstance(ondex, int) and os and not (ondex >= 0 and ondex <= (64 ** os - 1)):
                raise InvalidVarIndexError(f"Invalid ondex={ondex} for code={code}.")

            if code in IdxCrtSigDex and ondex is not None:
                raise InvalidVarIndexError(f"Non None ondex={ondex} for code={code}.")

            if code in IdxBthSigDex:
                if ondex is None:  # set default
                    ondex = index  # when not provided make ondex match index
                else:
                    if ondex != index and os == 0:  # must match if os == 0
                        raise InvalidVarIndexError(f"Non matching ondex={ondex}"
                                                   f" and index={index} for "
                                                   f"code={code}.")


            if not fs:  # compute fs from index
                if cs % 4:
                    raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                               f"variable length material. cs={cs}.")
                if os != 0:
                    raise InvalidCodeSizeError(f"Non-zero other index size for "
                                               f"variable length material. os={os}.")
                fs = (index * 4) + cs

            rawsize = (fs - cs) * 3 // 4

            raw = raw[:rawsize]  # copy rawsize from stream, may be less
            if len(raw) != rawsize:  # forbids shorter
                raise RawMaterialError(f"Not enougth raw bytes for code={code}"
                                       f"and index={index} ,expected {rawsize} "
                                       f"got {len(raw)}.")

            self._code = code
            self._index = index
            self._ondex = ondex
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64b is not None:
            self._exfil(qb64b)
            if strip:  # assumes bytearray
                del qb64b[:len(self.qb64b)]  # may be variable length fs

        elif qb64 is not None:
            self._exfil(qb64)

        elif qb2 is not None:
            self._bexfil(qb2)
            if strip:  # assumes bytearray
                del qb2[:len(self.qb2)]  # may be variable length fs

        else:
            raise EmptyMaterialError("Improper initialization need either "
                                     "(raw and code and index) or qb64b or "
                                     "qb64 or qb2.")

    @classmethod
    def _rawSize(cls, code):
        """
        Returns expected raw size in bytes for a given code. Not applicable to
        codes with fs = None
        """
        hs, ss, os, fs, ls = cls.Sizes[code]  # get sizes
        return ((fs - (hs + ss)) * 3 // 4)

    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code


    @property
    def name(self):
        """
        Returns:
            name (str): code name for self.code. Used for annotation for
            primitives like Matter

        """
        return self.Names[self.code]

    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw

    @property
    def index(self):
        """
        Returns ._index
        Makes .index read only
        """
        return self._index

    @property
    def ondex(self):
        """
        Returns ._ondex
        Makes .ondex read only
        """
        return self._ondex

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

    def _infil(self):
        """
        Returns fully qualified attached sig base64 bytes computed from
        self.raw, self.code and self.index.

        cs = hs + ss
        os = ss - ms (main index size)
        when fs None then size computed & fs = size * 4 + cs

        """
        code = self.code  # codex value chars hard code
        index = self.index  # main index value
        ondex = self.ondex  # other index value
        raw = self.raw  # bytes or bytearray

        ps = (3 - (len(raw) % 3)) % 3  # if lead then same pad size chars & lead size bytes
        hs, ss, os, fs, ls = self.Sizes[code]
        cs = hs + ss
        ms = ss - os

        if not fs:  # compute fs from index
            if cs % 4:
                raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                           f"variable length material. cs={cs}.")
            if os != 0:
                raise InvalidCodeSizeError(f"Non-zero other index size for "
                                           f"variable length material. os={os}.")
            fs = (index * 4) + cs

        if index < 0 or index > (64 ** ms - 1):
            raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

        if (isinstance(ondex, int) and os and
                not (ondex >= 0 and ondex <= (64 ** os - 1))):
            raise InvalidVarIndexError(f"Invalid ondex={ondex} for os={os} and "
                                       f"code={code}.")

        # both is hard code + converted index + converted ondex
        both = (f"{code}{intToB64(index, l=ms)}"
                f"{intToB64(ondex if ondex is not None else 0, l=os)}")

        # check valid pad size for whole code size, assumes ls is zero
        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        if (cs % 4) != ps - ls:  # adjusted pad given lead bytes
            raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                       f" raw pad size={ps}.")

        # prepend pad bytes, convert, then replace pad chars with full derivation
        # code including index,
        full = both.encode("utf-8") + encodeB64(bytes([0] * ps) + raw)[ps - ls:]

        if len(full) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid code={both} for raw size={len(raw)}.")

        return full


    def _binfil(self):
        """
        Returns bytes of fully qualified base2 bytes, that is .qb2
        self.code and self.index  converted to Base2 + self.raw left shifted
        with pad bits equivalent of Base64 decode of .qb64 into .qb2
        """
        code = self.code  # codex chars hard code
        index = self.index  # main index value
        ondex = self.ondex  # other index value
        raw = self.raw  # bytes or bytearray

        ps = (3 - (len(raw) % 3)) % 3  # same pad size chars & lead size bytes
        hs, ss, os, fs, ls = self.Sizes[code]
        cs = hs + ss
        ms = ss - os

        if index < 0 or index > (64 ** ss - 1):
            raise InvalidVarIndexError(f"Invalid index={index} for code={code}.")

        if (isinstance(ondex, int) and os and
                not (ondex >= 0 and ondex <= (64 ** os - 1))):
            raise InvalidVarIndexError(f"Invalid ondex={ondex} for os={os} and "
                                       f"code={code}.")

        if not fs:  # compute fs from index
            if cs % 4:
                raise InvalidCodeSizeError(f"Whole code size not multiple of 4 for "
                                           f"variable length material. cs={cs}.")
            if os != 0:
                raise InvalidCodeSizeError(f"Non-zero other index size for "
                                           f"variable length material. os={os}.")
            fs = (index * 4) + cs

        # both is hard code + converted index
        both = (f"{code}{intToB64(index, l=ms)}"
                f"{intToB64(ondex if ondex is not None else 0, l=os)}")

        if len(both) != cs:
            raise InvalidCodeSizeError("Mismatch code size = {} with table = {}."
                                       .format(cs, len(both)))

        if (cs % 4) != ps - ls:  # adjusted pad given lead bytes
                    raise InvalidCodeSizeError(f"Invalid code={both} for converted"
                                               f" raw pad size={ps}.")

        n = sceil(cs * 3 / 4)  # number of b2 bytes to hold b64 code + index
        # convert code both to right align b2 int then left shift in pad bits
        # then convert to bytes
        bcode = (b64ToInt(both) << (2 * (ps - ls))).to_bytes(n, 'big')
        full = bcode + bytes([0] * ls) + raw

        bfs = len(full)  # binary full size
        if bfs % 3 or (bfs * 4 // 3) != fs:  # invalid size
            raise InvalidCodeSizeError(f"Invalid code={both} for raw size={len(raw)}.")

        return full


    def _exfil(self, qb64b):
        """
        Extracts self.code, self.index, and self.raw from qualified base64 bytes qb64b

        cs = hs + ss
        ms = ss - os (main index size)
        when fs None then size computed & fs = size * 4 + cs
        """
        if not qb64b:  # empty need more bytes
            raise ShortageError("Empty material.")

        first = qb64b[:1]  # extract first char code selector
        if hasattr(first, "decode"):
            first = first.decode("utf-8")
        if first not in self.Hards:
            if first[0] == '-':
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Indexer.")
            elif first[0] == '_':
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Indexer.")
            else:
                raise UnexpectedCodeError(f"Unsupported code start char={first}.")

        hs = self.Hards[first]  # get hard code size
        if len(qb64b) < hs:  # need more bytes
            raise ShortageError(f"Need {hs - len(qb64b)} more characters.")

        hard = qb64b[:hs]  # get hard code
        if hasattr(hard, "decode"):
            hard = hard.decode("utf-8")
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, os, fs, ls = self.Sizes[hard]  # assumes hs in both tables consistent
        cs = hs + ss  # both hard + soft code size
        ms = ss - os
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)
        # assumes no variable length indexed codes so fs is not None

        if len(qb64b) < cs:  # need more bytes
            raise ShortageError(f"Need {cs - len(qb64b)} more characters.")

        index = qb64b[hs:hs+ms]  # extract index/size chars
        if hasattr(index, "decode"):
            index = index.decode("utf-8")
        index = b64ToInt(index)  # compute int index

        ondex = qb64b[hs+ms:hs+ms+os]  # extract ondex chars
        if hasattr(ondex, "decode"):
            ondex = ondex.decode("utf-8")

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            ondex = b64ToInt(ondex) if os else None  # compute ondex from code
            if ondex:  # not zero or None so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:
                ondex = None  # zero so set to None when current only
        else:
            ondex = b64ToInt(ondex) if os else index

        # index is index for some codes and variable length for others
        if not fs:  # compute fs from index which means variable length
            if cs % 4:
                raise ValidationError(f"Whole code size not multiple of 4 for "
                                      f"variable length material. cs={cs}.")
            if os != 0:
                raise ValidationError(f"Non-zero other index size for "
                                      f"variable length material. os={os}.")
            fs = (index * 4) + cs

        if len(qb64b) < fs:  # need more bytes
            raise ShortageError(f"Need {fs - len(qb64b)} more chars.")

        qb64b = qb64b[:fs]  # fully qualified primitive code plus material
        if hasattr(qb64b, "encode"):  # only convert extracted chars from stream
            qb64b = qb64b.encode("utf-8")

        # strip off prepended code and append pad characters
        #ps = cs % 4  # pad size ps = cs mod 4, same pad chars and lead bytes
        #base = ps * b'A' + qb64b[cs:]  # replace prepend code with prepad zeros
        #raw = decodeB64(base)[ps+ls:]  # decode and strip off ps+ls prepad bytes

        # check for non-zeroed pad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            base = ps * b'A' + qb64b[cs:]  # replace pre code with prepad chars of zero
            paw = decodeB64(base)  # decode base to leave prepadded raw
            pi = (int.from_bytes(paw[:ps], "big"))  # prepad as int
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed prepad bits = "
                                 f"{pi & (2 ** pbs - 1 ):<06b} in {qb64b[cs:cs+1]}.")
            raw = paw[ps:]  # strip off ps prepad paw bytes
        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            base = qb64b[cs:]  # strip off code leaving lead chars if any and value
            # decode lead chars + val leaving lead bytes + raw bytes
            # then strip off ls lead bytes leaving raw
            paw = decodeB64(base) # decode base to leave prepadded paw bytes
            li = int.from_bytes(paw[:ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:04x}.")

            raw = paw[ls:]

        if len(raw) != (len(qb64b) - cs) * 3 // 4:  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb64b}")

        self._code = hard
        self._index = index
        self._ondex = ondex
        self._raw = raw  # must be bytes for crpto opts and immutable not bytearray



    def _bexfil(self, qb2):
        """
        Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2

        cs = hs + ss
        ms = ss - os (main index size)
        when fs None then size computed & fs = size * 4 + cs
        """
        if not qb2:  # empty need more bytes
            raise ShortageError("Empty material, Need more bytes.")

        first = nabSextets(qb2, 1)  # extract first sextet as code selector
        if first not in self.Bards:
            if first[0] == b'\xf8':  # b64ToB2('-')
                raise UnexpectedCountCodeError("Unexpected count code start"
                                               "while extracing Matter.")
            elif first[0] == b'\xfc':  # b64ToB2('_')
                raise UnexpectedOpCodeError("Unexpected  op code start"
                                            "while extracing Matter.")
            else:
                raise UnexpectedCodeError(f"Unsupported code start sextet={first}.")

        hs = self.Bards[first]  # get code hard size equvalent sextets
        bhs = sceil(hs * 3 / 4)  # bhs is min bytes to hold hs sextets
        if len(qb2) < bhs:  # need more bytes
            raise ShortageError(f"Need {bhs - len(qb2)} more bytes.")

        hard = codeB2ToB64(qb2, hs)  # extract and convert hard part of code
        if hard not in self.Sizes:
            raise UnexpectedCodeError(f"Unsupported code ={hard}.")

        hs, ss, os, fs, ls = self.Sizes[hard]
        cs = hs + ss  # both hs and ss
        ms = ss - os
        # assumes that unit tests on Indexer and IndexerCodex ensure that
        # .Codes and .Sizes are well formed.
        # hs consistent and hs > 0 and ss > 0 and (fs >= hs + ss if fs is not None else True)

        bcs = sceil(cs * 3 / 4)  # bcs is min bytes to hold cs sextets
        if len(qb2) < bcs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bcs - len(qb2)))

        both = codeB2ToB64(qb2, cs)  # extract and convert both hard and soft part of code
        index = b64ToInt(both[hs:hs+ms])  # compute index

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            ondex = b64ToInt(both[hs+ms:hs+ms+os]) if os else None  # compute ondex from code
            if ondex:  # not zero or None so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:
                ondex = None  # zero so set to None when current only
        else:
            ondex = b64ToInt(both[hs+ms:hs+ms+os]) if os else index

        if hard in IdxCrtSigDex:  # if current sig then ondex from code must be 0
            if ondex:  # not zero so error
                raise ValueError(f"Invalid ondex={ondex} for code={hard}.")
            else:  # zero so set to None
                ondex = None

        if not fs:  # compute fs from size chars in ss part of code
            if cs % 4:
                raise ValidationError(f"Whole code size not multiple of 4 for "
                                      f"variable length material. cs={cs}.")
            if os != 0:
                raise ValidationError(f"Non-zero other index size for "
                                      f"variable length material. os={os}.")
            fs = (index * 4) + cs

        bfs = sceil(fs * 3 / 4)  # bfs is min bytes to hold fs sextets
        if len(qb2) < bfs:  # need more bytes
            raise ShortageError("Need {} more bytes.".format(bfs - len(qb2)))

        qb2 = qb2[:bfs]  # extract qb2 fully qualified primitive code plus material

        # check for non-zeroed prepad bits or lead bytes
        ps = cs % 4  # code pad size ps = cs mod 4
        pbs = 2 * (ps if ps else ls)  # pad bit size in bits
        if ps:  # ps. IF ps THEN not ls (lead) and vice versa OR not ps and not ls
            # convert last byte of code bytes in which are pad bits to int
            pi = (int.from_bytes(qb2[bcs-1:bcs], "big"))
            if pi & (2 ** pbs - 1 ):  # masked pad bits non-zero
                raise ValueError(f"Non zeroed pad bits = "
                                 f"{pi & (2 ** pbs - 1 ):>08b} in 0x{pi:02x}.")
        else:  # not ps. IF not ps THEN may or may not be ls (lead)
            li = int.from_bytes(qb2[bcs:bcs+ls], "big")  # lead as int
            if li:  # pre pad lead bytes must be zero
                if ls == 1:
                    raise ValueError(f"Non zeroed lead byte = 0x{li:02x}.")
                else:
                    raise ValueError(f"Non zeroed lead bytes = 0x{li:02x}.")


        raw = qb2[(bcs + ls):]  # strip code and leader bytes from qb2 to get raw

        if len(raw) != (len(qb2) - bcs - ls):  # exact lengths
            raise ConversionError(f"Improperly qualified material = {qb2}")

        self._code = hard
        self._index = index
        self._ondex = ondex
        self._raw = bytes(raw)  # must be bytes for crypto ops and not bytearray mutable


class Siger(Indexer):
    """
    Siger is subclass of Indexer, indexed signature material,

    Adds .verfer property which is instance of Verfer that provides
          associated signature verifier.

    See Indexer for inherited attributes and properties:

    Attributes:

    Properties:
        verfer (Verfer): instance if any provides public verification key

    Methods:

    Hidden:
        _verfer (Verfer): value for .verfer property


    """

    def __init__(self, verfer=None, **kwa):
        """Initialze instance

        Parameters:  See Matter for inherted parameters
            verfer (Verfer): instance if any provides public verification key

        """
        super(Siger, self).__init__(**kwa)
        if self.code not in IdxSigDex:
            raise ValidationError("Invalid code = {} for Siger."
                                  "".format(self.code))
        self.verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    @verfer.setter
    def verfer(self, verfer):
        """ verfer property setter """
        self._verfer = verfer


