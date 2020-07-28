# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""
import re
import json

from dataclasses import dataclass, astuple
from collections import namedtuple
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64

import cbor2 as cbor
import msgpack
import pysodium
import blake3

from ..kering import ValidationError, VersionError, EmptyMaterialError, DerivationError
from ..kering import Versionage, Version

Serialage = namedtuple("Serialage", 'json mgpk cbor')

Serials = Serialage(json='JSON', mgpk='MGPK', cbor='CBOR')

Mimes = Serialage(json='application/keri+json',
                  mgpk='application/keri+msgpack',
                  cbor='application/keri+cbor',)

VERRAWSIZE = 6  # hex characters in raw serialization size in version string
# "{:0{}x}".format(300, 6)  # make num char in hex a variable
# '00012c'
VERFMT = "KERI{:x}{:x}{}{:0{}x}_"  #  version format string

def Versify(version=None, kind=Serials.json, size=0):
    """
    Return version string
    """
    if kind not in Serials:
        raise  ValueError("Invalid serialization kind = {}".format(kind))
    version = version if version else Version
    return VERFMT.format(version[0], version[1], kind, size, VERRAWSIZE)

Vstrings = Serialage(json=Versify(kind=Serials.json, size=0),
                     mgpk=Versify(kind=Serials.mgpk, size=0),
                     cbor=Versify(kind=Serials.cbor, size=0))


VEREX = b'KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_'
Rever = re.compile(VEREX) #compile is faster

def Deversify(vs):
    """
    Returns tuple(kind, version, size)
      Where:
        kind is serialization kind, one of Serials
                   json='JSON', mgpk='MGPK', cbor='CBOR'
        version is version tuple of type Version
        size is int of raw size

    Parameters:
      vs is version string str

    Uses regex match to extract:
        serialization kind
        keri version
        serialization size
    """
    match = Rever.match(vs.encode("utf-8"))  #  match takes bytes
    if match:
        major, minor, kind, size = match.group("major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return(kind, version, size)

    raise ValueError("Invalid version string = {}".format(vs))

Ilkage = namedtuple("Ilkage", 'icp rot ixn dip drt')  # Event ilk (type of event)

Ilks = Ilkage(icp='icp', rot='rot', ixn='ixn', dip='dip', drt='drt')

@dataclass(frozen=True)
class CrySelectCodex:
    """
    Select codex of selector characters for cyptographic material
    Only provide defined characters.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    two:  str = '0'  # use two character table.
    four: str = '1'  # use four character table.

    def __iter__(self):
        return iter(astuple(self))

CrySelect = CrySelectCodex()  # Make instance

@dataclass(frozen=True)
class CryOneCodex:
    """
    CryOneCodex is codex of one character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryOneCodex results in 1 Base64 pad byte.
    """
    Ed25519_Seed:         str = 'A'  #  Ed25519 256 bit random seed for private key
    Ed25519N:             str = 'B'  #  Ed25519 verification key non-transferable, basic derivation.
    X25519:               str = 'C'  #  X25519 public encryption key, converted from Ed25519.
    Ed25519:              str = 'D'  #  Ed25519 verification key basic derivation
    Blake3_256:           str = 'E'  #  Blake3 256 bit digest self-addressing derivation.
    Blake2b_256:          str = 'F'  #  Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256:          str = 'G'  #  Blake2s 256 bit digest self-addressing derivation.
    SHA3_256:             str = 'H'  #  SHA3 256 bit digest self-addressing derivation.
    SHA2_256:             str = 'I'  #  SHA2 256 bit digest self-addressing derivation.
    ECDSA_secp256k1_Seed: str = 'J'  #  ECDSA secp256k1 448 bit random Seed for private key
    Ed448_Seed:           str = 'K'  #  Ed448 448 bit random Seed for private key
    X448:                 str = 'L'  #  X448 public encryption key, converted from Ed448


    def __iter__(self):
        return iter(astuple(self))

CryOne = CryOneCodex()  # Make instance

# Mapping of Code to Size
CryOneSizes = {
               "A": 44, "B": 44, "C": 44, "D": 44, "E": 44, "F": 44,
               "G": 44, "H": 44, "I": 44, "J": 44, "K": 76, "L": 76,
              }

# Mapping of Code to Size
CryOneRawSizes = {
               "A": 32, "B": 32, "C": 32, "D": 32, "E": 32, "F": 32,
               "G": 32, "H": 32, "I": 32, "J": 32, "K": 56, "L": 56,
              }


@dataclass(frozen=True)
class CryTwoCodex:
    """
    CryTwoCodex is codex of two character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryTwoCodex results in 2 Base64 pad bytes.
    """
    Seed_128:    str = '0A'  # 128 bit random seed.
    Ed25519:     str = '0B'  # Ed25519 signature.
    ECDSA_256k1: str = '0C'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

CryTwo = CryTwoCodex()  #  Make instance

# Mapping of Code to Size
CryTwoSizes = {
               "0A": 24,
               "0B": 88,
               "0B": 88,
              }

CryTwoRawSizes = {
                  "0A": 16,
                  "0B": 64,
                  "0B": 64,
                 }

@dataclass(frozen=True)
class CryFourCodex:
    """
    CryFourCodex codex of four character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in CryFourCodex results in 0 Base64 pad bytes.
    """
    ECDSA_256k1N:  str = "1AAA"  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1:   str = "1AAB"  # Ed25519 public verification or encryption key, basic derivation

    def __iter__(self):
        return iter(astuple(self))

CryFour = CryFourCodex()  #  Make instance

# Mapping of Code to Size
CryFourSizes = {
                "1AAA": 48,
                "1AAB": 48,
               }

CryFourRawSizes = {
                   "1AAA": 33,
                   "1AAB": 33,
                  }

# all sizes in one dict
CrySizes = dict(CryOneSizes)
CrySizes.update(CryTwoSizes)
CrySizes.update(CryFourSizes)

# all sizes in one dict
CryRawSizes = dict(CryOneRawSizes)
CryRawSizes.update(CryTwoRawSizes)
CryRawSizes.update(CryFourRawSizes)


class CryMat:
    """
    CryMat is fully qualified cryptographic material base class
    Sub classes are derivation code and key event element context specific.

    Includes the following attributes and properties:

    Attributes:


    Properties:
        .code  str derivation code to indicate cypher suite
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given raw
        .qb64 str in Base64 with derivation code and crypto material
        .qb2  bytes in binary with derivation code and crypto material

    """

    def __init__(self, raw=b'', qb64='', qb2='', code=CryOne.Ed25519N):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code

        When raw provided then validate that code is correct for length of raw
            and assign .raw
        Else when qb64 or qb2 provided extract and assign .raw and .code

        """
        if raw:  #  raw provided so infil with code
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))
            pad = self._pad(raw)
            if (not ( (pad == 1 and (code in CryOne)) or  # One or Five or Nine
                      (pad == 2 and (code in CryTwo)) or  # Two or Six or Ten
                      (pad == 0 and (code in CryFour)) )):  #  Four or Eight

                raise ValidationError("Wrong code={} for raw={}.".format(code, raw))

            raw = raw[:CryRawSizes[code]]  #  allows longer by truncating if stream
            if len(raw) != CryRawSizes[code]:  # forbids shorter
                raise ValidationError("Unexpected raw size={} for code={}"
                                      " not size={}.".format(len(raw),
                                                             code,
                                                             CryRawSizes[code]))

            self._code = code
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64:
            if hasattr(qb64, "decode"):  # converts bytes like to str
                qb64 = qb64.decode("utf-8")
            self._exfil(qb64)

        elif qb2:  # rewrite to use direct binary exfiltration
            self._exfil(encodeB64(qb2).decode("utf-8"))

        else:
            raise EmptyMaterialError("Improper initialization need raw or b64 or b2.")


    @staticmethod
    def _pad(raw):
        """
        Returns number of pad characters that would result from converting raw
        to Base64 encoding
        raw is bytes or bytearray
        """
        m = len(raw) % 3
        return (3 - m if m else 0)


    @property
    def pad(self):
        """
        Returns number of pad characters that would result from converting
        self.raw to Base64 encoding
        self.raw is raw is bytes or bytearray
        """
        return self._pad(self._raw)

    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code

    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw

    def _infil(self):
        """
        Returns fully qualified base64 given self.pad, self.code and self.raw
        code is Codex value
        raw is bytes or bytearray
        """
        pad = self.pad
        # valid pad for code length
        if len(self._code) % 4 != pad:  # pad is not remainder of len(code) % 4
            raise ValidationError("Invalid code = {} for converted raw pad = {}."
                                  .format(self._code, self.pad))
        # prepending derivation code and strip off trailing pad characters
        return (self._code + encodeB64(self._raw).decode("utf-8")[:-pad])


    def _exfil(self, qb64):
        """
        Extracts self.code and self.raw from qualified base64 qb64
        """
        pre = 1
        code = qb64[:pre]

        # need to map code to length so can only consume proper number of chars
        #  from front of qb64 so can use with full identifiers not just id prefixes

        if code in CryOne:  # One Char code
            qb64 = qb64[:CryOneSizes[code]]  # strip of identifier after prefix

        elif code == CrySelect.two: # first char of two char code
            pre += 1
            code = qb64[pre-2:pre]  #  get full code
            if code not in CryTwo:
                raise ValidationError("Invalid derivation code = {} in {}.".format(code, qb64))
            qb64 = qb64[:CryTwoSizes[code]]  # strip of identifier after prefix

        else:
            raise ValueError("Improperly coded material = {}".format(qb64))

        if len(qb64) != CrySizes[code]:  # forbids shorter
            raise ValidationError("Unexpected qb64 size={} for code={}"
                                  " not size={}.".format(len(qb64),
                                                         code,
                                                         CrySizes[code]))

        pad = pre % 4  # pad is remainder pre mod 4
        # strip off prepended code and append pad characters
        base = qb64[pre:] + pad * BASE64_PAD
        raw = decodeB64(base.encode("utf-8"))

        if len(raw) != (len(qb64) - pre) * 3 // 4:  # exact lengths
            raise ValueError("Improperly qualified material = {}".format(qb64))

        self._code = code
        self._raw = raw

    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64.encode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version Bytes
        redo to use b64 to binary decode table since faster
        """
        # rewrite to do direct binary infiltration by
        # decode self.code as bits and prepend to self.raw
        return decodeB64(self._infil().encode("utf-8"))


class Verifier(CryMat):
    """
    Verifier is CryMat subclass with method to verify signature of serialization
    using the .raw as verifier key and .code for signature cipher suite.

    See CryMat for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify: verifies signature

    """
    def __init__(self, **kwa):
        """
        Assign verification cipher suite function to ._verify

        """
        super(Verifier, self).__init__(**kwa)

        if self.code in [CryOne.Ed25519N, CryOne.Ed25519]:
            self._verify = self._ed25519
        else:
            raise ValueError("Unsupported code = {} for verifier.".format(self.code))


    def verify(self, sig, ser):
        """
        Returns True if bytes signature sig verifies on bytes serialization ser
        using .raw as verifier public key for ._verify cipher suite determined
        by .code

        Parameters:
            sig is bytes signature
            ser is bytes serialization
        """
        return (self._verify(sig=sig, ser=ser, key=self.raw))

    @staticmethod
    def _ed25519(sig, ser, key):
        """
        Returns True if verified False otherwise
        Verifiy ed25519 sig on ser using key

        Parameters:
            sig is bytes signature
            ser is bytes serialization
            key is bytes public key
        """
        try:  # verify returns None if valid else raises ValueError
            result = pysodium.crypto_sign_verify_detached(sig, ser, key)
        except Exception as ex:
            return False

        return True


class Signer(CryMat):
    """
    Signer is CryMat subclass with method to create signature of serialization
    using the .raw as signing (private) key seed, .code as cipher suite for
    signing and new property .verifier whose property verifier.raw
    is public key for signing.
    If not provided .verifier is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See CryMat for inherited attributes and properties:

    Attributes:

    Properties:
        .verifier is Verifier object instance

    Methods:
        sign: create signature

    """
    def __init__(self,raw=b'', code=CryOne.Ed25519_Seed, transferable=True, **kwa):
        """
        Assign signing cipher suite function to ._sign

        Parameters:  See CryMat for inherted parameters
            raw is bytes crypto material seed or private key
            code is derivation code
            transferable is Boolean True means verifier code is transferable
                                    False othersize non-transerable

        """
        try:
            super(Signer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == CryOne.Ed25519_Seed:
                raw = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
                super(Signer, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise ValueError("Unsupported signer code = {}.".format(code))

        if self.code == CryOne.Ed25519_Seed:
            self._sign = self._ed25519
            verkey, sigkey = pysodium.crypto_sign_seed_keypair(self.raw)
            verifier = Verifier(raw=verkey,
                                code=CryOne.Ed25519 if transferable
                                                    else CryOne.Ed25519N )
        else:
            raise ValueError("Unsupported signer code = {}.".format(self.code))

        self._verifier = verifier

    @property
    def verifier(self):
        """
        Property verifier:
        Returns Verifier instance
        Assumes ._verifier is correctly assigned
        """
        return self._verifier

    def sign(self, ser, index=None):
        """
        Returns either CryMat or SigMat instance of signature
        on bytes serialization ser

        If index is None return CryMat instance
        Otherwise return Sigmat instance

        Parameters:
            ser is bytes serialization
            index is
        """
        return (self._sign(ser=ser,
                           seed=self.raw,
                           key=self.verifier.raw,
                           index=index))

    @staticmethod
    def _ed25519(ser, seed, key, index):
        """
        Returns signature


        Parameters:
            ser is bytes serialization
            seed is bytes seed (private key)
            key is bytes public key
            index is index of offset into signers list or None

        """
        sig = pysodium.crypto_sign_detached(ser, seed + key)
        if index is None:
            return CryMat(raw=sig, code=CryTwo.Ed25519)
        else:
            return SigMat(raw=sig, code=SigTwo.Ed25519, index=index)


class Digester(CryMat):
    """
    Digester is CryMat subclass with method to verify digest of serialization
    using  .raw as digest and .code for digest algorithm.

    See CryMat for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify: verifies signature

    """
    def __init__(self, raw=b'', ser=b'', code=CryOne.Blake3_256, **kwa):
        """
        Assign digest verification function to ._verify

        See CryMat for inherited parameters

        Parameters:
           ser is bytes serialization from which raw is computed if not raw

        """
        try:
            super(Digester, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ser:
                raise ex
            if code == CryOne.Blake3_256:
                dig = blake3.blake3(ser).digest()
                super(Digester, self).__init__(raw=dig, code=code, **kwa)
            else:
                raise ValueError("Unsupported code = {} for digester.".format(code))

        if self.code == CryOne.Blake3_256:
            self._verify = self._blake3_256
        else:
            raise ValueError("Unsupported code = {} for digester.".format(self.code))


    def verify(self, ser):
        """
        Returns True if digest of bytes serialization ser matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code

        Parameters:
            ser is bytes serialization
        """
        return (self._verify(ser=ser, dig=self.raw))

    @staticmethod
    def _blake3_256(ser, dig):
        """
        Returns True if verified False otherwise
        Verifiy blake3_256 digest of ser matches dig

        Parameters:
            ser is bytes serialization
            dig is bytes reference digest
        """
        return(blake3.blake3(ser).digest() == dig)


class Nexter(Digester):
    """
    Nexter is Digester subclass with support to create itself from
    next sith and next keys

    See Digester for inherited attributes and properties:

    Attributes:

    Properties:

    Methods:


    """
    def __init__(self, ser=b'', sith=None, keys=None, ked=None, **kwa):
        """
        Assign digest verification function to ._verify

        See CryMat for inherited parameters

        Parameters:
           ser is bytes serialization from which raw is computed if not raw
           sith is int threshorld or lowercase hex str no leading zeros
           keys is list of keys each is qb64 public key str

        """
        try:
            super(Nexter, self).__init__(ser=ser, **kwa)
        except EmptyMaterialError as ex:
            if not (sith and keys) and not ked:
                raise ex
            ser = self._derive(sith=sith, keys=keys, ked=ked)
            super(Nexter, self).__init__(ser=ser, **kwa)


    @staticmethod
    def _derive(sith=None, keys=None, ked=None):
        """
        Returns serialization derived from sith, keys, or ked
        """
        if not (sith and keys):
            try:
                sith = ked["sith"]
                keys = ked["keys"]
            except Exception as ex:
                raise DerivationError("Error extracting sith and keys from"
                                      " ked = {}".format(ex))

        if not keys:
            raise DerivationError("Empty keys.")

        if isinstance(sith, list):
            # verify list expression against keys
            # serialize list here
            raise DerivationError("List form of sith = {} not yet supported".format(sith))
        else:
            if not isinstance(sith, (str)):
                sith = "{:x}".format(sith)  # lowecase hex no leading zeros

        nxts = [sith.encode("utf-8")]  # create list to concatenate for hashing
        for key in keys:
            nxts.append(key.encode("utf-8"))
        ser = b''.join(nxts)

        return ser

    def verify(self, ser=b'', sith=None, keys=None, ked=None):
        """
        Returns True if digest of bytes serialization ser matches .raw
        using .raw as reference digest for ._verify digest algorithm determined
        by .code

        If ser not provided then extract ser from either (sith, keys) or ked

        Parameters:
            ser is bytes serialization
            sith is str lowercase hex
        """
        if not ser:
            ser = self._derive(sith=sith, keys=keys, ked=ked)

        return (self._verify(ser=ser, dig=self.raw))


class Aider(CryMat):
    """
    Aider is CryMat subclass for autonomic identifier prefix using basic derivation
    from public key

    See CryMat for other inherited attributes and properties:

    Attributes:

    Properties:

    Methods:
        verify():  Verifies derivation of aid

    """
    def __init__(self, raw=b'', code=CryOne.Ed25519N, ked=None, **kwa):
        """
        assign ._verify to verify derivation of aid  = .qb64

        """
        try:
            super(Aider, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if not ked:
                raise  ex
            verifier = self._derive(ked)  # use ked to derive aid
            super(Aider, self).__init__(raw=verifier.raw,
                                        code=verifier.code,
                                        **kwa)

        if self.code == CryOne.Ed25519N:
            self._verify = self._ed25519n
        elif self.code == CryOne.Ed25519:
            self._verify = self._ed25519
        else:
            raise ValueError("Unsupported code = {} for aider.".format(self.code))

    @staticmethod
    def _derive(ked):
        """
        Returns Verifier derived from ked (key event dict) to use for .raw & .code
        """
        try:
            keys = ked["keys"]
            if len(keys) != 1:
                raise DerivationError("Basic derivation needs 1 key got "
                                      "{}".format(len(keys)))
            verifier = Verifier(qb64=keys[0])
        except Exception as ex:
            raise DerivationError("Error extracting public key ="
                                  " = {}".format(ex))

        if verifier.code not in [CryOne.Ed25519N, CryOne.Ed25519]:
            raise DerivationError("Invalid derivation code = {}"
                                  "".format(verifier.code))

        try:
            if verifier.code == CryOne.Ed25519N and ked["next"]:
                raise DerivationError("Non-empty next = {} for non-transferable"
                                      " code = {}".format(ked["next"],
                                                          verifier.code))
        except Exception as ex:
            raise DerivationError("Error checking next = {}".format(ex))

        return verifier

    def verify(self, ked):
        """
        Returns True if derivation from iked for .code matches .qb64,
                False otherwise

        Parameters:
            iked is inception key event dict
        """
        return (self._verify(ked=ked, aid=self.qb64))


    @staticmethod
    def _ed25519n(ked, aid):
        """
        Returns True if verified raises exception otherwise
        Verify derivation of fully qualified Base64 aid from inception iked dict

        Parameters:
            iked is inception key event dict
            aid is Base64 fully qualified
        """
        try:
            keys = ked["keys"]
            if len(keys) != 1:
                return False

            if keys[0] != aid:
                return False

            if ked["next"]:  # must be empty
                return False

        except Exception as ex:
            return False

        return True


    @staticmethod
    def _ed25519(ked, aid):
        """
        Returns True if verified raises exception otherwise
        Verify derivation of fully qualified Base64 aid from
        inception key event dict (ked)

        Parameters:
            iked is inception key event dict
            aid is Base64 fully qualified
        """
        try:
            keys = ked["keys"]
            if len(keys) != 1:
                return False

            if keys[0] != aid:
                return False
        except Exception as ex:
            return False

        return True



BASE64_PAD = '='

# Mappings between Base64 Encode Index and Decode Characters
#  B64ChrByIdx is dict where each key is a B64 index and each value is the B64 char
#  B64IdxByChr is dict where each key is a B64 chars and each values is the B64 indexe
# Map Base64 index to char
B64ChrByIdx = dict((index, char) for index,  char in enumerate([chr(x) for x in range(65, 91)]))
B64ChrByIdx.update([(index + 26, char) for index,  char in enumerate([chr(x) for x in range(97, 123)])])
B64ChrByIdx.update([(index + 52, char) for index,  char in enumerate([chr(x) for x in range(48, 58)])])
B64ChrByIdx[62] = '-'
B64ChrByIdx[63] = '_'

B64IdxByChr = {char: index for index, char in B64ChrByIdx.items()}  # map char to Base64 index

def IntToB64(i):
    """
    Returns conversion of int i to 2 digit Base64 str
    0 <= 1 <= 4095
    """
    if i < 0 or i >  4095:
        raise ValueError("Invalid int = {}".format(i))

    return "{}{}".format(B64ChrByIdx[i // 64], B64ChrByIdx[i % 64])

def B64ToInt(cs):
    """
    Returns conversion of 2 digit Base64 str cs to int
    """
    if len(cs) > 2:
        raise ValueError("Invalid cs = {}".format(cs))

    return (B64IdxByChr[cs[0]] * 64 + B64IdxByChr[cs[1]])


@dataclass(frozen=True)
class SigSelectCodex:
    """
    SigSelectCodex codex of selector characters for attached signature cyptographic material
    Only provide defined characters.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    four: str = '0'  # use four character table.
    five: str = '1'  # use five character table.
    six:  str = '2'  # use siz character table.

    def __iter__(self):
        return iter(astuple(self))

SigSelect = SigSelectCodex()  # Make instance


@dataclass(frozen=True)
class SigTwoCodex:
    """
    SigTwoCodex codex of two character length derivation codes for attached signatures
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in SigTwoCodex results in 2 Base64 pad bytes.

    First code character selects signature cipher suite
    Second code charater selects index into current signing key list
    Only provide first character here
    """
    Ed25519: str =  'A'  # Ed25519 signature.
    ECDSA_256k1: str = 'B'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

SigTwo = SigTwoCodex()  #  Make instance

# Mapping of Code to Size
SigTwoSizes = {
                "A": 88,
                "B": 88,
              }

SigTwoRawSizes = {
                "A": 64,
                "B": 64,
              }


SIGTWOMAX = 63  # maximum index value given one base64 digit

@dataclass(frozen=True)
class SigFourCodex:
    """
    SigFourCodex codex of four character length derivation codes
    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    Note binary length of everything in SigFourCodex results in 0 Base64 pad bytes.

    First two code characters select signature cipher suite
    Next two code charaters select index into current signing key list
    Only provide first two characters here
    """
    Ed448: str =  '0A'  # Ed448 signature.

    def __iter__(self):
        return iter(astuple(self))

SigFour = SigFourCodex()  #  Make instance

# Mapping of Code to Size
SigFourSizes = {
                "0A": 156,
               }

SigFourRawSizes = {
                "0A": 114,
               }


SIGFOURMAX = 4095  # maximum index value given two base 64 digits

@dataclass(frozen=True)
class SigFiveCodex:
    """
    Five codex of five character length derivation codes
    Only provide defined codes. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in Four results in 0 Base64 pad bytes.

    First three code characters select signature cipher suite
    Next two code charaters select index into current signing key list
    Only provide first three characters here
    """
    def __iter__(self):
        return iter(astuple(self))

SigFive = SigFiveCodex()  #  Make instance

# Mapping of Code to Size
SigFiveSizes = {}
SigFiveRawSizes = {}

SIGFIVEMAX = 4095  # maximum index value given two base 64 digits

# all sizes in one dict
SigSizes = dict(SigTwoSizes)
SigSizes.update(SigFourSizes)
SigSizes.update(SigFiveSizes)

SigRawSizes = dict(SigTwoRawSizes)
SigRawSizes.update(SigFourRawSizes)
SigRawSizes.update(SigFiveRawSizes)


class SigMat:
    """
    SigMat is fully qualified attached signature crypto material base class
    Sub classes are derivation code specific.

    Includes the following attributes and properites.

    Attributes:

    Properties:
        .code  str derivation code of cipher suite for signature
        .index int zero based offset into signing key list
        .raw   bytes crypto material only without code
        .pad  int number of pad chars given .raw
        .qb64 str in Base64 with derivation code and signature crypto material
        .qb2  bytes in binary with derivation code and signature crypto material
    """
    def __init__(self, raw=b'', qb64='', qb2='', code=SigTwo.Ed25519, index=0):
        """
        Validate as fully qualified
        Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64 is str of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code cipher suite
            index is int of offset index into current signing key list

        When raw provided then validate that code is correct for length of raw
            and assign .raw .code and .index
        Else when qb64 pr qb2 provided extract and assign .raw and .code

        """
        if raw:  #  raw provided
            if not isinstance(raw, (bytes, bytearray)):
                raise TypeError("Not a bytes or bytearray, raw={}.".format(raw))
            pad = self._pad(raw)
            if (not ( (pad == 2 and (code in SigTwo)) or  # Two or Six or Ten
                      (pad == 0 and (code in SigFour)) or  #  Four or Eight
                      (pad == 1 and (code in SigFive)) )):   # Five or Nine

                raise ValidationError("Wrong code={} for raw={}.".format(code, raw))

            if ( (code in SigTwo and ((index < 0) or (index > SIGTWOMAX)) ) or
                 (code in SigFour and ((index < 0) or (index > SIGFOURMAX)) ) or
                 (code in SigFive and ((index < 0) or (index > SIGFIVEMAX)) ) ):

                raise ValidationError("Invalid index={} for code={}.".format(index, code))

            raw = raw[:SigRawSizes[code]]  # allows longer by truncating stream
            if len(raw) != SigRawSizes[code]:  # forbids shorter
                raise ValidationError("Unexpected raw size={} for code={}"
                                      " not size={}.".format(len(raw),
                                                             code,
                                                             SigRawSizes[code]))

            self._code = code  # front part without index
            self._index = index
            self._raw = bytes(raw)  # crypto ops require bytes not bytearray

        elif qb64:
            if hasattr(qb64, "decode"):  # converts bytes like to str
                qb64 = qb64.decode("utf-8")
            self._exfil(qb64)

        elif qb2:  # rewrite to use direct binary exfiltration
            self._exfil(encodeB64(qb2).decode("utf-8"))

        else:
            raise EmptyMaterialError("Improper initialization need raw or b64 or b2.")


    @staticmethod
    def _pad(raw):
        """
        Returns number of pad characters that would result from converting raw
        to Base64 encoding
        raw is bytes or bytearray
        """
        m = len(raw) % 3
        return (3 - m if m else 0)


    @property
    def pad(self):
        """
        Returns number of pad characters that would result from converting
        self.raw to Base64 encoding
        self.raw is raw is bytes or bytearray
        """
        return self._pad(self._raw)

    @property
    def code(self):
        """
        Returns ._code
        Makes .code read only
        """
        return self._code

    @property
    def index(self):
        """
        Returns ._index
        Makes .index read only
        """
        return self._index


    @property
    def raw(self):
        """
        Returns ._raw
        Makes .raw read only
        """
        return self._raw


    def _infil(self):
        """
        Returns fully qualified attached sig base64 computed from
        self.raw, self.code and self.index.
        """
        pad = self.pad
        # valid pad for code length
        if self._code in SigTwo:  # 2 char = code + index
            full = "{}{}".format(self._code, B64ChrByIdx[self._index])

        elif self._code == SigSelect.four: # 4 char = code + index
            pass

        else:
            raise ValueError("Unrecognized code = {}".format(self._code))

        if len(full) % 4 != pad:  # pad is not remainder of len(code) % 4
            raise ValidationError("Invalid code + index = {} for converted raw pad = {}."
                                  .format(full, self.pad))
        # prepending full derivation code with index and strip off trailing pad characters
        return (full + encodeB64(self._raw).decode("utf-8")[:-pad])


    def _exfil(self, qb64):
        """
        Extracts self.code,self.index, and self.raw from qualified base64 qb64
        """
        pre = 1
        code = qb64[:pre]
        index = 0

        # need to map code to length so can only consume proper number of chars
        #  from front of qb64 so can use with full identifiers not just id prefixes

        if code in SigTwo:  # 2 char = 1 code + 1 index
            qb64 = qb64[:SigTwoSizes[code]]  # strip of exact len identifier after prefix
            pre += 1
            index = B64IdxByChr[qb64[pre-1:pre]]

        elif code == SigSelect.four:  #  '0'
            pre += 1
            code = qb64[pre-2:pre]
            if code not in SigFour:  # 4 char = 2 code + 2 index
                raise ValidationError("Invalid derivation code = {} in {}.".format(code, qb64))
            qb64 = qb64[:SigFourSizes[code]]  # strip of exact len identifier after prefix
            pre += 2
            index = B64ToInt(qb64[pre-2:pre])

        else:
            raise ValueError("Improperly coded material = {}".format(qb64))

        if len(qb64) != SigSizes[code]:  # forbit shorter
            raise ValidationError("Unexpected qb64 size={} for code={}"
                                  " not size={}.".format(len(qb64),
                                                         code,
                                                         SigSizes[code]))

        pad = pre % 4  # pad is remainder pre mod 4
        # strip off prepended code and append pad characters
        base = qb64[pre:] + pad * BASE64_PAD
        raw = decodeB64(base.encode("utf-8"))

        if len(raw) != (len(qb64) - pre) * 3 // 4:  # exact lengths
            raise ValueError("Improperly qualified material = {}".format(qb64))

        self._code = code
        self._index = index
        self._raw = raw


    @property
    def qb64(self):
        """
        Property qb64:
        Returns Fully Qualified Base64 Version
        Assumes self.raw and self.code are correctly populated
        """
        return self._infil()


    @property
    def qb64b(self):
        """
        Property qb64b:
        Returns Fully Qualified Base64 Version encoded as bytes
        Assumes self.raw and self.code are correctly populated
        """
        return self.qb64.encode("utf-8")


    @property
    def qb2(self):
        """
        Property qb2:
        Returns Fully Qualified Binary Version
        redo to use b64 to binary decode table since faster
        """
        # rewrite to do direct binary infiltration by
        # decode self.code as bits and prepend to self.raw
        return decodeB64(self._infil().encode("utf-8"))


"""
Need to add Serdery  as Serder factory that figures out what type of
serialization and creates appropriate subclass

"""

class Serder:
    """
    Serder is KERI key event serializer-deserializer class
    Only supports current version VERSION

    Has the following public properties:

    Properties:
        .raw is bytes of serialized event only
        .ked is key event dict
        .kind is serialization kind string value (see namedtuple coring.Serials)
        .version is Versionage instance of event version
        .size is int of number of bytes in serialed event only

    """
    def __init__(self, raw=b'', ked=None, kind=None):
        """
        Deserialize if raw provided
        Serialize if ked provided but not raw
        When serilaizing if kind provided then use kind instead of field in ked

        Parameters:
          raw is bytes of serialized event plus any attached signatures
          ked is key event dict or None
            if None its deserialized from raw
          kind is serialization kind string value or None (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
            if kind is None then its extracted from ked or raw
          size is int number of bytes in raw if any


        Attributes:
          ._raw is bytes of serialized event only
          ._ked is key event dict
          ._kind is serialization kind string value (see namedtuple coring.Serials)
            supported kinds are 'json', 'cbor', 'msgpack', 'binary'
          ._version is Versionage instance of event version
          ._size is int of number of bytes in serialed event only

        Properties:
          .raw is bytes of serialized event only
          .ked is key event dict
          .kind is serialization kind string value (see namedtuple coring.Serials)
          .version is Versionage instance of event version
          .size is int of number of bytes in serialed event only


        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes
        """
        if raw:  # deserialize raw using property
            self.raw = raw  # raw property setter does the deserialization
        elif ked: # serialize ked
            self._kind = kind
            self.ked = ked  # ked property setter does the serialization
        else:
            raise ValueError("Improper initialization need raw or ked.")

    @staticmethod
    def _sniff(raw):
        """
        Returns serialization kind, version and size from serialized event raw
        by investigating leading bytes that contain version string

        Parameters:
          raw is bytes of serialized event

        """
        match = Rever.search(raw)  #  Rever's regex takes bytes
        if not match or match.start() > 12:
            raise ValueError("Invalid version string in raw = {}".format(raw))

        major, minor, kind, size = match.group("major", "minor", "kind", "size")
        version = Versionage(major=int(major, 16), minor=int(minor, 16))
        kind = kind.decode("utf-8")
        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))
        size = int(size, 16)
        return(kind, version, size)


    def _inhale(self, raw):
        """
        Parses serilized event ser of serialization kind and assigns to
        instance attributes.

        Parameters:
          raw is bytes of serialized event
          kind id str of raw serialization kind (see namedtuple Serials)
          size is int size of raw to be deserialized

        Note:
          loads and jumps of json use str whereas cbor and msgpack use bytes

        """
        kind, version, size = self._sniff(raw)
        if version != Version:
            raise VersionError("Unsupported version = {}.{}".format(version.major,
                                                                    version.minor))

        if kind == Serials.json:
            try:
                ked = json.loads(raw[:size].decode("utf-8"))
            except Exception as ex:
                raise ex

        elif kind == Serials.mgpk:
            try:
                ked = msgpack.loads(raw[:size])
            except Exception as ex:
                raise ex

        elif kind ==  Serials.cbor:
            try:
                ked = cbor.loads(raw[:size])
            except Exception as ex:
                raise ex

        else:
            ked = None

        return (ked, kind, version, size)


    def _exhale(self, ked,  kind=None):
        """
        ked is key event dict
        kind is serialization if given else use one given in ked
        Returns tuple of (raw, kind, ked, version) where:
            raw is serialized event as bytes of kind
            kind is serialzation kind
            ked is key event dict
            version is Versionage instance

        Assumes only supports Version
        """
        if "vs" not in ked:
            raise ValueError("Missing or empty version string in key event dict = {}".format(ked))

        knd, version, size = Deversify(ked['vs'])  # extract kind and version
        if version != Version:
            raise VersionError("Unsupported version = {}.{}".format(version.major,
                                                                    version.minor))

        if not kind:
            kind = knd

        if kind not in Serials:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        if kind == Serials.json:
            raw = json.dumps(ked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        elif kind == Serials.mgpk:
            raw = msgpack.dumps(ked)

        elif kind == Serials.cbor:
            raw = cbor.dumps(ked)

        else:
            raise ValueError("Invalid serialization kind = {}".format(kind))

        size = len(raw)

        match = Rever.search(raw)  #  Rever's regex takes bytes
        if not match or match.start() > 12:
            raise ValueError("Invalid version string in raw = {}".format(raw))

        fore, back = match.span()  #  full version string
        # update vs with latest kind version size
        vs = Versify(version=version, kind=kind, size=size)
        # replace old version string in raw with new one
        raw = b'%b%b%b' % (raw[:fore], vs.encode("utf-8"), raw[back:])
        if size != len(raw):  # substitution messed up
            raise ValueError("Malformed version string size = {}".format(vs))
        ked['vs'] = vs  #  update ked

        return (raw, kind, ked, version)

    @property
    def raw(self):
        """ raw property getter """
        return self._raw

    @raw.setter
    def raw(self, raw):
        """ raw property setter """
        ked, kind, version, size = self._inhale(raw=raw)
        self._raw = bytes(raw[:size])  # crypto ops require bytes not bytearray
        self._ked = ked
        self._kind = kind
        self._version = version
        self._size = size

    @property
    def ked(self):
        """ ked property getter"""
        return self._ked

    @ked.setter
    def ked(self, ked):
        """ ked property setter  assumes ._kind """
        raw, kind, ked, version = self._exhale(ked=ked, kind=self._kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version

    @property
    def kind(self):
        """ kind property getter"""
        return self._kind

    @kind.setter
    def kind(self, kind):
        """ kind property setter Assumes ._ked """
        raw, kind, ked, version = self._exhale(ked=self._ked, kind=kind)
        size = len(raw)
        self._raw = raw[:size]
        self._ked = ked
        self._kind = kind
        self._size = size
        self._version = version

    @property
    def version(self):
        """ version property getter"""
        return self._version

    @property
    def size(self):
        """ size property getter"""
        return self._size

    @property
    def digmat(self):
        """
        Returns CryMat of digest of self.raw
        digmat (digest material) property getter
        """
        return (CryMat(raw=blake3.blake3(self.raw).digest(), code=CryOne.Blake3_256))

    @property
    def dig(self):
        """
        Returns qualified Base64 digest of self.raw
        dig (digest) property getter
        """
        return self.digmat.qb64

    @property
    def verifiers(self):
        """
        Returns list of Verifier instances as converted from .ked.keys
        verifiers property getter
        """
        return [Verifier(qb64=key) for key in self.ked["keys"]]


Kevage = namedtuple("Kelvage", 'serder sigs')  # Key Event tuple for KELS and DELs

Kevers = dict()  # dict of existing Kevers indexed by aid.qb64 of each Kever

KELs = dict() # dict of dicts of ordered events keyed by aid.qb64 then by event dig

DELs = dict()  # dict of dicts of dup events keyed by aid.qb64 then by event dig

Escrows = dict()

class Kevery:
    """
    Kevery is Kever (KERI key event verifier) instance factory which are
    extracted from a key event stream of event and attached signatures

    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:

    Properties:

    """
    def __init__(self):
        """
        Set up event stream

        """


    def processAll(self, kes):
        """

        """
        if not isinstance(kes, bytearray):  # destructive processing
            kes = bytearray(kes)

        while kes:
            try:
                serder, sigs = self.extractOne(kes)
            except Exception as  ex:
                # log diagnostics errors etc
                del kes[:]  # error extracting means bad key event stream
                continue

            try:
                self.processOne(serder, sigs)
            except Exception as  ex:
                # log diagnostics errors etc
                pass

    def extractOne(self, kes):
        """
        Extract one event with attached signatures from key event stream kes
        Returns: (serder, sigs)

        Parameters:
            kes is bytearray of serialized key event stream.
                May contain one or more sets each of a serialized event with
                attached signatures.

        """
        # deserialize packet from kes
        try:
            serder = Serder(raw=kes)
        except Exception as ex:
            raise ValidationError("Error while processing key event stream"
                                  " = {}".format(ex))

        version = serder.version
        if version != Version:  # This is where to dispatch version switch
            raise VersionError("Unsupported version = {}, expected {}."
                                  "".format(version, Version))

        del kes[:srdr.size]  # strip off event from front of kes

        # extract attached sigs if any
        # protocol dependent if http may use http header instead of stream

        ked = serder.ked
        keys = ked["keys"]
        sigs = []  # list of SigMat instances for attached signatures
        if "idxs" in ked and ked["idxs"]: # extract signatures given indexes
            indexes = ked["idxs"]
            if isinstance(indexes, str):
                nsigs = int(indexes, 16)
                if nsigs < 1:
                    raise ValidationError("Invalid number of attached sigs = {}."
                                              " Must be > 1 if not empty.".format(nsigs))

                for i in range(nsigs): # extract each attached signature
                    # check here for type of attached signatures qb64 or qb2
                    sig = SigMat(qb64=kes)  #  qb64
                    sigs.append(sig)
                    del kes[:len(sig.qb64)]  # strip off signature

                    if sig.index >= len(keys):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sig.index))

            elif isinstance(indexes, list):
                if len(set(indexes)) != len(indexes):  # duplicate index(es)
                    raise ValidationError("Duplicate indexes in sigs = {}."
                                              "".format(indexes))

                for index in indexes:
                    # check here for type of attached signatures qb64 or qb2
                    sig = SigMat(qb64=kes)  #  qb64
                    sigs.append(sig)
                    del kes[:len(sig.qb64)]  # strip off signature

                    if sig.index >= len(keys):
                        raise ValidationError("Index = {} to large for keys."
                                              "".format(sig.index))

                    if index != sig.index:
                        raise ValidationError("Mismatching signature index = {}"
                                              " with index = {}".format(sig.index,
                                                                        index))

            else:
                raise ValidationError("Invalid format of indexes = {}."
                                          "".format(indexes))

        else:  # no info on attached sigs
            pass
            #  check flag if should parse rest of stream for attached sigs
            #  or should parse for index block

        if not sigs:
            raise ValidationError("Missing attached signature(s).")

        return (serder, sigs)

    def processOne(self, serder, sigs):
        """
        Process one event with attached signatures

        Parameters:
            serder is Serder instance of event
            sigs is list of SigMat instances of attached signatures

        """
        # Verify serder.ked fields based on ked ilk and version.
        # If missing fields then raise error.

        # extract aid, sn, ilk to see how to process

        dig = serder.dig
        try:
            aider = Aider(qb64=ked["id"])
        except Exception as ex:
            raise ValidationError("Invalid aid = {}.".format(ked["id"]))

        aid = aider.qb64
        ked = serder.ked
        ilk = ked["ilk"]

        try:
            sn = int(ked["sn"], 16)
        except Exception as ex:
            raise ValidationError("Invalid sn = {}".format(ked["sn"]))


        if aid not in KELs:  #  first seen event for aid
            if ilk == Ilks.icp:  # first seen and inception so verify event keys
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem adds to KEL Kevers
                kever = Kever(serder=serder, sigs=sigs)  # create kever from serder

            else:  # not inception so can't verify add to escrow
                # log escrowed
                if aid not in Escrows:  #  add to Escrows
                    Escrows[aid] = dict()
                if dig not in Escrows[aid]:
                    Escrows[aid][dig] = Kevage(serder=serder, sigs=sigs)


        else:  # already accepted inception event for aid
            if dig in KELs["aid"]:  #  duplicate event so dicard
                # log duplicate
                return  # discard

            if ilk == Ilks.icp:  # inception event so maybe duplicitous
                # kever init verifies basic inception stuff and signatures
                # raises exception if problem
                kever = Kever(serder=serder, sigs=sigs)  # create kever from serder

                #  verified duplicitous event log it and add to DELS if first time
                if aid not in DELs:  #  add to DELS
                    DELs[aid] = dict()
                if dig not in DELS[aid]:
                    DELS[aid][dig] = Kevage(serder=serder, sigs=sigs)

            else:
                kever = Kevers[aid]  # get existing kever for aid
                # if sn not subsequent to prior event  else escrow
                if sn <= kever.sn:  # stale event
                    # log stale event
                    return  # discard

                if sn > kever.sn + 1:  # sn not in order
                    #  log escrowed
                    if aid not in Escrows:  #  add to Escrows
                        Escrows[aid] = dict()
                    if dig not in Escrows[aid]:
                        Escrows[aid][dig] = Kevage(serder=serder, sigs=sigs)

                else:  # sn == kever.sn + 1
                    if dig != kever.dig:  # prior event dig not match
                        raise ValidationError("Mismatch prior dig = {} with"
                                              " current = {}.".format(dig,
                                                                      kever.dig))

                    # verify signatures etc and update state if valid
                    # raise exception if problem. adds to KELs
                    kever.update(serder=serder, sigs=sigs)








class Kever:
    """
    Kever is KERI key event verifier class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Class Attributes:
        .EstablishOnly

    Attributes:
        .serder is Serder instance of current packet
        .sigs is list of SigMat instances of signatures
        .verifiers is list of Verifier instances of current signing keys
        .version is version of current event
        .aider is aider instance
        .sn is sequence number int
        .dig is qualified qb64 digest of event not prior event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .nexter is qualified qb64 of next sith and next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .conf is list of inception configuration data mappings
        .establishOnly is boolean

    Properties:

    """
    EstablishOnly = False

    def __init__(self, serder, sigs, establishOnly=None):
        """
        Create incepting kever and state from inception serder
        Verify incepting serder against sigs raises ValidationError if not

        Parameters:
            serder is Serder instance of inception event
            sigs is list of SigMat instances of signatures of event
            establishOnly is boolean trait to indicate establish only event

        """
        self.serder = serder
        self.verifiers = serder.verifiers  # converts keys to verifiers
        self.sigs = sigs
        ked = self.serder.ked
        sith = ked["sith"]
        if isinstance(sith, str):
            self.sith =  int(sith, 16)
        else:
            # fix this to support list sith
            raise ValueError("Unsupported type for sith = {}".format(sith))

        if not self.verify():
            raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

        self.version = self.serder.version  # version switch?

        self.aider = Aider(qb64=ked["id"])
        if not self.aider.verify(ked=ked):  # invalid aid
            raise ValidationError("Invalid aid = {} for inception ked = {}."
                                  "".format(self.aider.qb64, ked))

        self.sn = int(ked["sn"], 16)
        if self.sn != 0:
            raise ValidationError("Invalid sn = {} for inception ked = {}."
                                              "".format(self.sn, ked))
        self.dig = self.serder.dig

        self.ilk = ked["ilk"]
        if self.ilk != Ilks.icp:
            raise ValidationError("Expected ilk = {} got {}."
                                              "".format(Ilks.icp, self.ilk))
        self.nexter = Nexter(qb64=ked["next"]) if ked["next"] else None  # check for empty
        self.toad = int(ked["toad"], 16)
        self.wits = ked["wits"]
        self.conf = ked["conf"]

        self.establishOnly = establishOnly if establishOnly is not None else self.EstablishOnly
        self.establishOnly = True if self.establishOnly else False  # ensure boolean
        for d in self.conf:
            if "trait" in d and d["trait"] == "establishOnly":
                self.establishOnly = True

        aid = self.aider.qb64
        if aid not in KELs:
            KELs[aid] = dict()
        KELs[aid][self.dig] = Kevage(serder=serder, sigs=sigs)
        if aid not in Kevers:
            Kevers[aid] = dict()
        Kevers[aid][self.dig] = self



    def verify(self, sigs=None, serder=None, sith=None, verifiers=None):
        """
        Verify sigs against serder using sith and verifiers
        Assumes that sigs already extracted correctly wrt indexes
        If any of serder, sith, verifiers not provided then replace missing
           value with respective attribute .serder, .sith .verifiers instead

        Parameters:
            sigs is list of SigMat instances
            serder is Serder instance
            sith is int threshold
            verifiers is list of Verifier instances

        """
        sigs = sigs if sigs is not None else self.sigs
        serder = serder if serder is not None else self.serder
        sith = sith if sith is not None else self.sith
        verifiers = verifiers if verifiers is not None else self.verifiers

        for sig in sigs:
            verifier = verifiers[sig.index]
            if not verifier.verify(sig.raw, serder.raw):
                return False

        if not isinstance(sith, int):
            raise ValueError("Unsupported type for sith ={}".format(sith))
        if len(sigs) < sith:  # not meet threshold fix for list sith
            return False

        return True



    def update(self, serder,  sigs):
        """

        """
        # if rotation event use keys from event
        # if interaction event use keys from existing Kever
        ked = serder.ked
        ilk = ked["ilk"]

        if ilk == Ilks.rot:  # subsequent rotation event
            # verify next from prior
            # also check derivation code of aid for non-transferable
            #  check and

            if self.nexter is None:   # empty so rotations not allowed
                raise ValidationError("Attempted rotation for nontransferable"
                                      " aid = {}".format(self.aider.qb64))

            sith = ked["sith"]
            if isinstance(sith, str):
                sith =  int(ked.sith, 16)
            else:
                # fix this to support list sith
                raise ValueError("Unsupported type for sith = {}".format(sith))

            keys = ked["keys"]
            if not self.nexter.verify(sith=sith, keys=keys):
                raise ValidationError("Mismatch next digest = {} with rotation"
                                      " sith = {}, keys = {}.".format(nexter.qb64))


            # prior next valid so verify sigs using new verifier keys from event
            if not self.verify(serder.serder,
                               sigs=sigs,
                               sith=sith,
                               verifiers=serder.verifiers):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

            # next and signatures verify so update state
            self.sn = sn
            self.dig = dig
            self.sith = sith
            self.verifiers = serder.verifiers
            # verify nxt prior
            nexter = Nexter(qb64=ked["next"]) if nxt else None  # check for empty
            # update non transferable if None
            self.nexter = nexter
            self.toad = int(ked["toad"], 16)
            self.wits = ked["wits"]
            self.conf = ked["conf"]


            KELS[aid][dig] = Kevage(serder=serder, sigs=sigs)


        elif ilk == Ilks.ixn:  # subsequent interaction event
            if self.establishOnly:
                raise ValidationError("Unexpected non-establishment event = {}."
                                  "".format(serder))
            if not self.verify(serder=serder, sigs=sigs):
                raise ValidationError("Failure verifying signatures = {} for {}"
                                  "".format(sigs, serder))

            # update state
            self.sn = sn
            self.dig = dig
            KELS[aid][dig] = Kevage(serder=serder, sigs=sigs)


        else:  # unsupported event ilk so discard
            raise ValidationError("Unsupported ilk = {}.".format(ilk))





class Keger:
    """
    Keger is KERI key event generator class
    Only supports current version VERSION

    Has the following public attributes and properties:

    Attributes:
        .version is version of current event
        .aid is fully qualified qb64 autonomic id
        .sn is sequence number
        .predig is qualified qb64 digest of previous event
        .dig is qualified qb64 dige of current event
        .ilk is str of current event type
        .sith is int or list of current signing threshold
        .keys is list of qb64 current verification keys
        .nxt is qualified qb64 of next sith plus next signing keys
        .toad is int threshold of accountable duplicity
        .wits is list of qualified qb64 aids for witnesses
        .conf is list of inception configuration data mappings
        .indexes is int or list of signature indexes of current event if any

    Properties:



    """
    def __init__(self):
        """
        Extract and verify event and attached signatures from key event stream kes

        Parameters:


        """
        # initial state is vacuous
        self.version = None
        self.aid = None
        self.sn =  None
        self.predig = None
        self.dig = None
        self.ilk = None
        self.sith = None
        self.keys = []
        self.nxt = None
        self.toad = None
        self.wits = None
        self.conf = None
        self.indexes = None

