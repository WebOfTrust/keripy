# -*- coding: utf-8 -*-
"""
keri.core.signing module

Provides support Signer class
"""

import pysodium

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..kering import (EmptyMaterialError,)

from ..help import helping

from .coring import (Tiers, )
from .coring import (Matter, MtrDex, Verfer, Cigar)
from .indexing import IdrDex, Siger


DSS_SIG_MODE = "fips-186-3"
ECDSA_256r1_SEEDBYTES = 32
ECDSA_256k1_SEEDBYTES = 32


class Signer(Matter):
    """
    Signer is Matter subclass with method to create signature of serialization
    using:
        .raw as signing (private) key seed,
        .code as cipher suite for signing
        .verfer whose property .raw is public key for signing.

    If not provided .verfer is generated from private key seed using .code
    as cipher suite for creating key-pair.


    See Matter for inherited attributes and properties:

    Attributes:

    Properties:  (inherited)
        code (str): hard part of derivation code to indicate cypher suite
        both (int): hard and soft parts of full text code
        size (int): Number of triplets of bytes including lead bytes
            (quadlets of chars) of variable sized material. Value of soft size,
            ss, part of full text code.
            Otherwise None.
        rize (int): number of bytes of raw material not including
                    lead bytes
        raw (bytes): private signing key crypto material only without code
        qb64 (str): private signing key Base64 fully qualified with
                    derivation code + crypto mat
        qb64b (bytes): private signing keyBase64 fully qualified with
            derivation code + crypto mat
        qb2  (bytes): private signing key binary with
            derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise

    Properties:

        .verfer is Verfer object instance of public key derived from private key
            seed which is .raw

    Methods:
        sign: create signature

    """

    def __init__(self, raw=None, code=MtrDex.Ed25519_Seed, transferable=True, **kwa):
        """
        Assign signing cipher suite function to ._sign

        Parameters:  See Matter for inherted parameters
            raw is bytes crypto material seed or private key
            code is derivation code
            transferable is Boolean True means make verifier code transferable
                                    False make non-transferable

        """
        try:
            super(Signer, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Ed25519_Seed:
                raw = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
                super(Signer, self).__init__(raw=raw, code=code, **kwa)
            elif code == MtrDex.ECDSA_256r1_Seed:
                raw = pysodium.randombytes(ECDSA_256r1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)
            elif code == MtrDex.ECDSA_256k1_Seed:
                raw = pysodium.randombytes(ECDSA_256k1_SEEDBYTES)
                super(Signer, self).__init__(raw=bytes(raw), code=code, **kwa)

            else:
                raise ValueError("Unsupported signer code = {}.".format(code))

        if self.code == MtrDex.Ed25519_Seed:
            self._sign = self._ed25519
            verkey, sigkey = pysodium.crypto_sign_seed_keypair(self.raw)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.Ed25519 if transferable
                            else MtrDex.Ed25519N)
        elif self.code == MtrDex.ECDSA_256r1_Seed:
            self._sign = self._secp256r1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256R1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256r1 if transferable
                            else MtrDex.ECDSA_256r1N)
        elif self.code == MtrDex.ECDSA_256k1_Seed:
            self._sign = self._secp256k1
            d = int.from_bytes(self.raw, byteorder="big")
            sigkey = ec.derive_private_key(d, ec.SECP256K1())
            verkey = sigkey.public_key().public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = Verfer(raw=verkey,
                            code=MtrDex.ECDSA_256k1 if transferable
                            else MtrDex.ECDSA_256k1N)
        else:
            raise ValueError("Unsupported signer code = {}.".format(self.code))

        self._verfer = verfer

    @property
    def verfer(self):
        """
        Property verfer:
        Returns Verfer instance
        Assumes ._verfer is correctly assigned
        """
        return self._verfer

    def sign(self, ser, index=None, only=False, ondex=None, **kwa):
        """
        Returns either Cigar or Siger (indexed) instance of cryptographic
        signature material on bytes serialization ser

        If index is None
            return Cigar instance
        Else
            return Siger instance

        Parameters:
            ser (bytes): serialization to be signed
            index (int):  main index of associated verifier key in event keys
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next

        """
        return (self._sign(ser=ser,
                           seed=self.raw,
                           verfer=self.verfer,
                           index=index,
                           only=only,
                           ondex=ondex,
                           **kwa))

    @staticmethod
    def _ed25519(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        sig = pysodium.crypto_sign_detached(ser, seed + verfer.raw)

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.Ed25519_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.Ed25519_Crt_Sig  # use small current only
                else:
                    code = IdrDex.Ed25519_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.Ed25519_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.Ed25519_Big_Sig  # use use big both

            return Siger(raw=sig, code=code, index=index, ondex=ondex, verfer=verfer)

    @staticmethod
    def _secp256r1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        Ed25519 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256R1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256r1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.ECDSA_256r1_Crt_Sig  # use small current only
                else:
                    code = IdrDex.ECDSA_256r1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.ECDSA_256r1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.ECDSA_256r1_Big_Sig  # use use big both

            return Siger(raw=sig, code=code, index=index, ondex=ondex, verfer=verfer,)

    @staticmethod
    def _secp256k1(ser, seed, verfer, index, only=False, ondex=None, **kwa):
        """
        Returns signature as either Cigar or Siger instance as appropriate for
        secp256k1 digital signatures given index and ondex values

        The seed's code determins the crypto key-pair algorithm and signing suite
        The signature type, Cigar or Siger, and when indexed the Siger code
        may be completely determined by the seed and index values (index, ondex)
        by assuming that the index values are intentional.
        Without the seed code its more difficult for Siger to
        determine when for the Indexer code value should be changed from the
        than the provided value with respect to provided but incompatible index
        values versus error conditions.

        Parameters:
            ser (bytes): serialization to be signed
            seed (bytes):  raw binary seed (private key)
            verfer (Verfer): instance. verfer.raw is public key
            index (int |None): main index offset into list such as current signing
                None means return non-indexed Cigar
                Not None means return indexed Siger with Indexer code derived
                    from index, conly, and ondex values
            only (bool): True means main index only list, ondex ignored
                          False means both index lists (default), ondex used
            ondex (int | None): other index offset into list such as prior next
        """
        # compute raw signature sig using seed on serialization ser
        d = int.from_bytes(seed, byteorder="big")
        sigkey = ec.derive_private_key(d, ec.SECP256K1())
        der = sigkey.sign(ser, ec.ECDSA(hashes.SHA256()))
        (r, s) = utils.decode_dss_signature(der)
        sig = bytearray(r.to_bytes(32, "big"))
        sig.extend(s.to_bytes(32, "big"))

        if index is None:  # Must be Cigar i.e. non-indexed signature
            return Cigar(raw=sig, code=MtrDex.ECDSA_256k1_Sig, verfer=verfer)
        else:  # Must be Siger i.e. indexed signature
            # should add Indexer class method to get ms main index size for given code
            if only:  # only main index ondex not used
                ondex = None
                if index <= 63: # (64 ** ms - 1) where ms is main index size
                    code = IdrDex.ECDSA_256k1_Crt_Sig  # use small current only
                else:
                    code = IdrDex.ECDSA_256k1_Big_Crt_Sig  # use big current only
            else:  # both
                if ondex == None:
                    ondex = index  # enable default to be same
                if ondex == index and index <= 63:  # both same and small
                    code = IdrDex.ECDSA_256k1_Sig  # use  small both same
                else:  # otherwise big or both not same so use big both
                    code = IdrDex.ECDSA_256k1_Big_Sig  # use use big both

            return Siger(raw=sig, code=code, index=index, ondex=ondex, verfer=verfer,)



class Salter(Matter):
    """
    Salter is Matter subclass to maintain random salt for secrets (private keys)
    Its .raw is random salt, .code as cipher suite for salt

    To initialize with deterministic salt pass in 16 bytes for raw:
        salter = Salter(raw=b'0123456789abcdef')

    To create a deterministic secret, seed, or private key from salt
    call .signer:
        signer = salter.signer(code=MtrDex.Ed25519_Seed,
                               transferable=True,
                               path="",
                               tier=None,
                               temp=False)

    To create a deterministic set of secrets or seeds or private keys from salt
    call signers:
        signers = salter.signers(count=1,
                                 start=0,
                                 path="",
                                 code=MtrDex.Ed25519_Seed,
                                 transferable=True,
                                 tier=None,
                                 temp=False)

    Attributes:
        .level is str security level code. Provides default level

    Inherited Properties
        .pad  is int number of pad chars given raw
        .code is  str derivation code to indicate cypher suite
        .raw is bytes crypto material only without code
        .index is int count of attached crypto material by context (receipts)
        .qb64 is str in Base64 fully qualified with derivation code + crypto mat
        .qb64b is bytes in Base64 fully qualified with derivation code + crypto mat
        .qb2  is bytes in binary with derivation code + crypto material
        .transferable is Boolean, True when transferable derivation code False otherwise

    Properties:

    Methods:

    Hidden:
        ._pad is method to compute  .pad property
        ._code is str value for .code property
        ._raw is bytes value for .raw property
        ._index is int value for .index property
        ._infil is method to compute fully qualified Base64 from .raw and .code
        ._exfil is method to extract .code and .raw from fully qualified Base64

    """
    Tier = Tiers.low

    def __init__(self, raw=None, code=MtrDex.Salt_128, tier=None, **kwa):
        """
        Initialize salter's raw and code

        Inherited Parameters:
            raw is bytes of unqualified crypto material usable for crypto operations
            qb64b is bytes of fully qualified crypto material
            qb64 is str or bytes  of fully qualified crypto material
            qb2 is bytes of fully qualified crypto material
            code is str of derivation code
            index is int of count of attached receipts for CryCntDex codes

        Parameters:

        """
        try:
            super(Salter, self).__init__(raw=raw, code=code, **kwa)
        except EmptyMaterialError as ex:
            if code == MtrDex.Salt_128:
                raw = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
                super(Salter, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise ValueError("Unsupported salter code = {}.".format(code))

        if self.code not in (MtrDex.Salt_128,):
            raise ValueError("Unsupported salter code = {}.".format(self.code))

        self.tier = tier if tier is not None else self.Tier

    def stretch(self, *, size=32, path="", tier=None, temp=False):
        """
        Returns (bytes): raw binary seed (secret) derived from path and .raw
        and stretched to size given by code using argon2d stretching algorithm.

        Parameters:
            size (int): number of bytes in stretched seed
            path (str): unique chars used in derivation of seed (secret)
            tier (str): value from Tierage for security level of stretch
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use time set by tier to stretch
        """
        tier = tier if tier is not None else self.tier

        if temp:
            opslimit = 1  # pysodium.crypto_pwhash_OPSLIMIT_MIN
            memlimit = 8192  # pysodium.crypto_pwhash_MEMLIMIT_MIN
        else:
            if tier == Tiers.low:
                opslimit = 2  # pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
                memlimit = 67108864  # pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
            elif tier == Tiers.med:
                opslimit = 3  # pysodium.crypto_pwhash_OPSLIMIT_MODERATE
                memlimit = 268435456  # pysodium.crypto_pwhash_MEMLIMIT_MODERATE
            elif tier == Tiers.high:
                opslimit = 4  # pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE
                memlimit = 1073741824  # pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE
            else:
                raise ValueError("Unsupported security tier = {}.".format(tier))

        # stretch algorithm is argon2id
        seed = pysodium.crypto_pwhash(outlen=size,
                                      passwd=path,
                                      salt=self.raw,
                                      opslimit=opslimit,
                                      memlimit=memlimit,
                                      alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)
        return (seed)

    def signer(self, *, code=MtrDex.Ed25519_Seed, transferable=True, path="",
               tier=None, temp=False):
        """
        Returns Signer instance whose .raw secret is derived from path and
        salter's .raw and stretched to size given by code. The signers public key
        for its .verfer is derived from code and transferable.

        Parameters:
            code is str code of secret crypto suite
            transferable is Boolean, True means use transferace code for public key
            path is str of unique chars used in derivation of secret seed for signer
            tier is str Tierage security level
            temp is Boolean, True means use quick method to stretch salt
                    for testing only, Otherwise use more time to stretch
        """
        seed = self.stretch(size=Matter._rawSize(code), path=path, tier=tier,
                            temp=temp)

        return (Signer(raw=seed, code=code, transferable=transferable))


    def signers(self, count=1, start=0, path="",  **kwa):
        """
        Returns list of count number of Signer instances with unique derivation
        path made from path prefix and suffix of start plus offset for each count
        value from 0 to count - 1.

        See .signer for parameters used to create each signer.

        """
        return [self.signer(path=f"{path}{i + start:x}", **kwa) for i in range(count)]


class Cipher(Matter):
    """
    Cipher is Matter subclass holding a cipher text of a secret that may be
    either a secret seed (private key) or secret salt with appropriate CESR code
    to indicate which kind (which indicates size). The cipher text is created
    with assymetric encryption using an unrelated (public, private)
    encryption/decryption key pair. The public key is used for encryption the
    private key for decryption. The default is to use X25519 sealed box encryption.

    The Cipher instances .raw is the raw binary encrypted cipher text and its
    .code indicates what type of secret has been encrypted. The cipher suite used
    for the encryption/decryption is implied by the context where the cipher is
    used.

    See Matter for inherited attributes and properties

    """

    def __init__(self, raw=None, code=None, **kwa):
        """
        Parmeters:
            raw (Union[bytes, str]): cipher text
            code (str): cipher suite
        """
        if raw is not None and code is None:
            if len(raw) == Matter._rawSize(MtrDex.X25519_Cipher_Salt):
                code = MtrDex.X25519_Cipher_Salt
            elif len(raw) == Matter._rawSize(MtrDex.X25519_Cipher_Seed):
                code = MtrDex.X25519_Cipher_Seed

        if hasattr(raw, "encode"):
            raw = raw.encode("utf-8")  # ensure bytes not str

        super(Cipher, self).__init__(raw=raw, code=code, **kwa)

        if self.code not in (MtrDex.X25519_Cipher_Salt, MtrDex.X25519_Cipher_Seed):
            raise ValueError("Unsupported cipher code = {}.".format(self.code))

    def decrypt(self, prikey=None, seed=None):
        """
        Returns plain text as Matter instance (Signer or Salter) of cryptographic
        cipher text material given by .raw. Encrypted plain text is fully
        qualified (qb64) so derivaton code of plain text preserved through
        encryption/decryption round trip.

        Uses either decryption key given by prikey or derives prikey from
        signing key derived from private seed.

        Parameters:
            prikey (Union[bytes, str]): qb64b or qb64 serialization of private
                decryption key
            seed (Union[bytes, str]): qb64b or qb64 serialization of private
                signing key seed used to derive private decryption key
        """
        decrypter = Decrypter(qb64b=prikey, seed=seed)
        return decrypter.decrypt(ser=self.qb64b)


class Encrypter(Matter):
    """
    Encrypter is Matter subclass with method to create a cipher text of a
    fully qualified (qb64) private key/seed where private key/seed is the plain
    text. Encrypter uses assymetric (public, private) key encryption of a
    serialization (plain text). Using its .raw as the encrypting (public) key and
    its .code to indicate the cipher suite for the encryption operation.

    For example .code == MtrDex.X25519 indicates that X25519 sealed box
    encyrption is used. The encryption key may be derived from an Ed25519
    signing public key that associated with a nontransferable or basic derivation
    self certifying identifier. This allows use of the self certifying identifier
    to track or manage the encryption/decryption key pair. And could be used to
    provide additional authentication operations for using the
    encryption/decryption key pair. Support for this is provided at init time
    with the verkey parameter which allows deriving the encryption public key from
    the fully qualified verkey (signature verification key).

    See Matter for inherited attributes and properties:

    Methods:
        encrypt: returns cipher text

    """

    def __init__(self, raw=None, code=MtrDex.X25519, verkey=None, **kwa):
        """
        Assign encrypting cipher suite function to ._encrypt

        Parameters:  See Matter for inherted parameters such as qb64, qb64b
            raw (bytes): public encryption key
            qb64b (bytes): fully qualified public encryption key
            qb64 (str): fully qualified public encryption key
            code (str): derivation code for public encryption key
            verkey (Union[bytes, str]): qb64b or qb64 of verkey used to derive raw
        """
        if not raw and verkey:
            verfer = Verfer(qb64b=verkey)
            if verfer.code not in (MtrDex.Ed25519N, MtrDex.Ed25519):
                raise ValueError("Unsupported verkey derivation code = {}."
                                 "".format(verfer.code))
            # convert signing public key to encryption public key
            raw = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)

        super(Encrypter, self).__init__(raw=raw, code=code, **kwa)

        if self.code == MtrDex.X25519:
            self._encrypt = self._x25519
        else:
            raise ValueError("Unsupported encrypter code = {}.".format(self.code))

    def verifySeed(self, seed):
        """
        Returns:
            Boolean: True means private signing key seed corresponds to public
                signing key verkey used to derive encrypter's .raw public
                encryption key.

        Parameters:
            seed (Union(bytes,str)): qb64b or qb64 serialization of private
                signing key seed
        """
        signer = Signer(qb64b=seed)
        verkey, sigkey = pysodium.crypto_sign_seed_keypair(signer.raw)
        pubkey = pysodium.crypto_sign_pk_to_box_pk(verkey)
        return (pubkey == self.raw)

    def encrypt(self, ser=None, matter=None):
        """
        Returns:
            Cipher instance of cipher text encryption of plain text serialization
            provided by either ser or Matter instance when provided.

        Parameters:
            ser (Union[bytes,str]): qb64b or qb64 serialization of plain text
            matter (Matter): plain text as Matter instance of seed or salt to
                be encrypted
        """
        if not (ser or matter):
            raise EmptyMaterialError("Neither ser or plain are provided.")

        if ser:
            matter = Matter(qb64b=ser)

        if matter.code == MtrDex.Salt_128:  # future other salt codes
            code = MtrDex.X25519_Cipher_Salt
        elif matter.code == MtrDex.Ed25519_Seed:  # future other seed codes
            code = MtrDex.X25519_Cipher_Seed
        else:
            raise ValueError("Unsupported plain text code = {}.".format(matter.code))

        # encrypting fully qualified qb64 version of plain text ensures its
        # derivation code round trips through eventual decryption
        return (self._encrypt(ser=matter.qb64b, pubkey=self.raw, code=code))

    @staticmethod
    def _x25519(ser, pubkey, code):
        """
        Returns cipher text as Cipher instance
        Parameters:
            ser (Union[bytes, str]): qb64b or qb64 serialization of seed or salt
                to be encrypted.
            pubkey (bytes): raw binary serialization of encryption public key
            code (str): derivation code of serialized plain text seed or salt
        """
        raw = pysodium.crypto_box_seal(ser, pubkey)
        return Cipher(raw=raw, code=code)


class Decrypter(Matter):
    """
    Decrypter is Matter subclass with method to decrypt the plain text from a
    ciper text of a fully qualified (qb64) private key/seed where private
    key/seed is the plain text. Decrypter uses assymetric (public, private) key
    decryption of the cipher text using its .raw as the decrypting (private) key
    and its .code to indicate the cipher suite for the decryption operation.

    For example .code == MtrDex.X25519 indicates that X25519 sealed box
    decyrption is used. The decryption key may be derived from an Ed25519
    signing private key that is associated with a nontransferable or basic derivation
    self certifying identifier. This allows use of the self certifying identifier
    to track or manage the encryption/decryption key pair. And could be used to
    provide additional authentication operations for using the
    encryption/decryption key pair. Support for this is provided at init time
    with the sigkey parameter which allows deriving the decryption private key
    from the fully qualified sigkey (signing key).

    See Matter for inherited attributes and properties:

    Attributes:

    Properties:


    Methods:
        decrypt: create cipher text

    """

    def __init__(self, code=MtrDex.X25519_Private, seed=None, **kwa):
        """
        Assign decrypting cipher suite function to ._decrypt

        Parameters:  See Matter for inheirted parameters
            raw (bytes): private decryption key derived from seed (private signing key)
            qb64b (bytes): fully qualified private decryption key
            qb64 (str): fully qualified private decryption key
            code (str): derivation code for private decryption key
            seed (Union[bytes, str]): qb64b or qb64 of signing key seed used to
                derive raw which is private decryption key
        """
        try:
            super(Decrypter, self).__init__(code=code, **kwa)
        except EmptyMaterialError as ex:
            if seed:
                signer = Signer(qb64b=seed)
                if signer.code not in (MtrDex.Ed25519_Seed,):
                    raise ValueError("Unsupported signing seed derivation code = {}."
                                     "".format(signer.code))
                # verkey, sigkey = pysodium.crypto_sign_seed_keypair(signer.raw)
                sigkey = signer.raw + signer.verfer.raw  # sigkey is raw seed + raw verkey
                raw = pysodium.crypto_sign_sk_to_box_sk(sigkey)  # raw private encrypt key
                super(Decrypter, self).__init__(raw=raw, code=code, **kwa)
            else:
                raise

        if self.code == MtrDex.X25519_Private:
            self._decrypt = self._x25519
        else:
            raise ValueError("Unsupported decrypter code = {}.".format(self.code))

    def decrypt(self, ser=None, cipher=None, transferable=False):
        """
        Returns:
            Salter or Signer instance derived from plain text decrypted from
            encrypted cipher text material given by ser or cipher. Plain text
            that is orignally encrypt should always be fully qualified (qb64b)
            so that derivaton code of plain text is preserved through
            encryption/decryption round trip.

        Parameters:
            ser (Union[bytes,str]): qb64b or qb64 serialization of cipher text
            cipher (Cipher): optional Cipher instance when ser is None
            transferable (bool): True means associated verfer of returned
                signer is transferable. False means non-transferable
        """
        if not (ser or cipher):
            raise EmptyMaterialError("Neither ser or cipher are provided.")

        if ser:  # create cipher to ensure valid derivation code of material in ser
            cipher = Cipher(qb64b=ser)

        return (self._decrypt(cipher=cipher,
                              prikey=self.raw,
                              transferable=transferable))

    @staticmethod
    def _x25519(cipher, prikey, transferable=False):
        """
        Returns plain text as Salter or Signer instance depending on the cipher
            code and the embedded encrypted plain text derivation code.

        Parameters:
            cipher (Cipher): instance of encrypted seed or salt
            prikey (bytes): raw binary decryption private key derived from
                signing seed or sigkey
            transferable (bool): True means associated verfer of returned
                signer is transferable. False means non-transferable
        """
        pubkey = pysodium.crypto_scalarmult_curve25519_base(prikey)
        plain = pysodium.crypto_box_seal_open(cipher.raw, pubkey, prikey)  # qb64b
        # ensure raw plain text is qb64b or qb64 so its derivation code is round tripped
        if cipher.code == MtrDex.X25519_Cipher_Salt:
            return Salter(qb64b=plain)
        elif cipher.code == MtrDex.X25519_Cipher_Seed:
            return Signer(qb64b=plain, transferable=transferable)
        else:
            raise ValueError("Unsupported cipher text code = {}.".format(cipher.code))
