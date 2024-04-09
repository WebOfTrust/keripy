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
