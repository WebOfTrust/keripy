# -*- encoding: utf-8 -*-
"""
keri.core.coring module

"""

from dataclasses import dataclass, astuple


@dataclass(frozen=True)
class SelectCodex:
    """
    Select codex of selector characters
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.
    """
    skip: str = '_'  #  start with next character
    two: str = '0'  # use two character table.

    def __iter__(self):
        return iter(astuple(self))

Select = SelectCodex()  # Make instance

@dataclass(frozen=True)
class OneCodex:
    """
    One codex of one character length derivation codes
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in One results in 1 Base64 pad byte.
    """
    Ed25519N: str =  'A'  # Ed25519 verification key non-transferable, basic derivation.
    X25519: str = 'B'  # X25519 public encryption key, converted from Ed25519.
    Ed25519: str = 'C'  #  Ed25519 verification key basic derivation
    Blake3_256: str = 'D'  # Blake3 256 bit digest self-addressing derivation.
    Blake2b_256: str = 'E'  # Blake2b 256 bit digest self-addressing derivation.
    Blake2s_256: str = 'F'  # Blake2s 256 bit digest self-addressing derivation.
    ECDSA_256k1N: str = 'G'  # ECDSA secp256k1 verification key non-transferable, basic derivation.
    ECDSA_256k1: str = 'H'  #  Ed25519 verification key basic derivation
    SHA3_256: str = 'I'  # SHA3 256 bit digest self-addressing derivation.
    SHA2_256: str = 'J'  # SHA2 256 bit digest self-addressing derivation.

    def __iter__(self):
        return iter(astuple(self))

One = OneCodex()  # Make instance

@dataclass(frozen=True)
class TwoCodex:
    """
    Two codex of two character length derivation codes
    Only provide defined characters. Undefined are left out so that inclusion
    exclusion via 'in' operator works.

    Note binary length of everything in Two results in 2 Base64 pad bytes.
    """
    Ed25519: str =  '0A'  # Ed25519 signature.
    ECDSA_256k1: str = '0B'  # ECDSA secp256k1 signature.


    def __iter__(self):
        return iter(astuple(self))

Two = TwoCodex()  #  Make instance
