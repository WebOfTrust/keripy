# -*- coding: utf-8 -*-
"""
Generic Constants and Classes
"""
import sys
from collections import namedtuple

Versionage = namedtuple("Versionage", "major minor")

Version = Versionage(major=1, minor=0)  # KERI Protocol Version

SEPARATOR =  "\r\n\r\n"
SEPARATOR_BYTES = SEPARATOR.encode("utf-8")


class KeriError(Exception):
    """
    Base Class for keri exceptions

    To use   raise KeriError("Error: message")
    """


class ShortageError(KeriError):
    """
    Not Enough bytes in buffer for complete message or material
    Usage:
        raise ShortageError("error message")
    """


class EmptyMaterialError(KeriError):
    """
    Empty or Missing Crypto Material
    Usage:
        raise EmptyMaterialError("error message")
    """


class ClosedError(KeriError):
    """
    Error attempting to use closed (unopened) resource such as file, database etc that is

    Usage:
        raise ClosedError("error message")
    """

class DatabaseError(KeriError):
    """
    Error accessing database

    Usage:
        raise DatabaseError("error message")
    """


class MissingEntryError(DatabaseError):
    """
    Error Missing entry or entry not found in database

    Usage:
        raise MissingEntryError("error message")
    """


class ValidationError(KeriError):
    """
    Validation related errors
    Usage:
        raise ValidationError("error message")
    """


class MissingSignatureError(ValidationError):
    """
    Error At least One but Missing Enough Signatures for Threshold
    Usage:
        raise MissingSignatureError("error message")
    """


class MissingDelegatingSealError(ValidationError):
    """
    Error Missing Event with Delegating Seal
    Usage:
        raise MissingDelegatingSealError("error message")
    """


class OutOfOrderError(ValidationError):
    """
    Error prior event missing from log so can't verify sigs on this event
    Usage:
        raise OutOfOrderError("error message")
    """


class LikelyDuplicitousError(ValidationError):
    """
    Error event is likely duplicitous
    Usage:
        raise LikelyDuplicitousError("error message")
    """


class UnverifiedReceiptError(ValidationError):
    """
    Error reciept is unverfied
    Usage:
        raise UnverifiedReceiptError("error message")
    """


class UnverifiedTransferableReceiptError(ValidationError):
    """
    Error reciept from transferable identifier (validator) is unverfied
    Usage:
        raise UnverifiedTransferableReceiptError("error message")
    """


class VersionError(ValidationError):
    """
    Bad or Unsupported Version

    Usage:
        raise VersionError("error message")
    """


class DerivationError(ValidationError):
    """
    Derivation related errors
    Usage:
        raise DerivationError("error message")
    """


class DerivationCodeError(ValidationError):
    """
    Derivation Code cryppto material conversion errors
    Usage:
        raise DerivationCodeError("error message")
    """


class UnexpectedCountCodeError(DerivationCodeError):
    """
    Encountered count code start char "-" unexpectantly
    Usage:
        raise DerivationCodeError("error message")
    """


class UnexpectedOpCodeError(DerivationCodeError):
    """
    Encountered opcode code start char "_" unexpectantly
    Usage:
        raise DerivationCodeError("error message")
    """
