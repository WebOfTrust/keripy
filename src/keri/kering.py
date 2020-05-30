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

class ValidationError(KeriError):
    """
    Validation related errors
    Usage:
        raise ValidationError("error message")
    """

class VersionError(ValidationError):
    """
    Validation related errors
    Usage:
        raise ValidationError("error message")
    """
