# -*- coding: utf-8 -*-
"""
Generic Constants and Classes
"""

import sys

SEPARATOR =  "\r\n\r\n"
SEPARATOR_BYTES = SEPARATOR.encode("utf-8")


class LeopyError(Exception):
    """
    Base Class for leopy exceptions

    To use   raise LeopyError("Error: message")
    """

class ValidationError(LeopyError):
    """
    Validation related errors
    Usage:
        raise ValidationError("error message")
    """
