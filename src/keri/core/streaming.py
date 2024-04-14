# -*- coding: utf-8 -*-
"""
keri.core.streaming module

Provides support for Streamer and Annotater
"""


from typing import NamedTuple
from collections import namedtuple

from .. import kering

from .. import help


from . import coring


def annot():
    """Annotate CESR stream"""



def denot():
    """De-annotate CESR stream"""



class Streamer:
    """
    Streamer is CESR sniffable stream class


    Has the following public properties:

    Properties:


    Methods:


    Hidden:



    """

    def __init__(self, stream):
        """Initialize instance


        Parameters:
            stream (bytes | bytearray): sniffable CESR stream


        """
        self._stream = bytes(stream)


    @property
    def stream(self):
        """stream property getter
        """
        return self._stream

    @property
    def text(self):
        """expanded stream as qb64 text
        Returns:
           stream (bytes): expanded text qb64 version of stream

        """
        return self._stream

    @property
    def binary(self):
        """compacted stream as qb2 binary
        Returns:
           stream (bytes): compacted binary qb2 version of stream

        """
        return self._stream

    @property
    def texter(self):
        """expanded stream as Texter instance
        Returns:
           texter (Texter): Texter primitive of stream suitable wrapping

        """
        return self._stream





