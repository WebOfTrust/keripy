# -*- encoding: utf-8 -*-
"""
keri.spac.payloading module

"""

from collections import namedtuple

from keri.core import coring, MtrDex
from keri.kering import InvalidSoftError, InvalidCodeError


PayloadTypage = namedtuple("PayloadTypage", 'HOP RFI RFA RFD SCS')

PayloadTypes = PayloadTypage(HOP='HOP', RFI='RFI', RFA='RFA', RFD='RFD', SCS='SCS')


class PayloadTyper(coring.Tagger):
    """
    PayloadTyper is subclass of Tagger, cryptographic material, for formatted
    message types (PayloadTypes) in Base64. Leverages Tagger support compact special
    fixed size primitives with non-empty soft part and empty raw part.

    PayloadTyper provides a more compact representation than would be obtained by
    converting the raw ASCII representation to Base64.

    Attributes:

    Inherited Properties:  (See Tagger)
        code (str): hard part of derivation code to indicate cypher suite
        hard (str): hard part of derivation code. alias for code
        soft (str): soft part of derivation code fs any.
                    Empty when ss = 0.
        both (str): hard + soft parts of full text code
        size (int | None): Number of quadlets/triplets of chars/bytes including
                            lead bytes of variable sized material (fs = None).
                            Converted value of the soft part (of len ss) of full
                            derivation code.
                          Otherwise None when not variably sized (fs != None)
        fullSize (int): full size of primitive
        raw (bytes): crypto material only. Not derivation code or lead bytes.
        qb64 (str): Base64 fully qualified with derivation code + crypto mat
        qb64b (bytes): Base64 fully qualified with derivation code + crypto mat
        qb2  (bytes): binary with derivation code + crypto material
        transferable (bool): True means transferable derivation code False otherwise
        digestive (bool): True means digest derivation code False otherwise
        prefixive (bool): True means identifier prefix derivation code False otherwise
        special (bool): True when soft is special raw is empty and fixed size
        composable (bool): True when .qb64b and .qb2 are 24 bit aligned and round trip
        tag (str): B64 primitive without prepad (strips prepad from soft)


    Properties:
        type (str):  message type from PayloadTypes of PayloadTypage

    Inherited Hidden:  (See Tagger)
        _code (str): value for .code property
        _soft (str): soft value of full code
        _raw (bytes): value for .raw property
        _rawSize():
        _leadSize():
        _special():
        _infil(): creates qb64b from .raw and .code (fully qualified Base64)
        _binfil(): creates qb2 from .raw and .code (fully qualified Base2)
        _exfil(): extracts .code and .raw from qb64b (fully qualified Base64)
        _bexfil(): extracts .code and .raw from qb2 (fully qualified Base2)

    Hidden:


    Methods:

    """

    def __init__(self, qb64b=None, qb64=None, qb2=None, tag='', type='', **kwa):
        """
        Inherited Parameters:  (see Tagger)
            raw (bytes | bytearray | None): unqualified crypto material usable
                    for crypto operations.
            code (str): stable (hard) part of derivation code
            soft (str | bytes): soft part for special codes
            rize (int | None): raw size in bytes when variable sized material not
                        including lead bytes if any
                        Otherwise None
            qb64b (bytes | None): fully qualified crypto material Base64
            qb64 (str | bytes | None):  fully qualified crypto material Base64
            qb2 (bytes | None): fully qualified crypto material Base2
            strip (bool): True means strip (delete) matter from input stream
                bytearray after parsing qb64b or qb2. False means do not strip
            tag (str | bytes):  Base64 plain. Prepad is added as needed.

        Parameters:
            tsp (str):  message type from Tsps of Tspage

        """
        if not (qb64b or qb64 or qb2):
            if type:
                tag = type

        super(PayloadTyper, self).__init__(qb64b=qb64b, qb64=qb64, qb2=qb2, tag=tag, **kwa)

        if self.code not in (MtrDex.Tag3, ):
            raise InvalidCodeError(f"Invalid code={self.code} for Tsper "
                                   f"{self.type=}.")
        if self.type not in PayloadTypes:
            raise InvalidSoftError(f"Invalid tsp={self.type} for Tsper.")

    @property
    def type(self):
        """Returns:
                tag (str): B64 primitive without prepad (strips prepad from soft)

        Alias for self.tag

        """
        return self.tag
