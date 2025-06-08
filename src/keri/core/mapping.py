# -*- coding: utf-8 -*-
"""
keri.core.mapping module

Creates label value, field map data structures
"""
from collections.abc import Mapping, Iterable
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from dataclasses import dataclass, astuple, asdict


from ..kering import (Colds, EmptyMaterialError, InvalidValueError,
                      DeserializeError, SerializeError)

from ..help import isNonStringIterable, Reatt

from .counting import  Codens, CtrDex_2_0, UniDex_2_0, Counter
from .coring import MtrDex, Matter, Labeler, LabelDex, Decimer, DecDex



@dataclass(frozen=True)
class EscapeCodex:
    """EscapeCodex is codex of values that may need to be escaped
    in order to round trip correctly as either labels or values in a field map
    via Mapper.

    Only provide defined codes.
    Undefined are left out so that inclusion(exclusion) via 'in' operator works.
    """
    Escape: str = '1AAO'  # Escape code for excaping special map fields
    Null: str = '1AAK'  # Null None or empty value
    No: str = '1AAL'  # No Falsey Boolean value
    Yes: str = '1AAM'  # Yes Truthy Boolean value
    Decimal_L0: str = '4H'  # Decimal B64 string float and int lead size 0
    Decimal_L1: str = '5H'  # Decimal B64 string float and int lead size 1
    Decimal_L2: str = '6H'  # Decimal B64 string float and intlead size 2
    Decimal_Big_L0: str = '7AAH'  # Decimal B64 string float and int big lead size 0
    Decimal_Big_L1: str = '8AAH'  # Decimal B64 string float and int big lead size 1
    Decimal_Big_L2: str = '9AAH'  # Decimal B64 string float and int big lead size 2
    Tag1:  str = '0J'  # 1 B64 char tag with 1 pre pad
    Tag2:  str = '0K'  # 2 B64 char tag
    Tag3:  str = 'X'  # 3 B64 char tag
    Tag4:  str = '1AAF'  # 4 B64 char tag
    Tag5:  str = '0L'  # 5 B64 char tag with 1 pre pad
    Tag6:  str = '0M'  # 6 B64 char tag
    Tag7:  str = 'Y'  # 7 B64 char tag
    Tag8:  str = '1AAN'  # 8 B64 char tag
    Tag9:  str = '0N'  # 9 B64 char tag with 1 pre pad
    Tag10: str = '0O'  # 10 B64 char tag
    Tag11: str = 'Z'   # 11 B64 char tag
    StrB64_L0:     str = '4A'  # String Base64 Only Leader Size 0
    StrB64_L1:     str = '5A'  # String Base64 Only Leader Size 1
    StrB64_L2:     str = '6A'  # String Base64 Only Leader Size 2
    StrB64_Big_L0: str = '7AAA'  # String Base64 Only Big Leader Size 0
    StrB64_Big_L1: str = '8AAA'  # String Base64 Only Big Leader Size 1
    StrB64_Big_L2: str = '9AAA'  # String Base64 Only Big Leader Size 2
    Label1:        str = 'V'  # Label1 1 bytes for label lead size 1
    Label2:        str = 'W'  # Label2 2 bytes for label lead size 0
    Bytes_L0:     str = '4B'  # Byte String lead size 0
    Bytes_L1:     str = '5B'  # Byte String lead size 1
    Bytes_L2:     str = '6B'  # Byte String lead size 2
    Bytes_Big_L0: str = '7AAB'  # Byte String big lead size 0
    Bytes_Big_L1: str = '8AAB'  # Byte String big lead size 1
    Bytes_Big_L2: str = '9AAB'  # Byte String big lead size 2

    def __iter__(self):
        return iter(astuple(self))

EscapeDex = EscapeCodex()  # Make instance


# ToDo;  ""saidive"" Mapper that computs SAID on any map that has a 'd' field
# also recursively computes nested SAID on any nested maps using the ACDC
# most compact version SAID algorithm if "compactive" is True

class Mapper:
    """Mapper class for CESR native serializations of field maps of ordered
    (label, value) pairs (aka fields). As an abbreviation a field map in dict
    form is called a mad (map dict).  Includes the counter map body group as part
    of serialization.

    Properties:
        qb64 (str): mad serialization in qb64
        qb64b (bytes): mad serialization in qb64b
        qb2 (bytes): mad serialization in qb2
        count (int): number of quadlets/triplets in mad serialization
        byteCount (int): number of bytes in .count quadlets/triplets given cold
        size (int):  Number of bytes of field map serialization in text
                domain (qb64b)

    Hidden Attributes:
        ._mad (bytes): field map dict
        ._qb64b (bytes): mad serialization in qb64b text domain
        ._count (int): number of quadlets/triplets in mad serialization

    """

    def __init__(self, *, mad=None, qb64=None, qb64b=None, qb2=None, strip=False,
                 verify=True):
        """Initialize instance

        Parameters:
            mad (Mapping|Iterable|None):  Either dict or iterable of duples
                of (field, value) pairs or None. Ignored if None
            qb64 (str|bytes|bytearray|None): mad serialization in qb64 text domain
                Ignored if None or fields provided. Alias for qb64b
            qb64b (str|bytes|bytearray|None): mad serialization in qb64b text domain
                Ignored if None or mad provided. Alias for qb64
            qb2 (bytes|bytearray|None): fields serialization in qb2 binary domain
                Ignored if None or mad provided
            strip (bool):  True means strip mapper contents from input stream
                bytearray after parsing qb64, qb64b or qb2. False means do not strip.
                default False
            verify (bool): True means verify serialization against mad.

        Assumes that when qb64 or qb64b or qb2 are provided that they have
            already been extracted from a stream and are self contained

        """
        if isNonStringIterable(mad):
            mad = dict(mad)
        self._mad = mad if mad is not None else dict()
        self._qb64b = b''  # override later
        self._count = 0   # override later

        qb64b = qb64b if qb64b is not None else qb64  # copy qb64 to qb64b
        if mad or not (qb64b or qb2):
            mad = mad if mad is not None else dict()  # defaults to empty
            self._exhale(mad=mad)  # sets ._mad, ._qb64b, and ._count

        else:
            if qb64b:
                if hasattr(qb64b, "encode"):
                    qb64b = qb64b.encode()

                ctr = Counter(qb64b=qb64b)  # peek at counter
                bs = ctr.byteCount() + ctr.byteSize()
                buf = qb64b[:bs]
                if strip and isinstance(qb64b, bytearray):
                    del qb64b[:bs]


            elif qb2:
                ctr = Counter(qb2=qb2)  # peek at counter
                bs = ctr.byteCount(cold=Colds.bny) + ctr.byteSize(Colds.bny)
                buf = encodeB64(qb2[:bs])  # deserialize in qb64 text domain
                if strip and isinstance(qb2, bytearray):
                    del qb2[:bs]

            else:
                raise EmptyMaterialError(f"Need mad or qb64 or qb64b or qb2.")

            self._inhale(buf)  # sets ._mad, ._qb64b, and ._count

    @property
    def mad(self):
        """Getter for ._mad

        Returns:
              mad (dict): field map dict
        """
        return self._mad


    @property
    def qb64(self):
        """Getter for ._qb64b as text domain str

        Returns:
              qb64 (str): field map serialization
        """
        return self._qb64b.decode()


    @property
    def qb64(self):
        """Getter for ._qb64b as text domain str

        Returns:
              qb64 (str): field map serialization
        """
        return self._qb64b.decode()


    @property
    def qb64b(self):
        """Getter for ._qb64b as text domain bytes
        Returns:
            qb64b (bytes): field map serialization
        """
        return self._qb64b


    @property
    def qb2(self):
        """Getter for ._qb64b converted to qb2 binary domain

        Returns:
              qb2 (bytes): field map serialization as binary domain

        """
        return decodeB64(self._qb64b)


    @property
    def count(self):
        """Getter for ._count. Makes ._count read only
        Returns:
            count (int):  count value in quadlets/triples chars/bytes  of
                field map serialization

        """
        return self._count


    @property
    def size(self):
        """Number of bytes of field map serialization in text domain (qb64b)

        Returns:
            size (int):  Number of bytes of field map serialization in text
                domain (qb64b)

        """
        return self._count * 4  # always text domain


    def byteCount(self, cold=Colds.txt):
        """Computes number of bytes from .count quadlets/triplets given cold

        Returns:
            byteCount (int): number of bytes in .count quadlets/triplets given cold

        Parameters:
            cold (str): value of Coldage to indicate if text (qb64) or binary (qb2)
                        in order to convert .count quadlets/triplets to byte count
                        if not Colds.txt or Colds.bny raises ValueError
        """
        if cold == Colds.txt:  # quadlets
            return self.count * 4

        if cold == Colds.bny:  # triplets
            return self.count * 3

        raise ValueError(f"Invalid {cold=} for byte count conversion")


    def _inhale(self, ser=None):
        """Deserializes ser into .mad

        Parameters:
            ser (str|bytes|bytearray|None): mad serialization in qb64b text domain
                Uses self.qb64b if None
        """
        ser = ser if ser is not None else self.qb64b
        self._qb64b = bytes(ser)  # make bytes copy

        ser = bytearray(ser)  # make bytearray copy so can consume on the go
        mad = dict()

        # consume map ctr assumes already extracted full map
        mctr = Counter(qb64b=ser, strip=True)
        if mctr.name not in ('GenericMapGroup', 'BigGenericMapGroup'):
            raise DeserializeError(f"Expected GenericMapGroup got counter name="
                                   f"{mctr.name}")
        self._count = mctr.count + (mctr.fullSize // 4)  # include counter & contents
        if len(ser) != mctr.count * 4:
            raise DeserializeError(f"Invalid map content qb64b for count="
                                   f"{mctr.count}")

        while (ser):
            try:
                label = Labeler(qb64b=ser, strip=True).label
                mad[label] = self._deserialize(ser)
            except  InvalidValueError as ex:
                raise DeserializeError(f"Invalid value while deserializing") from ex

        self._mad = mad
        return self.mad


    def _deserialize(self, ser):
        """Recursively deserializes ser as value

        Parameters:
            ser (bytearray): deserializable bytearray for value

        Returns:
           value (None|bool|int|float|str|list|dict): deserialized value

        """
        if ser[0] == ord(b'-'):  # value is group (Counter) serialization
            vctr = Counter(qb64b=ser, strip=True)
            if vctr.name in ('GenericListGroup', 'BigGenericListGroup'):
                ls = vctr.byteCount()
                lser = ser[:ls]  # extract list bytes
                del ser[:ls]  # strip list bytes from ser
                value = []
                while lser:  # recursively deserialize list elements
                    value.append(self._deserialize(lser))

            elif vctr.name in ('GenericMapGroup', 'BigGenericMapGroup'):
                ms = vctr.byteCount()
                mser = ser[:ms]  # extract map bytes
                del ser[:ms]  # strip map bytes from ser
                value = {}
                while mser:  # recursively deserialize map items
                    label = Labeler(qb64b=mser, strip=True).label
                    value[label] = self._deserialize(mser)
            else:
                raise DeserializeError("Invalid counter name={vctr.name}")

        else:  # ser is primitive (Matter) serialization
            mtr = Matter(qb64b=ser, strip=True)
            if mtr.code == EscapeDex.Escape:  # yes escaped so get escaped value
                value = Matter(qb64b=ser, strip=True).qb64  # value is verbatim qb64
            else:
                if mtr.code == MtrDex.Null:
                    value = None
                elif mtr.code == MtrDex.Yes:
                    value = True
                elif mtr.code == MtrDex.No:
                    value = False
                elif mtr.code in DecDex:
                    value = Decimer(qb64b=mtr.qb64b).decimal
                elif mtr.code in LabelDex:
                    value = Labeler(qb64b=mtr.qb64b).text
                else:
                    value = mtr.qb64

        return value


    def _exhale(self, mad=None):
        """Serializes field map dict, mad

        Parameters:
            mad (dict|None): serializable field map dict. Uses self.mad if None

        Returns:
            ser (bytes): qb64b serialization of mad
        """
        mad = mad if mad is not None else self.mad

        ser = bytearray()  # full field map serialization as qb64 with counter
        bdy = bytearray()
        for l, v in mad.items():  # assumes valid field order & presence
            try:
                bdy.extend(Labeler(label=l).qb64b)
                bdy.extend(self._serialize(v))
            except InvalidValueError as ex:
                raise SerializeError("Invalid value while serializing") from ex

        ser.extend(Counter.enclose(qb64=bdy, code=Codens.GenericMapGroup))
        self._qb64b = bytes(ser)  # bytes so can sign, do crypto operations on it
        self._count = len(ser) // 4

        return self.qb64b


    def _serialize(self, val):
        """Recursively serializes val

        Parameters:
            val (None|bool|int|float|str|bytes|bytearray|list|dict): serializable value

        Returns:
            ser (bytearray): qb64b serialization of val

        """
        ser = bytearray()  # recursive serialization of val
        if val is None:
            ser.extend(Matter(raw=b'', code=MtrDex.Null).qb64b)
        elif isinstance(val, bool):
            if val:
                ser.extend(Matter(raw=b'', code=MtrDex.Yes).qb64b)
            else:
                ser.extend(Matter(raw=b'', code=MtrDex.No).qb64b)
        elif isinstance(val, (int, float)):
            ser.extend(Decimer(decimal=val).qb64b)
        elif isinstance(val, (str, bytes, bytearray)):
            try:
                primitive = Matter(qb64=val)
            except Exception as ex:  # not valid primitive
                ser.extend(Labeler(text=val).qb64b)  # so serialize as text
            else:  # valid primitive in qb64 format
                if len(primitive.qb64) != len(val):  # not complete so invalid
                    ser.extend(Labeler(text=val).qb64b)  # so serialize as text
                else:  # really valid complete primitive in qb64
                    if primitive.code in EscapeDex:  # verbatim text is special primitive
                        # need to escape so insert escape code
                        ser.extend(Matter(raw=b'', code=EscapeDex.Escape).qb64b)
                    ser.extend(primitive.qb64b)  # so serialize as primitive verbatim
        elif isinstance(val, Mapping):
            bdy = bytearray()
            for l, v in val.items():
                bdy.extend(Labeler(label=l).qb64b)
                bdy.extend(self._serialize(v))
            ser.extend(Counter.enclose(qb64=bdy,
                                       code=Codens.GenericMapGroup))
        elif isinstance(val, Iterable):
            bdy = bytearray()
            for v in val:
                bdy.extend(self._serialize(v))
            ser.extend(Counter.enclose(qb64=bdy,
                                       code=Codens.GenericListGroup))
        else:
            raise SerializeError(f"Nonserializible {val=}")

        return ser
