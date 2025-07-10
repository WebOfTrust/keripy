# -*- coding: utf-8 -*-
"""
keri.core.mapping module

Creates label value, field map data structures
"""
from copy import deepcopy
from collections.abc import Mapping, Iterable
from base64 import urlsafe_b64encode as encodeB64
from base64 import urlsafe_b64decode as decodeB64
from dataclasses import dataclass, astuple, asdict
import json

import cbor2 as cbor
import msgpack

from ordered_set import OrderedSet as oset

from ..kering import (Colds, sniff, Kinds, EmptyMaterialError, InvalidValueError,
                      DeserializeError, SerializeError)

from ..help import isNonStringIterable, Reatt

from .counting import  Codens, CtrDex_2_0, UniDex_2_0, Counter
from .coring import (MtrDex, Matter, Labeler, LabelDex, DecDex, Decimer,
                     DigDex, Diger)



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
    Empty: str = '1AAP'  # Empty value for Nonce, UUID, SAID, state or related fields
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
# field with designated label like '$id' for schema
# also recursively computes nested SAID on any nested maps using the ACDC
# most compact version SAID algorithm if "compactive" is True
"""
ACDC .csad and its serialization .craw is the most compact sad and raw
    respectively. This must be generated in order to compute the SAID of the ACDC,
    as well the SAIDs of any nested parts of the uncompacted sad regardless of
    degree of compactness. The most compact SAID is the one that is anchored in
    its TEL. The most compact said is literally the said of .csad computed via
    the most compact serialization .craw

    So need to hoist serder SAID calculation code to own method so ACDC can
    override SAID calculation with most compact variant SAID calculation.
    For ACDC, its .sad SAID is the most compact SAID at result of most compact
    calculation. Therefor to generate .sad take given sad and then perform most
    compact algorithm and then assign to .sad

    so makify and verify for ACDCs is different because of most compact SAID

"""

class Mapper:
    """Mapper class for CESR native serializations of field maps of ordered
    (label, value) pairs (aka fields). As an abbreviation a field map in dict
    form is called a mad (map dict).  Includes the counter map body group as part
    of serialization.

    Class Attributes:
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs

    Properties:
        raw (bytes): mad serialization as raw/qb64b bytes alias for .qb64b
        qb64b (bytes): mad serialization as qb64b bytes alias for .raw
        qb64 (str): mad serialization as qb64 str
        qb2 (bytes): mad serialization in qb2
        count (int): number of quadlets/triplets in mad serialization
        byteCount (int): number of bytes in .count quadlets/triplets given cold
        size (int):  Number of bytes of field map serialization in text
                domain (qb64b)
        strict (bool): True means labels must match strict formal limitations
                            labels must be valid attribute names,
                            i.e. rb'^[a-zA-Z_][a-zA-Z0-9_]*$'
                            which usually serialize more compactly
                       False means labels may be any utf-8 text
        said (str|None): primary said field value if any. None otherwise
                         primary has same label as zeroth item in .saids
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs


    Hidden Attributes:
        ._mad (bytes): field map dict (MAD = MAp Dict)
        ._raw (bytes): expanded mad serialization in qb64b text bytes domain
        ._count (int): number of quadlets/triplets in mad serialization
        ._strict (bool): labels strict format for strict property
        ._saids (dict): default top-level said fields and codes
        ._saidive (bool): compute saids or not
        ._kind (str): serialization kind from Kinds

    """
    Saids = dict(d=DigDex.Blake3_256)  # default said field label with digestive code
    Dummy = "#"  # dummy spaceholder char for SAID. Must not be a valid Base64 char

    def __init__(self, *, mad=None, raw=None, qb64b=None, qb64=None, qb2=None,
                 strip=False, makify=False, verify=True, strict=True,
                 saids=None, saidive=False, kind=Kinds.cesr):
        """Initialize instance

        Parameters:
            mad (Mapping|Iterable|None):  Either dict or iterable of duples
                of (field, value) pairs or None. Ignored if None
            raw (str|bytes|bytearray|None): mad serialization in qb64b text domain
                bytes domain. Alias for qb64b/qb64a. Compatible interface with
                Serder
                Ignored if None or mad provided. Alias for qb64
            qb64b (str|bytes|bytearray|None): mad serialization in qb64b text
                domain bytes/str. Compatible interface with Counter
                Ignored if None or fields provided. Alias for qb64
            qb64 (str|bytes|bytearray|None): mad serialization in qb64b text
                domain str/bytes. Compatible interface with Counter
                Ignored if None or mad provided. Alias for qb64b
            qb2 (bytes|bytearray|None): fields serialization in qb2 binary domain
                Ignored if None or mad provided. Compatible interface with Counter
            strip (bool):  True means strip mapper contents from input stream
                bytearray after parsing qb64, qb64b or qb2. False means do not strip.
                default False. Only applicable when native CESR (kind == Kinds.cesr)
            makify (bool): True means compute saids when .saidive
                           False means do not comput saids even when .saidive
            verify (bool): True means verify serialization against mad.
                           False means do not verify
            strict (bool): True means labels must match strict formal limitations
                            labels must be valid attribute names,
                            i.e. rb'^[a-zA-Z_][a-zA-Z0-9_]*$'
                            which usually serialize more compactly
                           False means labels may be any utf-8 text
            saids (dict): default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
            saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                            False means do not compute SAIDs


        Assumes that when qb64 or qb64b or qb2 are provided that they have
            already been extracted from a stream and are self contained

        """
        makify = True if makify else False
        verify = True if verify else False

        self._strict = True if strict else False
        self._saids = dict(saids if saids is not None else self.Saids)  # make copy
        self._saidive = True if saidive else False
        self._kind = kind

        if isNonStringIterable(mad):
            mad = deepcopy(mad)  # make deepcopy so does not mutate argument
        mad = mad if mad is not None else dict()
        qb64b = qb64b if qb64b is not None else qb64  # copy qb64 to qb64b
        raw = raw if raw is not None else qb64b # copy qb64b to raw

        if mad or not (raw or qb64b or qb2):  # mad may be empty if not others
            if makify and self.saidive:  # compute saids at top level
                raw, count = self._exhale(mad=mad, dummy=True, kind=kind) # first dummy serialization
                for label, code in self.saids.items():
                    if label in mad:  # has saidive field
                        said = Diger(ser=raw, code=code).qb64
                        mad[label] = said  # changes self._mad

            raw, count = self._exhale(mad=mad, kind=kind)
            self._raw = raw
            self._count = count
            self._mad = mad

        else:
            if raw:
                if hasattr(raw, "encode"):
                    raw = raw.encode()

                if kind == Kinds.cesr:
                    ctr = Counter(qb64b=raw)  # peek at counter
                    bs = ctr.byteCount() + ctr.byteSize()
                    buf = raw[:bs]
                    if strip and isinstance(raw, bytearray):
                        del raw[:bs]
                else:
                    buf = raw[:]

            elif qb2:
                if kind == Kinds.cesr:
                    ctr = Counter(qb2=qb2)  # peek at counter
                    bs = ctr.byteCount(cold=Colds.bny) + ctr.byteSize(Colds.bny)
                    buf = encodeB64(qb2[:bs])  # deserialize in qb64 text domain
                    if strip and isinstance(qb2, bytearray):
                        del qb2[:bs]
                else:
                    buf = raw[:]

            else:
                raise EmptyMaterialError(f"Need mad or qb64 or qb64b or qb2.")

            mad, raw, count, kind = self._inhale(buf, kind=kind)
            self._mad = mad
            self._raw = raw
            self._count = count
            self._kind = kind

        if self.saidive and not makify and verify:  # verify saids
            mad = dict(self.mad) # make shallow copy at top level
            raw, count = self._exhale(mad=mad, dummy=True, kind=kind) # make dummy copy
            for label, code in self.saids.items():
                if label in mad:  # has saidive field
                    said = Diger(ser=raw, code=code).qb64
                    if self.mad[label] != said:
                        raise InvalidValueError(f"Provided said field at {label=}"
                                                f" with value={self.mad[label]}"
                                                f" does not verify with computed"
                                                f" {said=}")


    @property
    def mad(self):
        """Getter for ._mad

        Returns:
              mad (dict): field map dict
        """
        return self._mad


    @property
    def raw(self):
        """Getter for ._raw as text domain bytes
        Returns:
            raw (bytes): field map serialization
        """
        return self._raw

    @property
    def qb64b(self):
        """Getter for ._raw as text domain bytes
        Returns:
            qb64b (bytes): field map serialization
        """
        return self._raw


    @property
    def qb64(self):
        """Getter for ._raw as text domain str

        Returns:
              qb64 (str): field map serialization
        """
        return self._raw.decode()


    @property
    def qb2(self):
        """Getter for ._raw converted to qb2 binary domain

        Returns:
              qb2 (bytes): field map serialization as binary domain

        """
        if self.kind != Kinds.cesr:
            raise ValueError(f"Binary domain undefined for non-native "
                                    f"kind={self.kind}")
        return decodeB64(self._raw)


    @property
    def count(self):
        """Getter for ._count. Makes ._count read only
        Returns:
            count (int|None):  count value in quadlets/triples chars/bytes  of
                               field map serialization when native CESR
                               Otherwise None when non-native

        """
        return self._count


    @property
    def size(self):
        """Number of bytes of field map serialization in text domain (qb64b)

        Returns:
            size (int):  Number of bytes of field map serialization in text
                domain (qb64b)

        """
        if self.kind != Kinds.cesr:
            return len(self.raw)

        return self._count * 4  # always text domain when native cesr

    @property
    def strict(self):
        """Getter for ._strict

        Returns:
              strict (bool): True means labels must match strict formal limitations
                               labels must be valid attribute names,
                               i.e. rb'^[a-zA-Z_][a-zA-Z0-9_]*$'
                               which usually serialize more compactly
                             False means labels may be any utf-8 text
        """
        return self._strict


    @property
    def said(self):
        """primary said field value if any. None otherwise

        Returns:
              said (str|None): primary said field value if any. None otherwise
                               primary has same label as zeroth item in .saids
        """
        if self.saidive and self.saids:
            l = list(self.saids.keys())[0]  # primary said is zeroth entry in said
            return self.mad.get(l, None)
        return None


    @property
    def saids(self):
        """Getter for ._saids

        Returns:
            saids (dict): default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        """
        return self._saids


    @property
    def saidive(self):
        """Getter for ._saidive

        Returns:
              saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                            False means do not compute SAIDs
        """
        return self._saidive

    @property
    def kind(self):
        """Getter for ._kind

        Returns:
              kind (str): serialization kind from Kinds
        """
        return self._kind


    def byteCount(self, cold=Colds.txt):
        """Computes number of bytes from .count quadlets/triplets given cold

        Returns:
            byteCount (int): number of bytes in .count quadlets/triplets given cold

        Parameters:
            cold (str): value of Coldage to indicate if text (qb64) or binary (qb2)
                        in order to convert .count quadlets/triplets to byte count
                        if not Colds.txt or Colds.bny raises ValueError
        """
        if self.kind != Kinds.cesr:
            raise ValueError(f"Byte count undefined for non-native kind={self.kind}")

        if cold == Colds.txt:  # quadlets
            return self.count * 4

        if cold == Colds.bny:  # triplets
            return self.count * 3

        raise ValueError(f"Invalid {cold=} for byte count conversion")


    def _inhale(self, ser=None, kind=Kinds.cesr):
        """Deserializes ser into .mad

        Returns:
            tuple(mad, raw, count, kind): results of deserialization where:
                mad is mapping dict deserialized from ser
                raw is bytes of ser
                count is number of bytes in raw
                kind is serialization kind of ser from sniffing

        Parameters:
            ser (str|bytes|bytearray|None): mad serialization in raw/qb64b
                text domain bytes. Uses self.raw if None
            kind (str): serialization kind from Kinds. Assumes already know what
                        kind from enclosing message sniff etc.
        """
        ser = ser if ser is not None else self.raw
        raw = bytes(ser)  # make bytes copy
        mad = dict()

        if kind == Kinds.cesr:  # native CESR
            ser = bytearray(ser)  # make bytearray copy so can consume on the go

            # consume map ctr assumes already extracted full map
            mctr = Counter(qb64b=ser, strip=True)
            if mctr.name not in ('GenericMapGroup', 'BigGenericMapGroup'):
                raise DeserializeError(f"Expected GenericMapGroup got counter name="
                                       f"{mctr.name}")

            count = mctr.count + (mctr.fullSize // 4)  # include counter & contents
            if len(ser) != mctr.count * 4:
                raise DeserializeError(f"Invalid map content qb64b for count="
                                       f"{mctr.count}")

            while (ser):
                try:
                    if self.strict:
                        label = Labeler(qb64b=ser, strip=True).label
                    else:
                        label = Labeler(qb64b=ser, strip=True).text
                    mad[label] = self._deserialize(ser)
                except  InvalidValueError as ex:
                    raise DeserializeError(f"Invalid value while deserializing") from ex

        else:  # non-native CESR
            count = None
            if kind == Kinds.json:
                try:
                    mad = json.loads(raw.decode())
                except Exception as ex:
                    raise DeserializeError(f"Error deserializing JSON: "
                                           f"{raw.decode()}") from ex

            elif kind == Kinds.mgpk:
                try:
                    mad = msgpack.loads(raw)
                except Exception as ex:
                    raise DeserializeError(f"Error deserializing MGPK: "
                        f"{raw.decode()}") from ex

            elif kind == Kinds.cbor:
                try:
                    mad = cbor.loads(raw)
                except Exception as ex:
                    raise DeserializeError(f"Error deserializing CBOR: "
                        f"{raw.decode()}") from ex

            else:
                raise DeserializeError(f"Invalid deserialization {kind=}")

        return (mad, raw, count, kind)


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
                    if self.strict:
                        label = Labeler(qb64b=mser, strip=True).label
                    else:
                        label = Labeler(qb64b=mser, strip=True).text
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


    def _exhale(self, mad=None, dummy=False, kind=Kinds.cesr):
        """Serializes field map dict, mad

        Parameters:
            mad (dict|None): serializable field map dict. Uses self.mad if None
            dummy (bool): True means dummy said fields given by .saids
                          False means do not dummy said fields given by .saids
            kind (str): serialization kind from Kinds

        Returns:
            ser (bytes): qb64b serialization of mad
        """
        mad = mad if mad is not None else self.mad

        if kind == Kinds.cesr:  # native CESR
            ser = bytearray()  # full field map serialization as qb64 with counter
            bdy = bytearray()
            for l, v in mad.items():  # assumes valid field order & presence
                try:
                    if self.strict:
                        bdy.extend(Labeler(label=l).qb64b)
                    else:
                        bdy.extend(Labeler(text=l).qb64b)

                    if dummy and l in self.saids:
                        try:  # use code of mad field value if present
                            code = Matter(qb64=v).code
                        except Exception:  # use default instead
                            code = self.saids[l]
                        # when code is digestive then we know we have to compute said dummy
                        # this accounts for aid fields that may or may not be saids
                        if code not in DigDex:  # if digestive then fill with dummy:
                            raise SerializeError(f"Unexpected non-digestive {code=} "
                                                 f"for value of SAID field label={l}")
                        if code != self.saids[l]:  # different than default
                            # remember actual code for field when not default so
                            # eventually computed said uses this code not default
                            self.saids[l] = code  # replace default with provided

                        v = self.Dummy * Matter.Sizes[code].fs
                        bdy.extend(v.encode())
                    else:
                        bdy.extend(self._serialize(v))
                except InvalidValueError as ex:
                    raise SerializeError("Invalid value while serializing") from ex

            ser.extend(Counter.enclose(qb64=bdy, code=Codens.GenericMapGroup))
            raw = bytes(ser)  # bytes so can sign, do crypto operations on it
            count = len(ser) // 4

        else:  # non-native CESR
            count = None
            if dummy:
                for label in self.saids:
                    if label in mad:
                        try:
                            code = Matter(qb64=mad[label]).code
                        except Exception:
                            code = self.saids[label]

                        # when code is digestive then we know we have to compute said dummy
                        # this accounts for aid fields that may or may not be saids
                        if code not in DigDex:  # if digestive then fill with dummy:
                            raise SerializeError(f"Unexpected non-digestive {code=} "
                                                         f"for value of SAID field label={l}")

                        if code != self.saids[label]:  # different than default
                            # remember actual code for field when not default so
                            # eventually computed said uses this code not default
                            self.saids[label] = code  # replace default with provided

                        mad[label] = self.Dummy * Matter.Sizes[code].fs


            if kind == Kinds.json:   # json.dumps returns str so must encode to bytes
                raw = json.dumps(mad, separators=(",", ":"), ensure_ascii=False).encode()

            elif kind == Kinds.mgpk:  # mgpk.dumps returns bytes
                raw = msgpack.dumps(mad)

            elif kind == Kinds.cbor:  # cbor.dumps returns bytes
                raw = cbor.dumps(mad)

            else:
                raise SerializeError(f"Unsupported serialization {kind=}")

        return (raw, count)


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
                if self.strict:
                    bdy.extend(Labeler(label=l).qb64b)
                else:
                    bdy.extend(Labeler(text=l).qb64b)
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


class Compactor(Mapper):
    """Compactor class that supports CESR native serializations of hierarchical
    partially disclosable nested field maps where each field map is an
    associative array of ordered (label, value) pairs (aka fields).
    This hierarchy supports the most compact SAID algorithm.
    Different degrees of partial disclosure can be used to support a process of
    graduated disclosure.

    This type of partial disclosure uses a tree of compactable field maps which
    tree can be partially or completely compacted or uncompacted by compacting
    or uncompacting the branches of the tree to/from the SAID of the branch.
    To clarify, a set of nested associative arrays forms a tree that can be
    partially compacted or uncompacted (contracted or expanded) at each nesting
    layer of each branch. This supports a process of graduated disclosure by
    changing the degree of compaction (uncompaction) expressed at a given stage
    in the graduated disclosure.

    The partial discosure of a hierarchy of associative arrays is different from
    the partial disclosure of a flat indexed array where one or more elements
    of the array are disclosed without disclosing other elements of the array.
    This later is often called 'selective disclosure'. But could be called indexed
    partial disclosure as opposed to hierarchical partial disclosure.
    Either could support a process of graduated disclosure.

    The Compactor class implements hierarchical graduated partial disclosure.
    (partor latin for to bear)

    The said field label default is 'd'.

    The most compact map SAID algorithm recursively computes the saids of nested
    field map that have SAID fields (usually labeled with 'd').
    The SAID serialization of a nested map becomes the field value of the
    associated field in its enclosing field map. This is used to  compute the
    serialization of the enclosing field map.
    The algorithm effectively rolls up the branches of a tree of
    nested field maps where each branch is rolled up into a node field whose
    value is the SAID of the rolled up branch. Nested field maps without said
    fields are not rolled up.

    As an abbreviation a field map in dict form is called a mad (map dict).
    Includes the counter map body group as part of serialization.

    Inherited Class Attributes:
        Saids (dict):  default saidive fields at top-level. Assumes .mad already
            in most compact form.
            Each key is label of saidive field.
            Each value is default primitive code of said digest value to be
                computed from serialized dummied .mad
        Dummy (str): dummy character for computing SAIDs

    Inherited Properties: (see Mapper)
        raw (bytes): mad serialization as raw/qb64b bytes alias for .qb64b
        qb64b (bytes): mad serialization as qb64b bytes alias for .raw
        qb64 (str): mad serialization as qb64 str
        qb2 (bytes): mad serialization in qb2
        count (int): number of quadlets/triplets in mad serialization
        byteCount (int): number of bytes in .count quadlets/triplets given cold
        size (int):  Number of bytes of field map serialization in text
                domain (qb64b)
        strict (bool): True means labels must match strict formal limitations
                            labels must be valid attribute names,
                            i.e. rb'^[a-zA-Z_][a-zA-Z0-9_]*$'
                            which usually serialize more compactly
                       False means labels may be any utf-8 text
        said (str|None): primary said field value if any. None otherwise
                         primary has same label as zeroth item in .saids
        saids (dict):   default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
        saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                        False means do not compute SAIDs

    Properties:
        leaves (dict): mapper at each leaf with computed said for leaf as
                             keyed by path to leaf, value is Mapper instance
        partials (dict|None): mapper of partially disclosable variants of with
                               fully computed saids for its leaves.
                               keyed by tuple of leaf paths,
                               value is Mapper instance.
                             None means have yet to expand
        iscompact (bool|None): True means one leaf with path = '' i.e.
                                        leaf is at top level and has said
                                        but does not verify said
                                     False if at least one leaf but path is not
                                        at top level
                                     None means no leaves so not compactive
                                        i.e. either has not been saidified yet
                                        or cannot be

    Hidden Attributes:
        ._mad (bytes): field map dict (MAD = MAp Dict)
        ._raw (bytes): expanded mad serialization in qb64b text bytes domain
        ._count (int): number of quadlets/triplets in mad serialization
        ._strict (bool): labels strict format for strict property
        ._saids (dict): default top-level said fields and codes
        ._saidive (bool): compute saids or not
        ._leaves (dict): mad of each leaf indexed by path to leaf
        ._partials (dict|None): partially compacted mad with fully computed saids
                           indexd by tuple of leaf paths in mad

    """

    def __init__(self, saidive=True, **kwa):
        """Initialize instance

        Inherited Parameters:  (see Mapper)
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
            makify (bool): True means compute saids when .saidive
                           False means do not comput saids even when .saidive
            verify (bool): True means verify serialization against mad.
                           False means do not verify
            strict (bool): True means labels must match strict formal limitations
                            labels must be valid attribute names,
                            i.e. rb'^[a-zA-Z_][a-zA-Z0-9_]*$'
                            which usually serialize more compactly
                           False means labels may be any utf-8 text
            saids (dict): default saidive fields at top-level.
                          Assumes .mad already in most compact form.
                          Each key is label of saidive field.
                          Each value is default primitive code of said digest
                              value to be computed from serialized dummied .mad
            saidive (bool): True means compute SAID(s) for toplevel fields in .saids
                            False means do not compute SAIDs

        Assumes that when qb64 or qb64b or qb2 are provided that they have
            already been extracted from a stream and are self contained

        """
        self._leaves = {}
        self._partials = None
        super(Compactor, self).__init__(saidive=saidive, **kwa)


    @property
    def said(self):
        """primary said field value if any. None otherwise

        Returns:
              said (str|None): primary said field value if any. None otherwise
                               primary has same label as zeroth item in .saids
        """
        if self.saids and (self.saidive or self.leaves):
            l = list(self.saids.keys())[0]  # primary said is zeroth entry in said
            return self.mad.get(l, None)
        return None



    @property
    def leaves(self):
        """Getter for ._leaves

        Returns:
              leaves (dict): mapper at each leaf with computed said for leaf as
                             keyed by path to leaf, value is Mapper instance
        """
        return self._leaves


    @property
    def partials(self):
        """Getter for ._partials

        Returns:
              partials (dict): mapper of partially disclosable variants of with
                               fully computed saids for its leaves.
                               keyed by tuple of leaf paths,
                               value is Mapper instance.
        """
        return self._partials

    @property
    def iscompact(self):
        """iscompact property

        Returns:
              iscompact (bool|None): True means has leaf with path = '' i.e.
                                        has leaf at top level and has said
                                        but does not verify said
                                     False if at least one leaf but no leaf
                                        at top level
                                     None means no leaves so not compactive
                                        i.e. either has not been saidified yet
                                        or cannot be
        """
        if not self.leaves:
            return None

        if (self.said and self.leaves and '' in self.leaves):
            return True

        return False


    def trace(self, saidify=False):
        """Recursively trace paths to leaves in self.mad and populate .leaves.
        When saidify then compute saids of leaves and update .mad .raw etc

        Returns:
           paths (list[str]): of leaf path strs, one per leaf in depth first order


        Parameters:
            saidify (bool): True means compute and assign SAID at each leaf
                            False means do not assign SAID

        """
        paths = self._trace(mad=self.mad, paths=[], saidify=saidify)
        if saidify and not self.iscompact:  # top-level said needs to be computed
            raw, count = self._exhale(dummy=True) # first dummy serialization
            for label, code in self.saids.items():
                if label in self.mad:  # has saidive field
                    said = Diger(ser=raw, code=code).qb64
                    self.mad[label] = said

            raw, count = self._exhale()  # not dummied
            self._raw = raw
            self._count = count

        return paths


    def _trace(self, mad, paths=None, path='', *, saidify=False):
        """Recursively trace paths to leaves in mad and populate .leaves

        Returns:
           paths (list[str]): of leaf path strs, one per leaf in depth first order

        Parameters:
            mad (Mapping): nested (MApping Dict)
            paths(list|None): path strs of leafs in top down order
                               None means start at top
            path (str): current relative to top-level mad as dot '.' separated
            saidify (bool): True means compute and assign SAID at each leaf
                            False means do not assign SAID

        """
        paths = paths if paths is not None else []

        # leaf has said at top level but none of its nested mappings have a said.
        isleaf = False
        for l in self.saids:
            if l in mad:
                isleaf = True
                break

        for l, v in mad.items():
            if isinstance(v, Mapping):
                if l in self.saids:
                    raise InvalidValueError(f"Got Mapping not str for said field"
                                            f" label={l} value={v}")
                if self._hassaid(mad=v):
                    isleaf = False
                    paths = self._trace(mad=v, paths=paths, path=path + "." + l,
                                        saidify=saidify)

        if isleaf:
            paths.append(path)
            if saidify:
                # leafer Mapper makes deepcopy of input mad arg
                leafer = Mapper(mad=mad, makify=True,
                                saids=self.saids, saidive=True, kind=self.kind)
                for l in leafer.saids:  # assign computed saids to original mad
                    if l in mad:
                        mad[l] = leafer.mad[l]
            else:
                # leafer Mapper makes deepcopy of input mad arg
                leafer = Mapper(mad=mad, makify=True, kind=self.kind)

            self.leaves[path] = leafer

        return paths


    def _hassaid(self, mad):
        """Recursively decends mad to determine if mad or its decendents has a
        said field. This is used to determine if mad could be a leaf node.

        Returns:
            hassaid (bool): True means mad is saided,
                                i.e. has a (nested) SAID field.
                            False means mad is not saided

        Parameters:
            mad (Mapping):  MApping Dict that may or may not have a nested said

        """
        hassaid = False
        for l, v in mad.items():
            if l in self.saids:
                hassaid = True
                break
            elif isinstance(v, Mapping):  # field value is a Mapping
                hassaid = self._hassaid(mad=v)
                if hassaid:
                    break

        return hassaid


    def getTail(self, path, mad=None):
        """Get tail of path into mad. When mad is not provided uses .mad

        Returns:
           tail (dict|None):  tail of path into mad or None if not found

        Parameters:
           path (str): dot "." separated path. Top-level is "" so ".x" is one
                       level down.
           mad (dict|None): field map dict (MApping Dict). None uses default of
                            self.mad

        """
        tail = mad if mad is not None else self.mad
        parts = path.split(".")[1:]  # split and strip off top level part
        for part in parts:
            if part not in tail:
                return None
            tail = tail[part]  # descend on level down
        return tail


    def getMad(self, path, mad=None):
        """Get enclosing mad of tail of path into mad.
        When mad is not provided uses .mad

        Returns:
           tuple(emad, tail): where emad is enclosing mad of tail of path and
                                   tail is label at tail end of path into mad


        Parameters:
           path (str): dot "." separated path. Top-level is "" so ".x" is one
                       level down.
           mad (dict|None): field map dict (MApping Dict). None uses default of
                            self.mad

        """
        mad = mad if mad is not None else self.mad
        # split and then strip off bottom level part
        parts = path.split(".")  # split
        tail = parts[-1] if parts else None  # save tail
        parts = parts[:-1] # strip off tail
        if not parts:  # tail is top so there is no super mad for mad
            return (None, tail)

        parts = parts[1:]  # strip off top
        for part in parts:  # if parts empty then top-level is super mad
            if part not in mad:  # path part not in mad
                return (None, tail)
            mad = mad[part]  # descend on level down
        if tail not in mad:  # tail not in mad so path not compatible with  mad
            return (None, None)
        return (mad, tail)


    def compact(self):
        """Recursively apply most compact said algorithm to mad. Populates
        .leaves in the process

        recursively find leaves, saidify them by computing saids on leaves
        then populate .leaves with saidified leaves then compact the  mad by
        compacting the leaves.

        Repeat above on newly compacted mad until reach fully compacted mad.
        """
        while True:  # at least once so trace computes top-level said
            paths = self._trace(mad=self.mad, paths=[], path='', saidify=True)
            for path in paths:  # only check to compact new leaves
                leafer = self.leaves[path]  # get leafer for new leaf path
                mad, tail = self.getMad(path)
                if mad is not None and tail is not None:
                    mad[tail] = leafer.said  # assign primary said to compact

            if not paths or self.iscompact:  # either no leaves or compact
                break


    def expand(self, greedy=True):
        """Recursively build .partials from .leaves.

        Parameters:
            greedy (bool): True means expand partials using greed algorithm
                           on leaves. Essentially expand as many leaves as
                           possible on each pass by reversing leaf oder.
                           False means do not use expand by reversing leaf order
        """
        self._partials = {}  # reset partials dict
        paths = list(self.leaves.keys())
        if greedy:
            paths.reverse()

        used = []  # already expanded paths
        if "" in paths:  # create partial of fully compacted leaf
            path = ""
            leafer = self.leaves[path]
            pmad = deepcopy(leafer.mad)  # expand pmad with copy of leafer
            used.append(path)
            # don't compute top-level saids on partials
            partial = Compactor(mad=pmad, makify=True, saidive=False)
            # don't compute saids on leaves of partials
            index = partial.trace()  # default saidify == False
            partial.iscompact
            self.partials[tuple(index)] = partial

        pmad = deepcopy(self.mad)  # partial starts with copy of self.mad
        while unused := oset(paths) - oset(used):  # preserved ordering
            created = False
            for path in unused:
                lmad, leaf = self.getMad(path=path, mad=pmad)
                if lmad is not None and leaf is not None:
                    leafer = self.leaves[path]
                    lmad[leaf] = deepcopy(leafer.mad)  # expand pmad with copy of leafer
                    used.append(path)
                    created = True

            if created:  # create new partial
                # compactor makes copy pmad so can reuse pmad to start next partial
                # don't compute top-level saids on partials
                partial = Compactor(mad=pmad, makify=True, saidive=False)
                # don't compute saids on leaves of partials
                index = partial.trace()  # default saidify == False
                self.partials[tuple(index)] = partial


