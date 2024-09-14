# -*- encoding: utf-8 -*-
"""
keri.help.helping module

"""
import base64
import dataclasses
import datetime
import re
from collections import deque
from collections.abc import Iterable, Sequence, Mapping

import pysodium

# usage:
# x not in FALSEY
# x in FALSEY
# x not in TRUTHY
# x in TRUTHY
FALSEY = (False, 0, None, "?0", "no", "false", "False", "off")
TRUTHY = (True, 1, "?1", "yes" "true", "True", 'on')


# Utilities
def isign(i):
    """
    Integer sign function
    Returns:
        (int): 1 if i > 0, -1 if i < 0, 0 otherwise

    """
    return (1 if i > 0 else -1 if i < 0 else 0)


def sceil(r):
    """
    Symmetric ceiling function
    Returns:
       sceil (int): value that is symmetric ceiling of r away from zero

    Because int() provides a symmetric floor towards zero, just inc int(r) by:
     1 when r - int(r) >  0  (r positive)
    -1 when r - int(r) <  0  (r negative)
     0 when r - int(r) == 0  (r integral already)
    abs(r) > abs(int(r) or 0 when abs(r)
    """
    return (int(r) + isign(r - int(r)))


def dictify(val: dataclasses.dataclass):
    """
    Returns a serializable dict represention of a dataclass.  If the dataclass
    contains a `_ser` method, use it instead of `asdict`

    Parameters:
         val the dataclass instance to turn into a dict.
    """
    ser = getattr(val, "_ser", None)
    if callable(ser):
        return ser()

    return dataclasses.asdict(val)


def datify(cls, d):
    """
    Returns instance of dataclass cls converted from dict d. If the dataclass
    cls or any nested dataclasses contains a `_der` method, the use it instead
    of default fieldtypes conversion.

    Parameters:
    cls is dataclass class
    d is dict
    """
    try:
        der = getattr(cls, "_der", None)
        if callable(der):
            return der(d)

        fieldtypes = {f.name: f.type for f in dataclasses.fields(cls)}
        return cls(**{f: datify(fieldtypes[f], d[f]) for f in d})  # recursive
    except:
        return d  # Not a dataclass.


def klasify(sers: Iterable, klases: Iterable, args: Iterable = None):
    """
    Convert each qb64 serialization ser  in sers to instance of corresponding
    klas in klases modified by corresponding arg in args.
    Useful for converting iterable of CESR serializations to associated iterable
    of CESR subclass instances.
    When klas in klases is None then return corresponding ser without conversion

    Parameters:
        sers (Iterable): of serialized CESR subclass, str .qb64 or bytes .qb64b
        klases (Iterable): of class reference of CESR subclass
    """
    if not args:
        args = ("qb64",) * len(klases)

    return tuple(klas(**{arg: ser}) if arg is not None
                 else klas(ser) if klas is not None
    else ser
                 for ser, klas, arg in zip(sers, klases, args))



def nonStringIterable(obj):
    """
    Returns:
        (bool): True if obj is non-string iterable, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string iterables.

    Faster way that is less future proof
    return (hasattr(x, '__iter__') and not isinstance(x, (str, bytes)))
    """
    return (not isinstance(obj, (str, bytes)) and isinstance(obj, Iterable))


def nonStringSequence(obj):
    """
    Returns: True if obj is non-string sequence, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string sequences.

    """
    return (not isinstance(obj, (str, bytes)) and isinstance(obj, Sequence))


def extractElementValues(element, values):
    """
    Recusive depth first search that recursively extracts value(s) from element
    and appends to values list

    Assumes that extracted values are str

    Parameters:
        element is some element to extract values from
        values is list of values from elements that are not nonStringIterables

    IF element is mapping or sequence (nonStringIterable) then
        recusively  extractValues from the items of that element

    Else
        append element to values list

    return

    """
    if nonStringIterable(element):
        if isinstance(element, Mapping):  # dict like
            for k in element:
                extractElementValues(element=element[k], values=values)
        else:
            for k in element:
                extractElementValues(element=k, values=values)

    elif isinstance(element, str):
        values.append(element)

    else:
        raise ValueError("Unexpected element value = {}. Not a str.".format(element))

    return


def extractValues(ked, labels):
    """
    Returns list of depth first recursively extracted values from elements of
    key event dict ked whose labels are in labels list

    Parameters:
       ked is key event dict
       labels is list of element labels in ked from which to extract values
    """
    values = []
    for label in labels:
        extractElementValues(element=ked[label], values=values)

    return values


DTS_BASE_0 = "2021-01-01T00:00:00.000000+00:00"
DTS_BASE_1 = "2021-01-01T00:00:01.000000+00:00"
DTS_BASE_2 = "2021-01-01T00:01:00.000000+00:00"
DTS_BASE_3 = "2021-01-01T01:00:00.000000+00:00"


def nowUTC():
    """
    Returns timezone aware datetime of current UTC time
    Convenience function that allows monkeypatching in tests to mock time
    """
    return (datetime.datetime.now(datetime.timezone.utc))


def nowIso8601():
    """
    Returns time now in RFC-3339 profile of ISO 8601 format.
    use now(timezone.utc)

    YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM[:SS[.ffffff]]
    .strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    '2020-08-22T17:50:09.988921+00:00'
    Assumes TZ aware
    For nanosecond use instead attotime or datatime64 in pandas or numpy
    """
    return (nowUTC().isoformat(timespec='microseconds'))


def toIso8601(dt=None):
    """
    Returns str datetime dt in RFC-3339 profile of ISO 8601 format.
    Converts datetime object dt to ISO 8601 formt
    If dt is missing use now(timezone.utc)

    YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM[:SS[.ffffff]]
    .strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    '2020-08-22T17:50:09.988921+00:00'
    Assumes TZ aware
    For nanosecond use instead attotime or datatime64 in pandas or numpy
    """
    if dt is None:
        dt = nowUTC()  # make it aware

    return (dt.isoformat(timespec='microseconds'))  # force include microseconds


def fromIso8601(dts):
    """
    Returns datetime object from RFC-3339 profile of ISO 8601 format str or bytes.
    Converts dts from ISO 8601 format to datetime object

    YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM[:SS[.ffffff]]
    .strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    '2020-08-22T17:50:09.988921+00:00'
    Assumes TZ aware
    For nanosecond use instead attotime or datatime64 in pandas or numpy
    """
    if hasattr(dts, "decode"):
        dts = dts.decode("utf-8")
    return (datetime.datetime.fromisoformat(dts))



# Base64 utilities
BASE64_PAD = b'='

# Mappings between Base64 Encode Index and Decode Characters
#  B64ChrByIdx is dict where each key is a B64 index and each value is the B64 char
#  B64IdxByChr is dict where each key is a B64 char and each value is the B64 index
# Map Base64 index to char
B64ChrByIdx = dict((index, char) for index, char in enumerate([chr(x) for x in range(65, 91)]))
B64ChrByIdx.update([(index + 26, char) for index, char in enumerate([chr(x) for x in range(97, 123)])])
B64ChrByIdx.update([(index + 52, char) for index, char in enumerate([chr(x) for x in range(48, 58)])])
B64ChrByIdx[62] = '-'
B64ChrByIdx[63] = '_'
# Map char to Base64 index
B64IdxByChr = {char: index for index, char in B64ChrByIdx.items()}
# tuple
B64_CHARS = tuple(B64ChrByIdx.values())  # tuple of characters in Base64


B64REX = rb'^[0-9A-Za-z_-]*\Z'   # [A-Za-z0-9\-\_]  bytes
Reb64 = re.compile(B64REX)  # compile is faster
# Usage: if Reb64.match(bext): or if not Reb64.match(bext): bext is bytes


def intToB64(i, l=1):
    """
    Returns conversion of int i to Base64 str
    l is min number of b64 digits left padded with Base64 0 == "A" char
    """
    d = deque()  # deque of characters base64

    while l:
        d.appendleft(B64ChrByIdx[i % 64])
        i = i // 64
        if not i:
            break
    for j in range(l - len(d)):  # range(x)  x <= 0 means do not iterate
        d.appendleft("A")
    return ("".join(d))


def intToB64b(i, l=1):
    """
    Returns conversion of int i to Base64 bytes
    l is min number of b64 digits left padded with Base64 0 == "A" char
    """
    return (intToB64(i=i, l=l).encode("utf-8"))


def b64ToInt(s):
    """
    Returns conversion of Base64 str s or bytes to int
    """
    if not s:
        raise ValueError("Empty string, conversion undefined.")
    if hasattr(s, 'decode'):
        s = s.decode("utf-8")
    i = 0
    for e, c in enumerate(reversed(s)):
        i |= B64IdxByChr[c] << (e * 6)  # same as i += B64IdxByChr[c] * (64 ** e)
    return i



def codeB64ToB2(s):
    """
    Returns conversion (decode) of Base64 chars to Base2 bytes.
    Where the number of total bytes returned is equal to the minimun number of
    octets sufficient to hold the total converted concatenated sextets from s,
    with one sextet per each Base64 decoded char of s. Assumes no pad chars in s.
    Sextets are left aligned with pad bits in last (rightmost) byte.
    This is useful for decoding as bytes, code characters from the front of
    a Base64 encoded string of characters.
    """
    i = b64ToInt(s)
    i <<= 2 * (len(s) % 4)  # add 2 bits right zero padding for each sextet
    n = sceil(len(s) * 3 / 4)  # compute min number of ocetets to hold all sextets
    return (i.to_bytes(n, 'big'))


def codeB2ToB64(b, l):
    """
    Returns conversion (encode) of l Base2 sextets from front of b to Base64 chars.
    One char for each of l sextets from front (left) of b.
    This is useful for encoding as code characters, sextets from the front of
    a Base2 bytes (byte string). Must provide l because of ambiguity between l=3
    and l=4. Both require 3 bytes in b. Trailing pad bits are removed so
    returned sextets as characters are right aligned .
    """
    if hasattr(b, 'encode'):
        b = b.encode("utf-8")  # convert to bytes
    n = sceil(l * 3 / 4)  # number of bytes needed for l sextets
    if n > len(b):
        raise ValueError("Not enough bytes in {} to nab {} sextets.".format(b, l))
    i = int.from_bytes(b[:n], 'big')  # convert only first n bytes to int
    # check if prepad bits are zero
    tbs = 2 * (l % 4)  # trailing bit size in bits
    i >>= tbs  # right shift out trailing bits to make right aligned
    return (intToB64(i, l))  # return as B64


def nabSextets(b, l):
    """
    Return first l sextets from front (left) of b as bytes (byte string).
    Length of bytes returned is minimum sufficient to hold all l sextets.
    Last byte returned is right bit padded with zeros
    b is bytes or str
    """
    if hasattr(b, 'encode'):
        b = b.encode()  # convert to bytes
    n = sceil(l * 3 / 4)  # number of bytes needed for l sextets
    if n > len(b):
        raise ValueError("Not enough bytes in {} to nab {} sextets.".format(b, l))
    i = int.from_bytes(b[:n], 'big')
    p = 2 * (l % 4)
    i >>= p  # strip of last bits
    i <<= p  # pad with empty bits
    return (i.to_bytes(n, 'big'))


def keyToKey64u(key):
    """
    Returns 64u
    Convert and return bytes key to unicode base64 url-file safe version
    """
    return base64.urlsafe_b64encode(key).decode("utf-8")


def key64uToKey(key64u):
    """
    Returns bytes
    Convert and return unicode base64 url-file safe key64u to bytes key
    """
    return base64.urlsafe_b64decode(key64u.encode("utf-8"))


def verifyEd25519(sig, msg, vk):
    """
    Returns True if signature sig of message msg is verified with
    verification key vk Otherwise False
    All of sig, msg, vk are bytes
    """
    try:
        result = pysodium.crypto_sign_verify_detached(sig, msg, vk)
    except Exception as ex:
        return False
    return (True if result else False)


def verify64uEd25519(signature, message, verkey):
    """
    Returns True if signature is valid for message with respect to verification
    key verkey

    signature and verkey are encoded as unicode base64 url-file strings
    and message is unicode string as would be the case for a json object

    """
    sig = key64uToKey(signature)
    vk = key64uToKey(verkey)
    msg = message.encode("utf-8")
    return (verifyEd25519(sig, msg, vk))


