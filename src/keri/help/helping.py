# -*- encoding: utf-8 -*-
"""
keri.help.helping module

"""
import base64
import dataclasses
import datetime
from collections.abc import Iterable, Sequence, Mapping

import pysodium
from multidict import MultiDict  # base class for mdict defined below
from orderedset import OrderedSet as oset


# Utilities
def isign(i):
    """
    Returns 1 if i > 0, -1 if i < 0, 0 otherwise
    Integer sign function
    """
    return (1 if i > 0 else -1 if i < 0 else 0)


def sceil(r):
    """
    Returns integer value that is symmetric ceiling of r away from zero
    Symmetric ceiling function
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


def nonStringIterable(obj):
    """
    Returns True if obj is non-string iterable, False otherwise

    Future proof way that is compatible with both Python3 and Python2 to check
    for non string iterables.

    Faster way that is less future proof
    return (hasattr(x, '__iter__') and not isinstance(x, (str, bytes)))
    """
    return (not isinstance(obj, (str, bytes)) and isinstance(obj, Iterable))


def nonStringSequence(obj):
    """
    Returns True if obj is non-string sequence, False otherwise

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
    key event dict ked whose flabels are in lables list

    Parameters:
       ked is key event dict
       labels is list of element labels in ked from which to extract values
    """
    values = []
    for label in labels:
        extractElementValues(element=ked[label], values=values)

    return values

def nowUTC():
    """
    Returns timezone aware datetime of current UTC time
    Convenience function that allows monkeypatching in tests to mock time
    """
    return (datetime.datetime.now(datetime.timezone.utc))


def nowIso8601():
    """
    Returns time now in ISO 8601 format
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
    Returns str datetime dt in ISO 8601 format
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
    Returns datetime object from ISO 8601 formated str or bytes
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
