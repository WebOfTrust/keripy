# -*- encoding: utf-8 -*-
"""
keri.help.helping module

"""
import os
import shutil
import tempfile
import base64

import pysodium

from multidict import MultiDict  # base class for mdict defined below
from orderedset import OrderedSet as oset


def cleanupBaseDir(baseDirPath):
    """
    Remove baseDirPath
    """
    if os.path.exists(baseDirPath):
        shutil.rmtree(baseDirPath)


def setupTmpBaseDir(baseDirPath=""):
    """
    Create temporary directory
    """
    if not baseDirPath: # create temp directory at /tmp/keri...test
        baseDirPath = tempfile.mkdtemp(prefix="keri",  suffix="test", dir="/tmp")
    baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
    return baseDirPath


def cleanupTmpBaseDir(baseDirPath):
    """
    Remove temporary root of baseDirPath
    Ascend tree to find temporary root directory
    """
    if os.path.exists(baseDirPath):
        while baseDirPath.startswith("/tmp/keri"):
            if baseDirPath.endswith("test"):
                shutil.rmtree(baseDirPath)
                break
            baseDirPath = os.path.dirname(baseDirPath)


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

class mdict(MultiDict):
    """
    Multiple valued dictionary. Insertion order of keys preserved.
    Associated with each key is a valuelist i.e. a list of values for that key.
    Extends  MultiDict
    https://multidict.readthedocs.io/en/stable/

    In MultiDict:
        .add(key,value)  appends value to the valuelist at key

        m["key"] = value replaces the valuelist at key with [value]

        m["key] treturns the first added element of the valuelist at key

    MultiDict methods access values in FIFO order
    mdict adds method to access values in LIFO order

    Extended methods in mdict but not in MultiDict are:
       nabone(key [,default])  get last value at key else default or KeyError
       nab(key [,default])  get last value at key else default or None
       naball(key [,default]) get all values inverse order else default or KeyError

    """

    def nabone(self, key, *pa, **kwa):
        """
        Usage:
            .nabone(key [, default])

        returns last value at key if key in dict else default
        raises KeyError if key not in dict and default not provided.
        """
        try:
            return self.getall(key)[-1]
        except KeyError:
            if not pa and "default" not in kwa:
                raise
            elif pa:
                return pa[0]
            else:
                return kwa["default"]


    def nab(self, key, *pa, **kwa):
        """
        Usage:
            .nab(key [, default])

        returns last value at key if key in dict else default
        returns None if key not in dict and default not provided.
        """
        try:
            return self.getall(key)[-1]
        except KeyError:
            if not pa and "default" not in kwa:
                return None
            elif pa:
                return pa[0]
            else:
                return kwa["default"]

    def naball(self, key, *pa, **kwa):
        """
        Usage:
            .nabone(key [, default])

        returns list of value at key if key in dict else default
        raises KeyError if key not in dict and default not provided.
        """
        try:
            # getall returns copy of list so safe to reverse
            return list(reversed(self.getall(key)))
        except KeyError:
            if not pa and "default" not in kwa:
                raise
            elif pa:
                return pa[0]
            else:
                return kwa["default"]


    def firsts(self):
        """
        Returns list of (key, value) pair where each value is first value at key
        No duplicate keys

        This is useful for forked lists of values with same keys
        """
        keys = oset(self.keys())  # get rid of duplicates provided by .keys()
        return [(k, self.getone(k)) for k in keys]


    def lasts(self):
        """
        Returns list of (key, value) pairs where each value is last value at key

        This is useful fo forked lists  of values with same keys
        """
        keys = oset(self.keys())  # get rid of duplicates provided by .keys()
        return [(k, self.nabone(k)) for k in keys]
